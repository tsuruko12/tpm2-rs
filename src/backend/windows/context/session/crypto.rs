use aes::{
    Aes128,
    cipher::{Block, BlockEncrypt},
};
use hmac::{Hmac, Mac, digest::Output};
use rand::{RngCore, rngs::OsRng};
use rsa::{Oaep, RsaPublicKey};
use sha2::{Digest, Sha256};
use tracing::error;
use zeroize::Zeroizing;

use crate::{Error, Result, types::{TpmCc, Tpm2bAuth}};
use super::{
    CpHashData, PreparedSession, ResponseAuthContext,
    codec::tpm2b_payload_mut,
    commands::TpmsAuthResponse,
    types::{Tpm2bNonce, TpmRc, TpmaSession},
};

const DIGEST_SIZE: usize = 32;
const BITS: u32 = 256;
const AES_BLOCK_SIZE: usize = 16;

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn encrypt_command_parameter(
    sessions: &[PreparedSession],
    parameter: &mut [u8],
) -> Result<()> {
    for session in sessions {
        if let PreparedSession::Hmac {
            auth_command,
            session_value,
            nonce_tpm,
        } = session
        {
            if auth_command
                .session_attributes()
                .contains(TpmaSession::DECRYPT)
            {
                return encrypt_parameter(
                    session_value,
                    auth_command.nonce().as_bytes(),
                    nonce_tpm.as_bytes(),
                    parameter,
                );
            }
        }
    }

    Err(Error::invalid_state(
        "expected an HMAC session for parameter encryption",
    ))
}

pub(crate) fn decrypt_response_parameter(
    command_code: TpmCc,
    parameters: &mut [u8],
    auth_contexts: &[ResponseAuthContext<'_>],
    auth_responses: &[TpmsAuthResponse],
) -> Result<()> {
    ensure_matching_auth_count(auth_contexts, auth_responses)?;

    let mut response_decrypt_context = None;

    for (auth_context, auth_response) in auth_contexts.iter().zip(auth_responses) {
        let ResponseAuthContext::Hmac(context) = auth_context else {
            continue;
        };

        verify_response_hmac(
            context.session_value,
            command_code,
            parameters,
            context.nonce_caller.as_bytes(),
            auth_response,
        )?;

        if context.command_attrs.contains(TpmaSession::ENCRYPT) {
            if response_decrypt_context
                .replace((context, auth_response.nonce()))
                .is_some()
            {
                return Err(Error::invalid_state(
                    "multiple sessions specify response parameter decryption",
                ));
            }
        }
    }

    let (hmac_context, nonce_tpm) = response_decrypt_context.ok_or_else(|| {
        error!("command session attribute mismatch");
        Error::InvalidData
    })?;
    let parameter = tpm2b_payload_mut(parameters)?;

    decrypt_parameter(
        hmac_context.session_value,
        nonce_tpm.as_bytes(),
        hmac_context.nonce_caller.as_bytes(),
        parameter,
    )
}

pub(super) fn derive_session_key(
    salt: &[u8],
    nonce_tpm: &[u8],
    nonce_caller: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    // sessionKey ∶= KDFa(sessionAlg, (authValue ∥ salt), "ATH", nonceTPM, nonceCaller, bits)
    let mut mac = HmacSha256::new_from_slice(salt)
        .map_err(|e| Error::invalid_state(format!("failed to initialize KDFa HMAC: {e:?}")))?;

    mac.update(&1u32.to_be_bytes());
    mac.update(b"ATH\0");
    mac.update(nonce_tpm);
    mac.update(nonce_caller);
    mac.update(&BITS.to_be_bytes());

    let bytes = mac.finalize().into_bytes();

    Ok(Zeroizing::new(bytes.to_vec()))
}

pub(super) fn generate_caller_nonce() -> Result<Tpm2bNonce> {
    let mut nonce = vec![0u8; DIGEST_SIZE];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(Error::random_generation)?;

    Ok(nonce.into())
}

pub(super) fn generate_encrypted_salt(
    public_key: &RsaPublicKey,
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let mut salt = Zeroizing::new([0u8; 32]); // nameAlg is fixed to SHA-256
    OsRng
        .try_fill_bytes(&mut *salt)
        .map_err(Error::random_generation)?;

    let padding = Oaep::new_with_label::<Sha256, _>("SECRET");

    let encrypted_salt = public_key
        .encrypt(&mut OsRng, padding, salt.as_ref())
        .map_err(Error::encryption)?;

    Ok((encrypted_salt, salt))
}

fn ensure_matching_auth_count(
    auth_contexts: &[ResponseAuthContext<'_>],
    auth_responses: &[TpmsAuthResponse],
) -> Result<()> {
    if auth_contexts.len() != auth_responses.len() {
        error!(
            expected = auth_contexts.len(),
            returned = auth_responses.len(),
            "response authorization count mismatch"
        );
        return Err(Error::InvalidData);
    }

    Ok(())
}

pub(super) fn compute_hmac(
    session_value: &[u8],
    cp_hash_data: &CpHashData<'_>,
    nonce_caller: &[u8],
    nonce_tpm: &[u8],
    attributes: TpmaSession,
) -> Result<Tpm2bAuth> {
    // data := cpHash || nonceCaller || nonceTPM || sessionAttributes
    let cp_hash = compute_cp_hash(cp_hash_data);

    let mut mac = HmacSha256::new_from_slice(session_value).map_err(|e| {
        Error::invalid_state(format!("failed to initialize authorization HMAC: {e:?}"))
    })?;

    mac.update(&cp_hash);
    mac.update(nonce_caller);
    mac.update(nonce_tpm);
    mac.update(&[attributes.bits()]);

    Ok(Tpm2bAuth::from(mac.finalize().into_bytes().to_vec()))
}

pub(crate) fn verify_response_hmac(
    session_value: &[u8],
    command_code: TpmCc,
    parameters: &[u8],
    nonce_caller: &[u8],
    auth_response: &TpmsAuthResponse,
) -> Result<()> {
    // data := rpHash || nonceTPM || nonceCaller || sessionAttributes
    let (nonce_tpm, session_attrs, response_hmac) = auth_response.as_parts();
    let rp_hash = compute_rp_hash(command_code, parameters);

    let mut mac = HmacSha256::new_from_slice(session_value)
        .map_err(|e| Error::invalid_state(format!("failed to initialize HMAC: {e:?}")))?;

    mac.update(&rp_hash);
    mac.update(nonce_tpm.as_bytes());
    mac.update(nonce_caller);
    mac.update(&[session_attrs.bits()]);

    mac.verify_slice(response_hmac.as_bytes()).map_err(|e| {
        error!(err = ?e, "response HMAC verification failed");
        Error::InvalidData
    })
}

fn compute_rp_hash(command_code: TpmCc, parameters: &[u8]) -> Output<Sha256> {
    // rpHash := SHA-256(responseCode || commandCode || parameters)
    let mut hash = Sha256::new();

    hash.update(TpmRc::SUCCESS.raw().to_be_bytes());
    hash.update(command_code.raw().to_be_bytes());
    hash.update(parameters);

    hash.finalize()
}

fn encrypt_parameter(
    session_value: &[u8],
    nonce_newer: &[u8],
    nonce_older: &[u8],
    parameter: &mut [u8],
) -> Result<()> {
    // nonce_newer: nonceCaller; nonce_older: nonceTPM
    let key_and_iv = derive_cfb_key_and_iv(session_value, nonce_newer, nonce_older)?;
    let (key, iv) = key_and_iv.split_at(AES_BLOCK_SIZE);

    aes_128_cfb_encrypt(key, iv, parameter)
}

fn decrypt_parameter(
    session_value: &[u8],
    nonce_newer: &[u8],
    nonce_older: &[u8],
    parameter: &mut [u8],
) -> Result<()> {
    // nonce_newer: nonceTPM; nonce_older: nonceCaller
    let key_and_iv = derive_cfb_key_and_iv(session_value, nonce_newer, nonce_older)?;
    let (key, iv) = key_and_iv.split_at(AES_BLOCK_SIZE);

    aes_128_cfb_decrypt(key, iv, parameter)
}

fn derive_cfb_key_and_iv(
    session_value: &[u8],
    nonce_newer: &[u8],
    nonce_older: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    // KDFa(hashAlg, sessionValue, "CFB", nonceNewer, nonceOlder, bits)
    let mut mac = HmacSha256::new_from_slice(session_value)
        .map_err(|e| Error::invalid_state(format!("failed to initialize KDFa HMAC: {e:?}")))?;

    mac.update(&1u32.to_be_bytes());
    mac.update(b"CFB\0");
    mac.update(nonce_newer);
    mac.update(nonce_older);
    mac.update(&256u32.to_be_bytes());

    Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
}

fn aes_128_cfb_encrypt(key: &[u8], iv: &[u8], parameter: &mut [u8]) -> Result<()> {
    let (cipher, mut feedback) = init_aes_128_cfb(key, iv)?;

    for block in parameter.chunks_mut(AES_BLOCK_SIZE) {
        let mut key_stream = feedback.clone();
        cipher.encrypt_block(&mut key_stream);

        for (byte, key_stream_byte) in block.iter_mut().zip(key_stream.iter()) {
            *byte ^= key_stream_byte;
        }

        feedback[..block.len()].copy_from_slice(block);
    }

    Ok(())
}

fn aes_128_cfb_decrypt(key: &[u8], iv: &[u8], parameter: &mut [u8]) -> Result<()> {
    let (cipher, mut feedback) = init_aes_128_cfb(key, iv)?;

    for block in parameter.chunks_mut(AES_BLOCK_SIZE) {
        let mut ciphertext = Block::<Aes128>::default();
        ciphertext[..block.len()].copy_from_slice(block);

        let mut key_stream = feedback.clone();
        cipher.encrypt_block(&mut key_stream);

        for (byte, key_stream_byte) in block.iter_mut().zip(key_stream.iter()) {
            *byte ^= key_stream_byte;
        }

        feedback[..block.len()].copy_from_slice(&ciphertext[..block.len()]);
    }

    Ok(())
}

fn init_aes_128_cfb(key: &[u8], iv: &[u8]) -> Result<(Aes128, Block<Aes128>)> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(Error::invalid_state("AES-CFB IV must be 16 bytes"));
    }

    let cipher = <Aes128 as aes::cipher::KeyInit>::new_from_slice(key)
        .map_err(|_| Error::invalid_state("AES-CFB key must be 16 bytes"))?;
    let mut feedback = Block::<Aes128>::default();
    feedback.copy_from_slice(iv);

    Ok((cipher, feedback))
}

fn compute_cp_hash(cp_hash_data: &CpHashData<'_>) -> Output<Sha256> {
    // cpHash := SHA-256(commandCode || Name1 || Name2 || Name3 || parameters)
    let mut hasher = Sha256::new();

    hasher.update(cp_hash_data.command_code.raw().to_be_bytes());

    for &name in cp_hash_data.handle_names {
        hasher.update(name);
    }

    hasher.update(cp_hash_data.parameters);

    hasher.finalize()
}
