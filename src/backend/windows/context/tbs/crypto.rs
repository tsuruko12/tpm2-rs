use aes::{
    Aes128,
    cipher::{Block, BlockEncrypt},
};
use hmac::{Hmac, Mac, digest::Output};
use sha2::{Digest, Sha256};
use tracing::debug;
use zeroize::Zeroizing;

use super::super::TpmsAuthResponse;
use crate::{
    backend::windows::TpmRc, 
    error::{Error, Result}, 
    types::tpm::{Tpm2bAuth, TpmCc, TpmaSession},
};

const AES_BLOCK_SIZE: usize = 16;

type HmacSha256 = Hmac<Sha256>;

pub(super) struct CpHashData<'a> {
    pub(super) command_code: TpmCc,
    pub(super) handle_names: &'a [Vec<u8>],
    pub(super) parameters: &'a [u8],
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

    let bytes = mac.finalize().into_bytes();

    Ok(bytes
        .as_slice()
        .try_into()
        .expect("HMAC size must not exceed Tpm2bAuth::MAX_BYTES"))
}

pub(super) fn verify_response_hmac(
    session_value: &[u8],
    command_code: TpmCc,
    parameters: &[u8],
    nonce_caller: &[u8],
    auth_response: &TpmsAuthResponse,
) -> Result<()> {
    // data := rpHash || nonceTPM || nonceCaller || sessionAttributes
    let rp_hash = compute_rp_hash(command_code, parameters);

    let mut mac = HmacSha256::new_from_slice(session_value)
        .map_err(|e| Error::invalid_state(format!("failed to initialize HMAC: {e:?}")))?;
    mac.update(&rp_hash);
    mac.update(auth_response.nonce.as_bytes());
    mac.update(nonce_caller);
    mac.update(&[auth_response.session_attributes.bits()]);

    mac.verify_slice(auth_response.hmac.as_bytes())
        .map_err(|e| {
            debug!(err = ?e, "response HMAC verification failed");
            Error::InvalidData
        })
}

pub(super) fn encrypt_parameter(
    session_value: &[u8],
    nonce_newer: &[u8],
    nonce_older: &[u8],
    parameter: &mut [u8],
) -> Result<()> {
    // nonce_newer: nonceCaller, nonce_older: nonceTPM
    let key_and_iv = derive_cfb_key_and_iv(session_value, nonce_newer, nonce_older)?;
    let (key, iv) = key_and_iv.split_at(AES_BLOCK_SIZE);

    aes_128_cfb_encrypt(key, iv, parameter)
}

pub(super) fn decrypt_parameter(
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

fn compute_rp_hash(command_code: TpmCc, parameters: &[u8]) -> Output<Sha256> {
    // rpHash := SHA-256(responseCode || commandCode || parameters)
    let mut hash = Sha256::new();
    hash.update(TpmRc::SUCCESS.value().to_be_bytes());
    hash.update(command_code.value().to_be_bytes());
    hash.update(parameters);

    hash.finalize()
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
    hasher.update(cp_hash_data.command_code.value().to_be_bytes());
    for name in cp_hash_data.handle_names {
        hasher.update(name);
    }
    hasher.update(cp_hash_data.parameters);

    hasher.finalize()
}
