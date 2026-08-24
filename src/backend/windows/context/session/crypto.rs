use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::super::super::types::Tpm2bNonce;
use crate::{Error, Result, backend::windows::types::{Tpm2bEncryptedSecret, TpmuEncryptedSecret}};

const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 32;
const BITS: u32 = 256;
type HmacSha256 = Hmac<Sha256>;

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
    let mut nonce = vec![0u8; NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(Error::random_generation)?;

    Ok(nonce
        .try_into()
        .expect("caller nonce size must not exceed Tpm2bNonce::MAX_BYTES"))
}

pub(super) fn generate_encrypted_salt(
    public_key: &RsaPublicKey,
) -> Result<(Tpm2bEncryptedSecret, Zeroizing<[u8; 32]>)> {
    let mut salt = Zeroizing::new([0u8; SALT_SIZE]);
    OsRng
        .try_fill_bytes(&mut *salt)
        .map_err(Error::random_generation)?;

    let padding = Oaep::new_with_label::<Sha256, _>("SECRET\0");
    let encrypted_salt = public_key
        .encrypt(&mut OsRng, padding, salt.as_ref())
        .map_err(Error::encryption)?;

    Ok((
        Tpm2bEncryptedSecret::from(TpmuEncryptedSecret::rsa(encrypted_salt)
            .expect("RSA encrypted salt must match the RSA modulus size")), 
        salt,
    ))
}
