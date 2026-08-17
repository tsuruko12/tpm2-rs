#[cfg(all(feature = "openssl", feature = "rustcrypto"))]
compile_error!("only one symmetric crypto backend can be enabled: `openssl` or `rustcrypto`");

#[cfg(not(any(feature = "openssl", feature = "rustcrypto")))]
compile_error!("one symmetric crypto backend must be enabled: `openssl` or `rustcrypto`");

mod backend;
mod cache;
mod context;
mod db;
pub mod error;
mod macros;
mod types;

use crate::types::Tpm2bPublicKeyRsa;
pub use crate::{
    context::Context,
    error::{Error, Result},
    types::{algorithm, hierarchy, policy, public},
};

use rand::{RngCore, rngs::OsRng};

use types::SymmetricKeyBits;

fn generate_sym_key(key_bits: SymmetricKeyBits) -> Result<Tpm2bPublicKeyRsa> {
    let key_len = match key_bits {
        SymmetricKeyBits::Bits128 => 16,
        SymmetricKeyBits::Bits256 => 32,
    };

    let mut key = vec![0u8; key_len];
    OsRng
        .try_fill_bytes(key.as_mut_slice())
        .map_err(Error::random_generation)?;

    Ok(key
        .try_into()
        .expect("generated symmetric key must fit within Tpm2bPublicKeyRsa::MAX_BYTES")
    )
}

fn generate_key_id() -> Result<String> {
    Ok(hex::encode(generate_random_bytes(16)?))
}

fn generate_random_bytes(length: usize) -> Result<Vec<u8>> {
    let mut key = vec![0u8; length];
    OsRng
        .try_fill_bytes(&mut key)
        .map_err(Error::random_generation)?;

    Ok(key)
}