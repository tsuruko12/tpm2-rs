#[cfg(all(feature = "openssl", feature = "rustcrypto"))]
compile_error!("only one symmetric crypto backend can be enabled: `openssl` or `rustcrypto`");

#[cfg(not(any(feature = "openssl", feature = "rustcrypto")))]
compile_error!("one symmetric crypto backend must be enabled: `openssl` or `rustcrypto`");

mod backend;
mod context;
mod db;
pub mod error;
mod types;

pub use crate::{
    context::Context,
    error::{Error, Result},
    types::SymmetricKeyBits,
};
use zeroize::Zeroizing;

const SYMMETRIC_BLOCK_SIZE: usize = 16;

fn generate_random_bytes(length: usize) -> Result<Vec<u8>> {
    let mut key = vec![0u8; length];
    getrandom::fill(&mut key).map_err(|_| os_rng_err())?;

    Ok(key)
}

fn generate_sym_key(key_bits: SymmetricKeyBits) -> Result<Zeroizing<Vec<u8>>> {
    let key_len = match key_bits {
        SymmetricKeyBits::Bits128 => 16,
        SymmetricKeyBits::Bits256 => 32,
    };

    let mut key = Zeroizing::new(vec![0u8; key_len]);
    getrandom::fill(key.as_mut_slice()).map_err(|_| os_rng_err())?;

    Ok(key)
}

fn os_rng_err() -> Error {
    Error::Internal("failed to generate random bytes")
}
