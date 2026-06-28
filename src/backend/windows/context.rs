mod random;
mod tbs;

use std::{ffi::c_void, u16};

use crate::{data::MetadataStore, error::{Error, Result}, types::AuthorizationCache};

type ContextHandle = *mut c_void;

pub struct Context {
    handle: ContextHandle,
    store: MetadataStore,
    authorization_cache: AuthorizationCache,
}

impl Context {
    pub fn connect() -> Result<Self> {
        Self::create_context()
    }

    pub fn get_random(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        if num_bytes > u16::MAX as usize {
            return Err(Error::invalid_param(
                "random byte count exceeds the maximum supported size"
            ));
        }

        let mut buf = Vec::with_capacity(num_bytes);
        
        while buf.len() < num_bytes {
            let remaining = num_bytes - buf.len();

            let request_size = remaining.min(u16::MAX as usize);
            let chunk = self.get_random_once(request_size)?;

            if chunk.is_empty() {
                return Err(Error::failure("TPM returned no random bytes"));
            }

            buf.extend_from_slice(&chunk);
        }

        buf.truncate(num_bytes);

        Ok(buf)
    }
}

#[cfg(test)]
pub(crate) fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
}
