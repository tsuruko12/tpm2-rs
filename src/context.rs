use crate::{
    backend::BackendContext,
    db::MetadataStore,
    error::{Error, Result},
    types::AuthorizationCache,
};

pub struct Context {
    backend: BackendContext,
    store: MetadataStore,
    authorization_cache: AuthorizationCache,
}

impl Context {
    pub fn connect() -> Result<Self> {
        Ok(Self {
            backend: BackendContext::create_context()?,
            store: MetadataStore::new()?,
            authorization_cache: AuthorizationCache::default(),
        })
    }

    #[cfg(target_os = "linux")]
    pub fn connect_from_env() -> Result<Self> {
        Ok(Self {
            backend: BackendContext::create_context_from_tcti_env()?,
            store: MetadataStore::new()?,
            authorization_cache: AuthorizationCache::default(),
        })
    }

    pub fn get_random(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        buf.try_reserve_exact(num_bytes)
            .map_err(|_| Error::resource_exhausted("failed to allocate random output buffer"))?;

        while buf.len() < num_bytes {
            let remaining = num_bytes - buf.len();
            let chunk_size = remaining.min(u16::MAX as usize) as u16;

            let chunk = self.backend.get_random_once(chunk_size)?;

            if chunk.is_empty() {
                return Err(Error::Internal("TPM returned no random bytes"));
            }

            if chunk.len() > chunk_size as usize {
                return Err(Error::Internal(
                    "TPM returned more random bytes than requested",
                ));
            }

            buf.extend_from_slice(&chunk);
        }

        buf.truncate(num_bytes);

        Ok(buf)
    }
}
