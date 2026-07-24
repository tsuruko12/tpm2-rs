use tracing::error;

use crate::{
    backend::BackendContext, 
    db::MetadataStore, 
    error::{Error, Result}, 
    types::{Authorization, AuthorizationCache},
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

    pub fn provision(&mut self) -> Result<()> {
        self.store.init()?;
        
        let key_meta = self.backend.create_internal_keys(&Authorization::default())?;
        self.store.add_internal_key_meta(&key_meta)?;

        Ok(())
    }

    pub fn get_random(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        buf.try_reserve_exact(num_bytes)
            .map_err(|_| Error::resource_exhausted("failed to allocate random output buffer"))?;

        while buf.len() < num_bytes {
            let remaining = num_bytes - buf.len();
            let chunk_size = remaining.min(u16::MAX as usize) as u16;

            let chunk = self.backend.get_random(chunk_size)?;

            if chunk.is_empty() {
                error!("TPM returned no random bytes");
                return Err(Error::InvalidData);
            }

            if chunk.len() > chunk_size as usize {
                error!("TPM returned more random bytes than requested");
                return Err(Error::InvalidData);
            }

            buf.extend_from_slice(&chunk);
        }

        buf.truncate(num_bytes);

        Ok(buf)
    }
}
