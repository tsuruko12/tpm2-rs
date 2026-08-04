use tracing::{debug, error};
#[cfg(target_os = "linux")]
use tss_esapi::handles::{KeyHandle, PersistentTpmHandle};

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

        let owner_authorization = Authorization::default();

        let key_meta = self
            .backend
            .create_internal_keys(&owner_authorization)?;

        match self.store.add_internal_key_meta(&key_meta) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.backend.evict_persistent_handles(&owner_authorization, &key_meta, None);
                Err(e)
            }
        }
    }

    pub fn get_random(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        let sesssion_salt_key = self.load_session_salt_key()?;

        let mut buf = Vec::new();

        buf.try_reserve_exact(num_bytes)
            .map_err(|_| Error::resource_exhausted("failed to allocate random output buffer"))?;

        while buf.len() < num_bytes {
            let remaining = num_bytes - buf.len();
            let chunk_size = remaining.min(u16::MAX as usize) as u16;

            let chunk = self.backend.get_random(chunk_size, sesssion_salt_key)?;

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

    #[cfg(target_os = "linux")]
    fn load_session_salt_key(&mut self) -> Result<KeyHandle> {
        let key_meta = self.store.load_session_salt_key()?;

        let persistent_handle = PersistentTpmHandle::new(key_meta.handle)
            .map_err(|_| {
                debug!(
                    handle = format_args!("{:#010x}", key_meta.handle), 
                    "stored TPM persistent handle is invalid"
                );
                Error::corrupted_store()
            })?;
        let loaded_handle = self.backend.load_persistent_handle(persistent_handle)?;

        self.backend.validate_object_name(loaded_handle, &key_meta.object_name)?;

        Ok(loaded_handle.into())
    }

    #[cfg(target_os = "windows")]
    fn load_session_salt_key(&mut self) -> Result<TpmiDhObject> {
        let key_meta = self.store.load_session_salt_key()?;

    let handle = TpmiDhObject::try_from(key_meta.handle)
        .ok()
        .filter(|handle| handle.is_persistent())
        .ok_or_else(|| {
            debug!(
                handle = format_args!("{:#010x}", key_meta.handle),
                "stored TPM persistent handle is invalid"
            );
            Error::corrupted_store()
        })?;

        self.backend
            .validate_object_name(handle, &key_meta.object_name)?;

        Ok(handle)
    }
}
