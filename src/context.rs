mod authorization;
mod key;
mod provision;
mod random;

use crate::{
    backend::BackendContext,
    cache::Cache,
    db::MetadataStore,
    error::Result,
    types::{BackendObjectHandle, LoadedHandle},
};

/// Provides access to a TPM and its managed key store.
pub struct Context {
    backend: BackendContext,
    store: MetadataStore,
    cache: Cache,
}

impl Context {
    /// Creates a context connected to the system TPM.
    ///
    /// On Linux, this method attempts to connect to `/dev/tpmrm0` first,
    /// then falls back to `/dev/tpm0`.
    /// On Windows, it connects through TPM Base Services (TBS).
    pub fn connect() -> Result<Self> {
        Ok(Self {
            backend: BackendContext::create_context()?,
            store: MetadataStore::new()?,
            cache: Cache::default(),
        })
    }

    /// Creates a context using a TCTI configuration from the environment.
    ///
    /// This method is available only on Linux.
    ///
    /// The following variables are checked in order:
    ///
    /// - `TPM2TOOLS_TCTI`
    /// - `TCTI`
    /// - `TEST_TCTI`
    #[cfg(target_os = "linux")]
    pub fn connect_from_env() -> Result<Self> {
        Ok(Self {
            backend: BackendContext::create_context_from_tcti_env()?,
            store: MetadataStore::new()?,
            cache: Cache::default(),
        })
    }

    fn load_internal_srk(&mut self) -> Result<LoadedHandle> {
        let key_meta = self.store.load_internal_srk()?;
        self.backend.resolve_internal_key(key_meta)
    }

    fn load_session_salt_handle(&mut self) -> Result<BackendObjectHandle> {
        let key_meta = self.store.load_session_salt_key()?;
        self.backend
            .resolve_internal_key(key_meta)
            .map(|loaded| loaded.handle.inner())
    }

    fn load_shared_wrapping_handle(&mut self) -> Result<LoadedHandle> {
        let key_meta = self.store.load_shared_wrapping_key()?;
        self.backend.resolve_internal_key(key_meta)
    }
}
