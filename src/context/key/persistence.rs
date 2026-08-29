use tracing::debug;

use crate::{Error, Result, types::{Key, KeyId, LoadedObjectHandle, tpm::TpmiDhPersistent}};
use super::super::Context;

impl Context {
    /// Make a stored TPM key persistent.
    ///
    /// `persistent_handle` selects the TPM persistent handle. When it is `None`,
    /// an available persistent handle is selected automatically. On success, 
    /// the stored key metadata is updated to reference the persistent TPM object.
    ///
    /// # Errors
    ///
    /// If `key` is temporary, already persistent, or cannot be
    /// loaded, returns [`Error::InvalidKey`]. 
    /// If the specified handle is invalid, returns [`Error::InvalidParameter`] .
    pub fn persist(&mut self, key: &Key, persistent_handle: Option<u32>) -> Result<()> {
        let key_id = key.id();

        if matches!(key_id, KeyId::Temporary(_)) {
            return Err(Error::invalid_key("temporary key cannot be persisted"));
        }

        let owner_authorization = self.owner_authorization()?;
        let (persistent_handle, search_end) = match persistent_handle {
            Some(handle) => {
                let handle = TpmiDhPersistent::try_from(handle)
                    .ok()
                    .filter(|handle| handle.value() <= TpmiDhPersistent::STORAGE_AVAILABLE_LAST.value())
                    .ok_or_else(|| {
                        Error::invalid_param(
                            "persistent handle must be in the range 0x8100_0000 to 0x81FF_FFFF",
                        )
                    })?;
                    
                (handle, None)
            },
            None => {
                let start_value = TpmiDhPersistent::STORAGE_AVAILABLE_FIRST.value() + 2;
                (
                    start_value
                        .try_into()
                        .expect("handle must be in the persistent range"),
                    Some(TpmiDhPersistent::STORAGE_AVAILABLE_LAST),
                )
            }
        };

        let loaded = self.load_key(key_id)?;
        if loaded.is_persistent() {
            let _ = self.backend.release_handle(loaded.handle);
            return Err(Error::invalid_key("specified key is already persistent"));
        }

        let session_salt_handle = match self.load_session_salt_handle() {
            Ok(handle) => LoadedObjectHandle::Persistent(handle),
            Err(e) => {
                let _ = self.backend.release_handle(loaded.handle);
                return Err(e);
            }
        };

        let (obj_handle, persistent_handle) = self.backend.persist_handle(
            loaded.handle.inner(), 
            persistent_handle, 
            &owner_authorization, 
            session_salt_handle.inner(), 
            search_end,
        )?;

        match self.store.update_persistent_handle(key_id.as_str(), persistent_handle.value()) {
            Ok(()) => {
                let _ = self.backend.release_handle(obj_handle);
                let _ = self.backend.release_handle(session_salt_handle);
                Ok(())
            },
            Err(e) => {
                if let Err(err) = self.backend.evict_control(
                    obj_handle.inner(), 
                    persistent_handle, 
                    &owner_authorization, 
                    Some(session_salt_handle.inner()), 
                    None,
                ) {
                    debug!(?err, "rollback failed");
                    let _ = self.backend.release_handle(obj_handle);
                }
                let _ = self.backend.release_handle(session_salt_handle);

                Err(e)
            }
        }
    }
}