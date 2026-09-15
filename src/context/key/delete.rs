use crate::{
    Result, db::StoredKeyKind, types::{LoadedObjectHandle, tpm::{Tpm2bName, TpmiDhPersistent}}
};
use super::super::Context;

impl Context {
    pub fn delete(&mut self, key_name: &str) -> Result<()> {
        match self.store.get_key_kind(key_name)? {
            StoredKeyKind::Tpm => {
                let mut targets = Vec::new();
                self.store.collect_persistent_key(key_name, &mut targets)?;

                for target in targets.iter().rev() {
                    if let Some(handle) = target.persistent_handle {
                        self.evict_persistent_key(handle, &target.obj_name)?;
                    }

                    self.store.delete_key_meta(&target.key_name)?;
                    self.cache.delete_stored_key(&target.key_name);
                }                
            },
            StoredKeyKind::Symmetric => {
                self.store.delete_key_meta(key_name)?;
                self.cache.delete_stored_key(key_name);
            }
        }

        Ok(())
    }

    fn evict_persistent_key(
        &mut self, 
        persistent_handle: TpmiDhPersistent,
        obj_name: &Tpm2bName,
    ) -> Result<()> {
        let owner_authorization = self.owner_authorization()?;
        let session_salt_handle = self
            .load_session_salt_handle()
            .map(LoadedObjectHandle::Persistent)?;
        let loaded = match self.backend.resolve_persistent_handle(persistent_handle, obj_name) {
            Ok(loaded) => loaded,
            Err(e) => {
                let _ = self.backend.release_handle(session_salt_handle);
                return Err(e)
            }
        };

        let result = self.backend.evict_control(
            loaded.inner(), 
            persistent_handle, 
            &owner_authorization,
            Some(session_salt_handle.inner()), 
            None,
        )
        .map(|_| ());

        let _ = self.backend.release_handle(session_salt_handle);
        let _ = self.backend.release_handle(loaded);

        result
    }
}