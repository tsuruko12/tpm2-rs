use super::{CommandResources, Context};
use crate::{
    Error, Result, db::{InternalKeyKind, InternalKeyMeta}, types::{
        Authorization, CreatedObject, LoadedHandle,
        tpm::{Tpm2bAuth, Tpm2bDigest, Tpm2bPublic, TpmiDhObject, TpmiDhPersistent, TpmiRhHierarchy},
    },
};

impl Context {
    pub(crate) fn create_internal_keys(
        &mut self,
        owner_authorization: &Authorization,
    ) -> Result<Vec<InternalKeyMeta>> {
        let mut resources = CommandResources::default();
        let mut key_meta = Vec::with_capacity(3);
        let mut persistent_handles = Vec::with_capacity(3);

        let empty_auth = Tpm2bAuth::default();
        let srk_authorization = Authorization::default();

        let result = (|| {
            let srk_meta = self.create_and_persist(
                &mut resources,
                InternalKeyKind::Srk,
                TpmiDhPersistent::SRK_SEARCH_START,
                owner_authorization,
                Some(TpmiDhPersistent::SRK_SEARCH_END),
                None,
                |ctx| {
                    ctx.create_primary(
                        TpmiRhHierarchy::OWNER,
                        &Tpm2bPublic::storage_parent(),
                        empty_auth.clone(),
                        owner_authorization,
                        None,
                    )
                },
            )?;
            let srk_handle = TpmiDhObject::from(srk_meta.handle);
            let parent =
                LoadedHandle::persistent(srk_handle, srk_meta.obj_name.clone(), srk_authorization);

            key_meta.push(srk_meta);
            persistent_handles.push(srk_handle);

            resources.flush_all_handles(self)?;

            let storage_available_first = TpmiDhPersistent::STORAGE_AVAILABLE_FIRST;
            let rsa_public = Tpm2bPublic::rsa_decrypt(Tpm2bDigest::default());

            let session_salt_key_meta = self.create_and_persist(
                &mut resources,
                InternalKeyKind::SessionSaltKey,
                storage_available_first,
                owner_authorization,
                Some(TpmiDhPersistent::STORAGE_AVAILABLE_LAST),
                None,
                |ctx| ctx.create_and_load(&rsa_public, empty_auth.clone(), &parent, None),
            )?;
            let session_salt_handle = TpmiDhObject::from(session_salt_key_meta.handle);

            let next_handle = TpmiDhPersistent::try_from(session_salt_key_meta.handle.value() + 1)
                .map_err(|_| Error::resource_exhausted("no persistent handle is available"))?;

            key_meta.push(session_salt_key_meta);
            persistent_handles.push(session_salt_handle);

            resources.flush_all_handles(self)?;

            let shared_wrapping_key_meta = self.create_and_persist(
                &mut resources,
                InternalKeyKind::SharedWrappingKey,
                next_handle,
                owner_authorization,
                Some(TpmiDhPersistent::STORAGE_AVAILABLE_LAST),
                Some(session_salt_handle),
                |ctx| {
                    ctx.create_and_load(&rsa_public, empty_auth, &parent, Some(session_salt_handle))
                },
            )?;
            let shared_wrapping_handle = TpmiDhObject::from(shared_wrapping_key_meta.handle);

            key_meta.push(shared_wrapping_key_meta);
            persistent_handles.push(shared_wrapping_handle);

            resources.flush_all_handles(self)
        })();

        match result {
            Ok(()) => match resources.release(self) {
                Ok(()) => Ok(key_meta),
                Err(e) => {
                    self.evict_persistent_handles(
                        owner_authorization,
                        &key_meta,
                        Some(&persistent_handles),
                    );
                    Err(e)
                }
            },
            Err(e) => {
                resources.cleanup(self);
                
                self.evict_persistent_handles(
                    owner_authorization,
                    &key_meta,
                    Some(&persistent_handles),
                );
                Err(e)
            }
        }
    }

    fn create_and_persist<F>(
        &mut self,
        resources: &mut CommandResources,
        kind: InternalKeyKind,
        mut persistent_handle: TpmiDhPersistent,
        owner_authorization: &Authorization,
        serch_end: Option<TpmiDhPersistent>,
        session_salt_handle: Option<TpmiDhObject>,
        create: F,
    ) -> Result<InternalKeyMeta>
    where
        F: FnOnce(&mut Self) -> Result<CreatedObject>,
    {
        let created = create(self)?;
        resources.add_transient_handle(created.handle);

        self.evict_control(
            resources,
            created.handle,
            &mut persistent_handle,
            owner_authorization,
            session_salt_handle,
            serch_end,
        )?;

        Ok(InternalKeyMeta {
            kind,
            handle: persistent_handle,
            obj_name: created.name,
        })
    }

    pub(crate) fn evict_persistent_handles(
        &mut self,
        owner_authorization: &Authorization,
        key_meta: &[InternalKeyMeta],
        persistent_handles: Option<&[TpmiDhObject]>,
    ) {
        let mut resources = CommandResources::default();

        match persistent_handles {
            Some(handles) => {
                for (meta, loaded_handle) in key_meta.iter().rev().zip(handles.iter().rev()) {
                    let mut persistent_handle = meta.handle;

                    if let Err(err) = self.evict_control(
                        &mut resources,
                        *loaded_handle,
                        &mut persistent_handle,
                        owner_authorization,
                        None,
                        None,
                    ) {
                        tracing::debug!(?err, "rollback failed");
                    }
                }
            }
            None => {
                for meta in key_meta.iter().rev() {
                    let handle = TpmiDhObject::from(meta.handle);
                    let mut persistent_handle = meta.handle;

                    if let Err(err) = self.evict_control(
                        &mut resources,
                        handle,
                        &mut persistent_handle,
                        owner_authorization,
                        None,
                        None,
                    ) {
                        tracing::debug!(?err, "rollback failed");
                    }
                }
            }
        }

        resources.cleanup(self);
    }
}
