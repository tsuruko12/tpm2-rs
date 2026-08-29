use tss_esapi::handles::ObjectHandle;

use crate::{
    Error, Result, 
    db::{InternalKeyKind, InternalKeyMeta}, 
    types::{
        Authorization, CreatedObject, LoadedHandle,
        tpm::{Tpm2bAuth, Tpm2bDigest, Tpm2bPublic, TpmiDhPersistent, TpmiRhHierarchy},
    }
};
use super::{Context, CommandResources};

impl Context {
    pub(crate) fn create_internal_keys(
        &mut self,
        owner_authorization: &Authorization,
    ) -> Result<Vec<InternalKeyMeta>> {
        let mut key_meta = Vec::with_capacity(3);
        let mut persistent_handles = Vec::with_capacity(3);

        let empty_auth = Tpm2bAuth::default();
        let srk_authorization = Authorization::default();

        let mut resources = CommandResources::default();

        let result = (|| {
            let (srk_meta, srk_handle) = self.create_and_persist(
                &mut resources,
                InternalKeyKind::Srk,
                TpmiDhPersistent::SRK_SEARCH_START, 
                owner_authorization, 
                Some(TpmiDhPersistent::SRK_SEARCH_END), 
                None, 
                |ctx| {
                    ctx.create_primary(
                        TpmiRhHierarchy::OWNER,
                        Tpm2bPublic::storage_parent(),
                        empty_auth.clone(), 
                        owner_authorization, 
                        None,
                    )
            })?;

            let parent = LoadedHandle::persistent(
                srk_handle.into(),
                srk_meta.obj_name.clone(),
                srk_authorization,
            );

            key_meta.push(srk_meta);
            persistent_handles.push(srk_handle);

            let _ = resources.flush_all_handles(self);

            let rsa_public = Tpm2bPublic::rsa_decrypt(Tpm2bDigest::default());

            let (session_salt_key_meta, session_salt_handle) = self.create_and_persist(
                &mut resources,
                InternalKeyKind::SessionSaltKey,
                TpmiDhPersistent::STORAGE_AVAILABLE_FIRST,
                owner_authorization,
                Some(TpmiDhPersistent::STORAGE_AVAILABLE_LAST),
                None,
                |ctx| {
                    ctx.create_and_load_key(
                        rsa_public.clone(), 
                        empty_auth.clone(), 
                        &parent, 
                        None
                    )
                },
            )?;

            let next_handle = TpmiDhPersistent::try_from(session_salt_key_meta.handle.value() + 1)
                .map_err(|_| Error::resource_exhausted("no persistent handle is available"))?;
            if next_handle.value() > TpmiDhPersistent::STORAGE_AVAILABLE_LAST.value() {
                return Err(Error::resource_exhausted("no persistent handle is available"));
            }

            key_meta.push(session_salt_key_meta);
            persistent_handles.push(session_salt_handle);

            let _ = resources.flush_all_handles(self);

            let (shared_wrapping_key_meta, shared_wrapping_handle) = self.create_and_persist(
                &mut resources,
                InternalKeyKind::SharedWrappingKey,
                next_handle,
                owner_authorization,
                Some(TpmiDhPersistent::STORAGE_AVAILABLE_LAST),
                Some(session_salt_handle.into()),
                |ctx| {
                    ctx.create_and_load_key(
                        rsa_public,
                        empty_auth,
                        &parent,
                        Some(session_salt_handle.into()),
                    )
                },
            )?;

            key_meta.push(shared_wrapping_key_meta);
            persistent_handles.push(shared_wrapping_handle);

            let _ = resources.flush_all_handles(self);

            Ok(())
        })();

        match result {
            Ok(()) => {
                for handle in persistent_handles {
                    resources.add_persistent_handle(handle);
                }            
                let _ = resources.release(self);

                Ok(key_meta)
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
        persistent_handle: TpmiDhPersistent,
        owner_authorization: &Authorization,
        serch_end: Option<TpmiDhPersistent>,
        session_salt_handle: Option<ObjectHandle>,
        create: F,
    ) -> Result<(InternalKeyMeta, ObjectHandle)>
    where
        F: FnOnce(&mut Self) -> Result<CreatedObject>,
    {
        let created = create(self)?;
        resources.add_transient_handle(created.handle);

        let (handle, persistent_handle) = self.evict_control(
            created.handle,
            persistent_handle,
            owner_authorization,
            session_salt_handle,
            serch_end,
        )?;

        Ok((
            InternalKeyMeta {
                kind,
                handle: persistent_handle,
                obj_name: created.name,
            },
            handle,
        ))
    }

    pub(crate) fn evict_persistent_handles(
        &mut self, 
        owner_authorization: &Authorization,
        key_meta: &[InternalKeyMeta], 
        persistent_handles: Option<&[ObjectHandle]>,
    ) {
        let mut resources = CommandResources::default();

        match persistent_handles {
            Some(handles) => {
                for (meta, obj_handle) in key_meta
                    .iter()
                    .rev()
                    .zip(handles.iter().rev())
                {
                    resources.add_persistent_handle(*obj_handle);

                    if let Err(e) = self.evict_control(
                        *obj_handle,
                        meta.handle,
                        owner_authorization,
                        None,
                        None,
                    ) {
                        tracing::debug!(?e, "rollback failed");
                    }
                }
            },
            None => {
                for meta in key_meta.iter().rev() {    
                    let Ok(loaded_handle) =
                        self.load_persistent_handle(meta.handle)
                    else {
                        continue;
                    };
                    resources.add_handle(loaded_handle);

                    if let Err(e) = self.evict_control(
                        loaded_handle.inner(),
                        meta.handle,
                        owner_authorization,
                        None,
                        None,
                    ) {
                        tracing::debug!(?e, "rollback failed");
                    }
                }
            }
        }

        resources.cleanup(self);
    }
}
