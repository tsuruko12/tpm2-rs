use super::{Context, CommandResources};
use crate::{
    Result,
    db::InternalKeyMeta,
    types::{
        Authorization, CreatedObject, LoadedParent, Tpm2bAuth, TpmiDhObject, TpmiDhPersistent,
        TpmtPublic,
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

        let srk_authorization = Authorization::default();

        let result = (|| {
            let srk_meta = self.create_and_persist(
                &mut resources,
                TpmiDhPersistent::SRK_SEARCH_START,
                owner_authorization,
                Some(TpmiDhPersistent::SRK_SEARCH_END),
                None,
                |ctx| {
                    ctx.create_owner_primary(
                        &TpmtPublic::storage_parent(), 
                        owner_authorization, 
                        None,
                    )
                },
            )?;

            let srk_handle = TpmiDhObject::try_from(srk_meta.handle)
                .expect("created persistent handle must be valid");
            let parent = LoadedParent::new(
                srk_handle,
                srk_meta.object_name.clone(),
                srk_authorization,
            );

            key_meta.push(srk_meta);
            persistent_handles.push(srk_handle);

            self.flush_handles(&mut resources.transient_handles)?;

            let owner_available_first = TpmiDhPersistent::OWNER_AVAILABLE_FIRST;
            let rsa_public = TpmtPublic::rsa_decrypt();

            let session_salt_key_meta = self.create_and_persist(
                &mut resources,
                owner_available_first,
                owner_authorization,
                Some(TpmiDhPersistent::OWNER_AVAILABLE_LAST),
                None,
                |ctx| ctx.create_and_load(&rsa_public, Tpm2bAuth::default(), &parent, None),
            )?;
            let session_salt_key_handle = TpmiDhObject::try_from(session_salt_key_meta.handle)
                .expect("created persistent handle must be valid");

            key_meta.push(session_salt_key_meta);
            persistent_handles.push(session_salt_key_handle);

            self.flush_handles(&mut resources.transient_handles)?;

            let shared_wrapping_key_meta = self.create_and_persist(
                &mut &mut resources,
                (owner_available_first.raw() + 1)
                    .try_into()
                    .expect("owner handle must be in the persistent range"),
                owner_authorization,
                Some(TpmiDhPersistent::OWNER_AVAILABLE_LAST),
                Some(session_salt_key_handle),
                |ctx| {
                    ctx.create_and_load(
                        &rsa_public,
                        Tpm2bAuth::default(),
                        &parent,
                        Some(session_salt_key_handle),
                    )
                },
            )?;
            let shared_wrapping_key_handle = TpmiDhObject::try_from(shared_wrapping_key_meta.handle)
                .expect("created persistent handle must be valid");

            key_meta.push(shared_wrapping_key_meta);
            persistent_handles.push(shared_wrapping_key_handle);

            self.flush_handles(&mut resources.transient_handles)?;

            Ok(())
        })();

        match result {
            Ok(()) => {
                match self.release_resources(&mut resources) {
                    Ok(()) => Ok(key_meta),
                    Err(e) => {
                        self.evict_persistent_handles(
                            owner_authorization,
                            &key_meta, 
                            Some(&mut persistent_handles),    
                        );

                        Err(e)
                    }
                }
            },
            Err(e) => {
                self.cleanup_resources(&mut resources);
                self.evict_persistent_handles(
                    owner_authorization,
                    &key_meta, 
                    Some(&mut persistent_handles),    
                );

                Err(e)
            }
        }
    }

    fn create_and_persist<F>(
        &mut self,
        resources: &mut CommandResources,
        mut persistent_handle: TpmiDhPersistent,
        owner_authorization: &Authorization,
        serch_end: Option<TpmiDhPersistent>,
        session_salt_key: Option<TpmiDhObject>,
        create: F,
    ) -> Result<InternalKeyMeta>
    where
        F: FnOnce(&mut Self) -> Result<CreatedObject>,
    {
        let created = create(self)?;
        resources.add_transient_handle(created.obj_handle);

        self.evict_control(
            resources,
            created.obj_handle,
            &mut persistent_handle,
            owner_authorization,
            session_salt_key,
            serch_end,
        )?;

        Ok(InternalKeyMeta {
            handle: persistent_handle.raw(),
            object_name: created.name.into_bytes(),
        })
    }

    pub(crate) fn evict_persistent_handles(
        &mut self, 
        owner_authorization: &Authorization,
        key_meta: &[InternalKeyMeta], 
        persistent_handles: Option<&mut [TpmiDhObject]>,
    ) {
        let mut resources = CommandResources::default();

        match persistent_handles {
            Some(handles) => {
                for (meta, loaded_handle) in key_meta
                    .iter()
                    .rev()
                    .zip(handles.iter_mut().rev())
                {
                    let mut persistent_handle = TpmiDhPersistent::try_from(meta.handle)
                            .expect("created persistent handle must be valid");

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
            },
            None => {
                for meta in key_meta.iter().rev() {
                    let handle = TpmiDhObject::try_from(meta.handle)
                        .expect("created persistent handle must be valid");
                    let mut persistent_handle = TpmiDhPersistent::try_from(meta.handle)
                            .expect("created persistent handle must be valid");

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

        self.cleanup_resources(&mut resources);
    }
}
