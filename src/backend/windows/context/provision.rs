use super::Context;
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
        let mut key_meta = Vec::with_capacity(3);
        let mut persistent_handles = Vec::with_capacity(3);

        let srk_handle = TpmiDhObject::from(TpmiDhPersistent::SRK_HANDLE);
        let srk_authorization = Authorization::default();

        let srk_meta = self.create_and_persist(
            TpmiDhPersistent::SRK_HANDLE,
            owner_authorization,
            None,
            None,
            |ctx| {
                ctx.create_owner_primary(
                    &TpmtPublic::storage_parent(), 
                    owner_authorization, 
                    None,
                )
            },
        )?;

        let parent = LoadedParent::new(
            srk_handle,
            srk_meta.object_name.clone(),
            srk_authorization,
        );

        key_meta.push(srk_meta);
        persistent_handles.push(srk_handle);

        let result = (|| {
            let owner_available_first = TpmiDhPersistent::OWNER_AVAILABLE_FIRST;
            let rsa_public = TpmtPublic::rsa_decrypt();

            let session_salt_key_meta = self.create_and_persist(
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

            let shared_wrapping_key_meta = self.create_and_persist(
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

            Ok(())
        })();

        match result {
            Ok(()) => Ok(key_meta),
            Err(e) => {
                self.evict_persistent_handles(
                    &key_meta, 
                    Some(&persistent_handles), 
                    owner_authorization,
                );
                
                Err(e)
            },
        }
    }

    fn create_and_persist<F>(
        &mut self,
        mut persistent_handle: TpmiDhPersistent,
        owner_authorization: &Authorization,
        serch_end: Option<TpmiDhPersistent>,
        session_salt_key_handle: Option<TpmiDhObject>,
        create: F,
    ) -> Result<InternalKeyMeta>
    where
        F: FnOnce(&mut Self) -> Result<CreatedObject>,
    {
        let created = create(self)?;

        let result = self.evict_control(
            created.handle,
            &mut persistent_handle,
            owner_authorization,
            session_salt_key_handle,
            serch_end,
        );
        let _ = self.flush_handle(created.handle);

        result.map(|_| InternalKeyMeta {
            handle: persistent_handle.raw(),
            object_name: created.name.into_bytes(),
        })
    }

    pub(crate) fn evict_persistent_handles(
        &mut self, 
        owner_authorization: &Authorization,
        key_meta: &[InternalKeyMeta], 
        persistent_handles: Option<&[TpmiDhObject]>,
    ) {
        match persistent_handles {
            Some(handles) => {
                for (meta, &loaded_handle) in
                    key_meta.iter().rev().zip(handles.iter().rev())
                {
                    let mut persistent_handle = TpmiDhPersistent::try_from(meta.handle)
                            .expect("created persistent handle must be valid");

                    if let Err(err) = self.evict_control(
                        loaded_handle,
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
                    let handle = TpmiDhObject::try_from(meta.handle)
                        .expect("created persistent handle must be valid");
                    let mut persistent_handle = TpmiDhPersistent::try_from(meta.handle)
                            .expect("created persistent handle must be valid");

                    if let Err(err) = self.evict_control(
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
    }
}
