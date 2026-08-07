use tss_esapi::{
    handles::{KeyHandle, ObjectHandle, PersistentTpmHandle},
    structures::Auth
};

use crate::{
    Error, Result, 
    db::InternalKeyMeta, 
    types::{Authorization, CreatedObject, LoadedParent, TpmiDhPersistent, TpmtPublic}
};
use super::{Context, CommandResources};

impl Context {
    pub(crate) fn create_internal_keys(
        &mut self,
        owner_authorization: &Authorization,
    ) -> Result<Vec<InternalKeyMeta>> {
        let mut resources = CommandResources::default();
        let mut key_meta = Vec::with_capacity(3);
        let mut persistent_handles = Vec::with_capacity(3);

        let srk_search_start = PersistentTpmHandle::new(TpmiDhPersistent::SRK_SEARCH_START.raw())
            .expect("SRK_SEARCH_START must be in the persistent range");
        let srk_search_end = PersistentTpmHandle::new(TpmiDhPersistent::SRK_SEARCH_END.raw())
            .expect("SRK_SEARCH_END must be in the persistent range");
        let srk_authorization = Authorization::default();

        let result = (|| {
            let (srk_meta, srk_handle) = self.create_and_persist(
                &mut resources,
                srk_search_start, 
                owner_authorization, 
                Some(srk_search_end), 
                None, 
                |ctx| {
                    ctx.create_owner_primary(
                        &(TpmtPublic::storage_parent().try_into()?), 
                        owner_authorization, 
                        None,
                    )
            })?;

            let parent = LoadedParent::new(
                srk_handle.into(),
                srk_meta.object_name.clone(),
                srk_authorization,
            );

            key_meta.push(srk_meta);
            persistent_handles.push(srk_handle);

            self.flush_handles(&mut resources.transient_handles)?;

            let storage_first = PersistentTpmHandle::new(
                TpmiDhPersistent::STORAGE_AVAILABLE_FIRST.raw()
            )
            .expect("STORAGE_AVAILABLE_FIRST must be in the persistent range");
            let storage_last = PersistentTpmHandle::new(
                TpmiDhPersistent::STORAGE_AVAILABLE_LAST.raw()
            )
            .expect("STORAGE_AVAILABLE_LAST must be in the persistent range");
            let rsa_public = TpmtPublic::rsa_decrypt().try_into()?;

            let (session_salt_key_meta, session_salt_key_handle) = self.create_and_persist(
                &mut resources,
                storage_first,
                owner_authorization,
                Some(storage_last),
                None,
                |ctx| ctx.create_and_load(&rsa_public, Auth::default(), &parent, None),
            )?;

            let next_handle = PersistentTpmHandle::new(session_salt_key_meta.handle + 1)
                .map_err(|_| Error::resource_exhausted("no persistent handle is available"))?;

            key_meta.push(session_salt_key_meta);
            persistent_handles.push(session_salt_key_handle);

            self.flush_handles(&mut resources.transient_handles)?;

            let (shared_wrapping_key_meta, shared_wrapping_key_handle) = self.create_and_persist(
                &mut resources,
                next_handle,
                owner_authorization,
                Some(storage_last),
                Some(session_salt_key_handle.into()),
                |ctx| {
                    ctx.create_and_load(
                        &rsa_public,
                        Auth::default(),
                        &parent,
                        Some(session_salt_key_handle.into()),
                    )
                },
            )?;

            key_meta.push(shared_wrapping_key_meta);
            persistent_handles.push(shared_wrapping_key_handle);

            self.flush_handles(&mut resources.transient_handles)?;

            Ok(())
        })();

        match result {
            Ok(()) => {
                match self.release_resources(&mut resources) {
                    Ok(()) => {
                        let _ = self.close_handles(&mut persistent_handles);
                        Ok(key_meta)
                    },
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
        mut persistent_handle: PersistentTpmHandle,
        owner_authorization: &Authorization,
        serch_end: Option<PersistentTpmHandle>,
        session_salt_key: Option<KeyHandle>,
        create: F,
    ) -> Result<(InternalKeyMeta, ObjectHandle)>
    where
        F: FnOnce(&mut Self) -> Result<CreatedObject>,
    {
        let created = create(self)?;
        resources.add_transient_handle(created.obj_handle);

        let handle = self.evict_control(
            resources,
            created.obj_handle.into(),
            &mut persistent_handle,
            owner_authorization,
            session_salt_key,
            serch_end,
        )?;

        Ok((
            InternalKeyMeta {
                handle: persistent_handle.into(),
                object_name: created.name.into_bytes(),
            },
            handle,
        ))
    }

    pub(crate) fn evict_persistent_handles(
        &mut self, 
        owner_authorization: &Authorization,
        key_meta: &[InternalKeyMeta], 
        persistent_handles: Option<&mut [ObjectHandle]>,
    ) {
        let mut resources = CommandResources::default();

        match persistent_handles {
            Some(handles) => {
                for (meta, loaded_handle) in key_meta
                    .iter()
                    .rev()
                    .zip(handles.iter_mut().rev())
                {
                    let mut persistent_handle =
                        PersistentTpmHandle::new(meta.handle)
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
                        let _ = self.close_handle(loaded_handle);
                    }
                }
            },
            None => {
                for meta in key_meta.iter().rev() {
                    let mut persistent_handle =
                        PersistentTpmHandle::new(meta.handle)
                            .expect("created persistent handle must be valid");
                    let Ok(mut handle) =
                        self.load_persistent_handle(persistent_handle)
                    else {
                        continue;
                    };

                    if let Err(err) = self.evict_control(
                        &mut resources,
                        handle,
                        &mut persistent_handle,
                        owner_authorization,
                        None,
                        None,
                    ) {
                        tracing::debug!(?err, "rollback failed");
                        let _ = self.close_handle(&mut handle);
                    }
                }
            }
        }

        self.cleanup_resources(&mut resources);
    }
}
