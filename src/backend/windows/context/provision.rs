use crate::{
    Result, db::InternalKeyMeta, 
    types::{Authorization, LoadedParent, Tpm2bAuth, TpmiDhObject, TpmiDhPersistent, TpmtPublic}
};
use super::{Context, key::CreatedObject};

impl Context {
    pub(crate) fn create_internal_keys(
        &mut self, 
        owner_authorization: &Authorization,
    ) -> Result<Vec<InternalKeyMeta>> {
        let mut key_meta = Vec::with_capacity(3);
        let srk_authorization = Authorization::default();

        let srk_meta = self.create_and_persist(
            TpmiDhPersistent::SRK_HANDLE, 
            owner_authorization, 
            None, 
            None, 
            |context| {
                context.create_owner_primary(
                    &TpmtPublic::storage_parent(),
                    owner_authorization,
                    None,
                )
            },
        )?;

        let parent = LoadedParent::new(
            srk_meta.handle.into(), 
            srk_meta.object_name.as_slice(), 
            srk_authorization,
        );
        key_meta.push(srk_meta);

        let result = (|| {
            let rsa_public = TpmtPublic::rsa_decrypt();

            let session_salt_key = self.create_and_persist(
                TpmiDhPersistent::OWNER_AVAILABEL_FIRST,
                owner_authorization,
                Some(TpmiDhPersistent::OWNER_AVAILABEL_LAST),
                None,
                |context| {
                    context.create_and_load(
                        &rsa_public,
                        Tpm2bAuth::default(),
                        &parent,
                        None,
                    )
                },
            )?;
            let session_salt_key_handle: TpmiDhObject = session_salt_key.handle.into();
            key_meta.push(session_salt_key);

            let shared_wrapping_key = self.create_and_persist(
                TpmiDhPersistent::OWNER_AVAILABEL_FIRST,
                owner_authorization,
                Some(TpmiDhPersistent::OWNER_AVAILABEL_LAST),
                Some(session_salt_key_handle),
                |context| {
                    context.create_and_load(
                        &rsa_public,
                        Tpm2bAuth::default(),
                        &parent,
                        Some(session_salt_key_handle),
                    )
                },
            )?;
            key_meta.push(shared_wrapping_key);

            Ok(())
        })();

        if let Err(e) = result {
            for meta in key_meta.iter().rev() {
                let mut handle = meta.handle;
                let _ = self.evict_control(
                    handle.into(), 
                    &mut handle, 
                    owner_authorization, 
                    None, 
                    None,
                );                
            }

            return Err(e);
        }

        Ok(key_meta)
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
            created.handle.try_into()?,
            &mut persistent_handle,
            owner_authorization,
            session_salt_key_handle, 
            serch_end,
        );

        let _ = self.flush_handle(created.handle.try_into()?);

        result.map(|_| InternalKeyMeta {
            handle: persistent_handle,
            object_name: created.name.into_bytes(),
        })
    }
}
