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
        let srk_authorization = Authorization::default();

        let srk_meta = self.create_and_persist(
            TpmiDhPersistent::SRK_HANDLE,
            owner_authorization,
            None,
            None,
            |ctx| {
                ctx.create_owner_primary(&TpmtPublic::storage_parent(), owner_authorization, None)
            },
        )?;

        let parent = LoadedParent::new(
            srk_meta.handle.into(),
            srk_meta.object_name.clone(),
            srk_authorization,
        );
        key_meta.push(srk_meta);

        let result = (|| {
            let rsa_public = TpmtPublic::rsa_decrypt();

            let session_salt_key = self.create_and_persist(
                TpmiDhPersistent::OWNER_AVAILABLE_FIRST,
                owner_authorization,
                Some(TpmiDhPersistent::OWNER_AVAILABLE_LAST),
                None,
                |ctx| ctx.create_and_load(&rsa_public, Tpm2bAuth::default(), &parent, None),
            )?;
            let session_salt_key_handle: TpmiDhObject = session_salt_key.handle.into();
            key_meta.push(session_salt_key);

            let shared_wrapping_key = self.create_and_persist(
                TpmiDhPersistent::OWNER_AVAILABLE_FIRST, // memo: should be add 1
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
            key_meta.push(shared_wrapping_key);

            Ok(())
        })();

        // memo: maybe deleting SRK isn't necessary, left it
        if let Err(e) = result {
            for meta in key_meta.iter().rev() {
                let mut handle = meta.handle;
                let _ =
                    self.evict_control(handle.into(), &mut handle, owner_authorization, None, None);
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

        let _ = self.flush_handle(created.handle.try_into()?); // memo: don't flush session_salt_key sinced it's used

        result.map(|_| InternalKeyMeta {
            handle: persistent_handle,
            object_name: created.name.into_bytes(),
        })
    }
}
