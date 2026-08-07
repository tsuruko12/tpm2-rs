use tss_esapi::{
    handles::{KeyHandle, ObjectHandle, TpmHandle as EsapiTpmHandle},
    interface_types::session_handles::AuthSession,
    structures::{Private, Public},
};

use crate::{
    Error, Result,
    types::{LoadedParent, TpmaSession},
};
use super::Context;
use super::super::CommandResources;

impl Context {
    pub(super) fn load_handle(
        &mut self,
        in_private: &Private,
        in_public: &Public,
        parent: &LoadedParent,
        session_salt_key: Option<KeyHandle>,
        caller_resources: Option<&mut CommandResources>,
    ) -> Result<(KeyHandle, Vec<u8>)> {
        let mut default_resources = CommandResources::default();
        let resources = caller_resources.unwrap_or(&mut default_resources);

        let parent_handle = parent.handle();

        let result = (|| {
            match session_salt_key {
                Some(_) => {
                    self.prepare_sessions(
                        resources, 
                        Some((parent_handle.into(), parent.authorization())),
                        TpmaSession::decrypt().with_continue_session(), 
                        session_salt_key,
                    )?
                },
                None => resources.add_session(AuthSession::Password)?,
            }

            let obj_handle = self
                .ctx
                .execute_with_sessions(resources.session_slots(), |ctx| {
                    ctx.load(parent_handle, in_private.clone(), in_public.clone())
                })
                .map_err(Error::from_tss_err)?;
            
            resources.clear_policy_session();
            resources.add_transient_handle(obj_handle);

            Ok((obj_handle, self.read_object_name(obj_handle)?))
        })();

        self.finish_command(result, resources)
    }

    pub(crate) fn load_persistent_handle(
        &mut self,
        tpm_handle: impl Into<EsapiTpmHandle>,
    ) -> Result<ObjectHandle> {
        self.ctx
            .tr_from_tpm_public(tpm_handle.into())
            .map_err(Error::esapi)
    }
}
