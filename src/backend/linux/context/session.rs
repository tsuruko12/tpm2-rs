mod policy;

use tss_esapi::{
    constants::SessionType,
    handles::{KeyHandle, ObjectHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{Auth, SymmetricDefinition},
};

use super::{CommandResources, Context};
use crate::{
    Error, Result,
    types::{Authorization, PolicyData, tpm::TpmaSession},
};

// policy + no-attrs -> policy authorization
// policy + attrs -> policy authorization + extra HMAC session for attrs
// no-policy + attrs -> HMAC authorization
// no-policy + auth + no-attrs -> HMAC authorization
// no-policy + no-auth + no-attrs -> password authorization

impl Context {
    pub(super) fn prepare_sessions(
        &mut self,
        resources: &mut CommandResources,
        session_attrs: TpmaSession,
        authorization: Option<(ObjectHandle, &Authorization)>,
        tpm_key: Option<KeyHandle>,
    ) -> Result<()> {
        // tpm_key is only None before the handle is created
        let Some((obj_handle, authorization)) = authorization else {
            if let Some(hmac_session) = resources.find_hmac_session() {
                return self.reuse_hmac_session(hmac_session, session_attrs);
            }
            return self.prepare_hmac_session(resources, session_attrs, tpm_key);
        };

        self.set_auth(obj_handle, authorization.auth.clone().into())?;

        if !resources.has_no_sessions() {
            return self.reuse_sessions(
                resources, 
                session_attrs, 
                authorization.policy.as_ref(),
            )
        }

        if let Some(policy) = &authorization.policy {
            self.prepare_policy_session(resources, policy, tpm_key)?;

            if !session_attrs.is_empty() {
                self.prepare_hmac_session(resources, session_attrs, tpm_key)?;
            }
        } else if (session_attrs.is_empty() 
            || session_attrs == TpmaSession::CONTINUE_SESSION)
            && authorization.auth.is_empty()
        {
            resources.add_session(AuthSession::Password)?;
        } else {
            self.prepare_hmac_session(resources, session_attrs, tpm_key)?;
        }                       

        Ok(())
    }

    fn prepare_policy_session(
        &mut self,
        resources: &mut CommandResources,
        policy: &PolicyData,
        tpm_key: Option<KeyHandle>,
    ) -> Result<()> {
        let policy_session = self.start_auth_session(resources, SessionType::Policy, tpm_key)?;

        self.set_session_attrs(policy_session, TpmaSession::continue_session())?;
        self.apply_policy(
            policy_session
                .try_into()
                .expect("expected policy session handle"),
            policy,
        )
    }

    fn prepare_hmac_session(
        &mut self,
        resources: &mut CommandResources,
        session_attrs: TpmaSession,
        tpm_key: Option<KeyHandle>,
    ) -> Result<()> {
        let hmac_session = self.start_auth_session(resources, SessionType::Hmac, tpm_key)?;
        let session_attrs = session_attrs.with_continue_session();
        self.set_session_attrs(hmac_session, session_attrs)
    }

    fn reuse_sessions(
        &mut self, 
        resources: &mut CommandResources,
        session_attrs: TpmaSession,
        policy: Option<&PolicyData>,
    ) -> Result<()> {
        if resources.find_password_session().is_some() {
            return Ok(())
        }

        if let Some(hmac_session) = resources.find_hmac_session() {
            self.reuse_hmac_session(hmac_session, session_attrs)?;
        }

        if let Some(session) = resources.find_policy_session() {
            let policy = policy
                .ok_or_else(|| Error::invalid_state(
                    "policy must be Some when reusing a policy session")
                )?;

            let policy_session = PolicySession::try_from(session).unwrap();
            self.restart_policy(policy_session)?;
            self.set_session_attrs(session, TpmaSession::continue_session())?;

            self.apply_policy(
                policy_session,
                policy,
            )?;
        }

        Ok(())
    }

    fn reuse_hmac_session(
        &mut self, 
        hmac_session: AuthSession,
        session_attrs: TpmaSession,
    ) -> Result<()> {
        let session_attrs = session_attrs.with_continue_session();
        self.set_session_attrs(hmac_session, session_attrs)
    }

    fn set_session_attrs(&mut self, session: AuthSession, session_attrs: TpmaSession) -> Result<()> {
        self.ctx.tr_sess_set_attributes(
            session,
            session_attrs.into(),
            TpmaSession::all().bits().into(),
        )
        .map_err(Error::esapi)
    }

    fn start_auth_session(
        &mut self,
        resources: &mut CommandResources,
        session_type: SessionType,
        tpm_key: Option<KeyHandle>,
    ) -> Result<AuthSession> {
        let session = self
            .ctx
            .start_auth_session(
                tpm_key,
                None,
                None,
                session_type,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(Error::from_tss_err)?
            .ok_or_else(|| {
                tracing::debug!("TPM returns no session");
                Error::InvalidData
            })?;

        resources.add_session(session)?;

        Ok(session)
    }

    fn set_auth(&mut self, handle: ObjectHandle, auth: Auth) -> Result<()> {
        self.ctx
            .tr_set_auth(handle, auth)
            .map_err(Error::esapi)
    }
}
