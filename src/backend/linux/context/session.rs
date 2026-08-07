use sha2::{Digest as _, Sha256};
use tracing::debug;
use tss_esapi::{
    constants::SessionType,
    handles::{KeyHandle, ObjectHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Digest, DigestList, PcrSelectionList, PcrSelectionListBuilder, SymmetricDefinition,
    },
};

use super::{CommandResources, Context, auth_from_bytes};
use crate::{
    Error, Result,
    types::{Authorization, PcrSelection, PolicyCommand, PolicyData, Tpm2bDigest, TpmaSession},
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
        authorization: Option<(ObjectHandle, &Authorization)>,
        session_attrs: TpmaSession,
        tpm_key: Option<KeyHandle>,
    ) -> Result<()> {
        // tpm_key is only None before the handle is created
        match authorization {
            Some((obj_handle, authorization)) => {
                let (auth, policy) = authorization.as_parts();
                self.set_auth(obj_handle, auth)?;

                if let Some(hmac_session) = resources.find_hmac_session() {
                    self.prepare_sessions_with_hmac(
                        resources, 
                        hmac_session, 
                        session_attrs, 
                        policy, 
                        tpm_key,
                    )?;
                } else if let Some(policy) = policy {
                    self.prepare_policy_session(resources, policy, tpm_key)?;

                    if !session_attrs.is_empty() {
                        self.prepare_hmac_session(resources, session_attrs, tpm_key)?;
                    }
                } else if (session_attrs.is_empty() 
                    || session_attrs == TpmaSession::CONTINUE_SESSION)
                    && auth.is_empty()
                {
                    resources.add_session(AuthSession::Password)?;
                } else {
                    self.prepare_hmac_session(resources, session_attrs, tpm_key)?;
                }                       
            },
            None => {
                self.prepare_hmac_session(resources, session_attrs, tpm_key)?;
            }
        }

        Ok(())
    }

    fn prepare_sessions_with_hmac(
        &mut self,
        resources: &mut CommandResources,
        hmac_session: AuthSession,
        session_attrs: TpmaSession,
        policy: Option<&PolicyData>,
        tpm_key: Option<KeyHandle>,
    ) -> Result<()> {
        if let Some(policy) = policy {
            self.prepare_policy_session(resources, policy, tpm_key)?;
        }

        self.set_session_attrs(hmac_session, session_attrs)
    }

    fn prepare_policy_session(
        &mut self,
        resources: &mut CommandResources,
        policy: &PolicyData,
        tpm_key: Option<KeyHandle>,
    ) -> Result<AuthSession> {
        let policy_session = self.start_auth_session(tpm_key, SessionType::Policy)?;
        resources.add_session(policy_session)?;

        self.set_session_attrs(policy_session, TpmaSession::empty())?;
        self.apply_policy(
            policy_session
                .try_into()
                .expect("session must be a policy session"),
            policy,
        )?;

        Ok(policy_session)
    }

    fn prepare_hmac_session(
        &mut self,
        resources: &mut CommandResources,
        session_attrs: TpmaSession,
        tpm_key: Option<KeyHandle>,
    ) -> Result<AuthSession> {
        let hmac_session = self.start_auth_session(tpm_key, SessionType::Hmac)?;
        resources.add_session(hmac_session)?;
        self.set_session_attrs(hmac_session, session_attrs)?;

        Ok(hmac_session)
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
        tpm_key: Option<KeyHandle>,
        session_type: SessionType,
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

        Ok(session)
    }

    fn set_auth(&mut self, handle: ObjectHandle, auth: &[u8]) -> Result<()> {
        self.ctx
            .tr_set_auth(handle, auth_from_bytes(auth)?)
            .map_err(Error::esapi)
    }

    fn apply_policy(&mut self, session: PolicySession, policy: &PolicyData) -> Result<()> {
        self.apply_policy_step(session, policy)
    }

    fn apply_policy_pcr(&mut self, session: PolicySession, selection: &PcrSelection) -> Result<()> {
        let size_of_select = self.get_sha256_pcr_select_size()?;
        let hash_alg = selection.hash_alg().into();
        let selected_slots = selection
            .slots()
            .iter()
            .copied()
            .map(Into::into)
            .collect::<Vec<_>>();

        let selection_list = PcrSelectionListBuilder::new()
            .with_size_of_select(size_of_select)
            .with_selection(hash_alg, &selected_slots)
            .build()
            .map_err(|e| {
                Error::invalid_state(format!("failed to build PCR selection list: {e:#}"))
            })?;

        let digest = self.compute_pcr_digest(selection_list.clone())?;

        self.ctx
            .policy_pcr(session, digest, selection_list)
            .map_err(Error::from_tss_err)
    }

    fn apply_policy_command_code(
        &mut self,
        session: PolicySession,
        command_code: PolicyCommand,
    ) -> Result<()> {
        self.ctx
            .policy_command_code(session, command_code.into())
            .map_err(Error::from_tss_err)
    }

    fn apply_policy_auth(&mut self, session: PolicySession) -> Result<()> {
        self.ctx
            .policy_auth_value(session)
            .map_err(Error::from_tss_err)
    }

    fn apply_policy_password(&mut self, session: PolicySession) -> Result<()> {
        self.ctx
            .policy_password(session)
            .map_err(Error::from_tss_err)
    }

    fn apply_policy_or(
        &mut self,
        session: PolicySession,
        digests: &[Tpm2bDigest],
        selected_branch: &PolicyData,
    ) -> Result<()> {
        let mut digest_list = DigestList::new();

        for digest in digests {
            digest_list
                .add(digest.clone().try_into()?)
                .map_err(|_| Error::invalid_state("digest list contains more than 8 items"))?;
        }

        if matches!(selected_branch, PolicyData::Or { .. }) {
            return Err(Error::invalid_state("unexpected nested PolicyOr"));
        }

        self.apply_policy_step(session, selected_branch)?;
        self.ctx
            .policy_or(session, digest_list)
            .map_err(Error::from_tss_err)
    }

    fn apply_sequence_steps(&mut self, session: PolicySession, steps: &[PolicyData]) -> Result<()> {
        for step in steps {
            if matches!(step, PolicyData::Sequence(_)) {
                return Err(Error::invalid_state("unexpected nested policy sequence"));
            }

            self.apply_policy_step(session, step)?;
        }

        Ok(())
    }

    fn compute_pcr_digest(&mut self, selection_list: PcrSelectionList) -> Result<Digest> {
        let mut hasher = Sha256::new();
        let mut update_counter = None;
        let mut remaining = selection_list;

        while !remaining.is_empty() {
            let (counter, returned_selection, digest_list) = self
                .ctx
                .pcr_read(remaining.clone())
                .map_err(Error::from_tss_err)?;

            match update_counter {
                Some(expected_counter) => {
                    if expected_counter != counter {
                        return Err(Error::authorization_failed("PCR value changed during read"));
                    }
                }
                None => update_counter = Some(counter),
            }

            let selected_count = returned_selection
                .get_selections()
                .iter()
                .map(|selection| selection.selected().len())
                .sum::<usize>();

            if selected_count == 0 || digest_list.len() != selected_count {
                debug!("PCR read did not return the requested values");
                return Err(Error::InvalidData);
            }

            for digest in digest_list.value() {
                hasher.update(digest.value());
            }

            remaining
                .subtract(&returned_selection)
                .map_err(Error::from_tss_err)?;
        }

        Digest::try_from(hasher.finalize().to_vec()).map_err(Error::from_tss_err)
    }

    fn apply_policy_step(&mut self, session: PolicySession, policy: &PolicyData) -> Result<()> {
        match policy {
            PolicyData::Pcr(selection) => self.apply_policy_pcr(session, selection),
            PolicyData::Command(command) => self.apply_policy_command_code(session, *command),
            PolicyData::AuthValue => self.apply_policy_auth(session),
            PolicyData::Password => self.apply_policy_password(session),
            PolicyData::Or { .. } => {
                let (digests, selected_branch) = policy.selected_or_branch()?;
                self.apply_policy_or(session, digests, selected_branch)
            }
            PolicyData::Sequence(steps) => self.apply_sequence_steps(session, steps),
        }
    }
}
