use sha2::{Digest as _, Sha256};
use tracing::error;
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

use super::{Context, auth_from_bytes};
use crate::{
    Error, Result,
    types::{Authorization, PcrSelection, PolicyCommand, PolicyData, Tpm2bDigest, TpmaSession},
};

type SessionSlots = (
    Option<AuthSession>,
    Option<AuthSession>,
    Option<AuthSession>,
);

impl Context {
    pub(super) fn prepare_sessions(
        &mut self,
        auth_handle: impl Into<ObjectHandle>,
        authorization: &Authorization,
        session_attrs: TpmaSession,
        session_salt_key: Option<KeyHandle>,
    ) -> Result<SessionSlots> {
        // session_salt_key is only None before the handle is created
        let auth_handle = auth_handle.into();
        let (auth, policy) = authorization.as_parts();

        self.set_auth(auth_handle, auth)?;

        let mut sessions = Vec::with_capacity(2);

        if let Some(policy) = policy {
            sessions.push(self.prepare_policy_session(policy, session_salt_key)?);

            if !session_attrs.is_empty() {
                sessions.push(self.prepare_hmac_session(session_attrs, session_salt_key)?);
            }

            return Ok(to_session_slots(sessions));
        }

        if (session_attrs.is_empty() || session_attrs == TpmaSession::CONTINUE_SESSION)
            && auth.is_empty()
        {
            sessions.push(AuthSession::Password);
        } else {
            sessions.push(self.prepare_hmac_session(session_attrs, session_salt_key)?);
        }

        Ok(to_session_slots(sessions))
    }

    pub(super) fn prepare_sessions_with_hmac(
        &mut self,
        hmac_session: AuthSession,
        session_attrs: TpmaSession,
        policy: Option<&PolicyData>,
        session_salt_key: Option<KeyHandle>,
    ) -> Result<SessionSlots> {
        let mut sessions = Vec::with_capacity(2);

        if let Some(policy) = policy {
            sessions.push(self.prepare_policy_session(policy, session_salt_key)?);
        }

        self.set_session_attrs(hmac_session, session_attrs)?;
        sessions.push(hmac_session);

        Ok(to_session_slots(sessions))
    }

    fn prepare_policy_session(
        &mut self,
        policy: &PolicyData,
        session_salt_key: Option<KeyHandle>,
    ) -> Result<AuthSession> {
        self.ensure_session_slot_available()?;

        let policy_session = self.start_auth_session(session_salt_key, SessionType::Policy)?;
        self.set_session_attrs(policy_session, TpmaSession::continue_session())?;

        if let Err(e) = self.apply_policy(
            policy_session
                .try_into()
                .expect("session was created as a policy session"),
            policy,
        ) {
            let _ = self.flush_sessions();
            return Err(e);
        }

        self.set_session_attrs(policy_session, TpmaSession::empty())?;

        Ok(policy_session)
    }

    fn prepare_hmac_session(
        &mut self,
        attrs: TpmaSession,
        session_salt_key: Option<KeyHandle>,
    ) -> Result<AuthSession> {
        self.ensure_session_slot_available()?;

        let hmac_session = self.start_auth_session(session_salt_key, SessionType::Hmac)?;
        self.set_session_attrs(hmac_session, attrs)?;

        Ok(hmac_session)
    }

    fn set_session_attrs(&mut self, session: AuthSession, attrs: TpmaSession) -> Result<()> {
        match self.ctx.tr_sess_set_attributes(
            session,
            attrs.into(),
            TpmaSession::all().bits().into(),
        ) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = self.flush_sessions();
                Err(Error::from_tss_err(e))
            }
        }
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
                tracing::error!("TPM returns no session");
                Error::InvalidData
            })?;

        self.register_session(session);

        Ok(session)
    }

    pub(super) fn find_hmac_session(&self) -> Option<AuthSession> {
        self.sessions
            .iter()
            .flatten()
            .copied()
            .find(|session| matches!(session, AuthSession::HmacSession(_)))
    }

    fn set_auth(&mut self, handle: ObjectHandle, auth: &[u8]) -> Result<()> {
        self.ctx
            .tr_set_auth(handle, auth_from_bytes(auth)?)
            .map_err(Error::esapi)
    }

    fn ensure_session_slot_available(&self) -> Result<()> {
        if self.sessions.iter().any(Option::is_none) {
            Ok(())
        } else {
            Err(Error::invalid_state("no available session slot"))
        }
    }

    fn register_session(&mut self, session: AuthSession) {
        let slot = self
            .sessions
            .iter_mut()
            .find(|slot| slot.is_none())
            .expect("session slot must be available");

        *slot = Some(session);
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
                error!("PCR read did not return the requested values");
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

fn to_session_slots(sessions: Vec<AuthSession>) -> SessionSlots {
    let mut iter = sessions.into_iter();
    (iter.next(), iter.next(), iter.next())
}
