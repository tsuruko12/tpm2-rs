use sha2::{Digest as Sha2Digest, Sha256};
use tracing::debug;
use tss_esapi::{
    constants::SessionType,
    interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
    structures::{
        Digest, DigestList, PcrSelectSize, PcrSelectionList, PcrSelectionListBuilder
    },
};

use super::{CommandResources, Context, Error, Result};
use crate::types::{
    PcrSelection, PolicyBranchData, PolicyCommand, PolicyData,
    tpm::{Tpm2bDigest, TpmlDigest},
};

impl Context {
    pub(super) fn apply_policy(
        &mut self,
        session: PolicySession,
        policy: &PolicyData,
    ) -> Result<()> {
        self.apply_policy_step(session, policy)
    }

    pub(super) fn restart_policy(&mut self, policy_session: PolicySession) -> Result<()> {
        self.ctx
            .policy_restart(policy_session)
            .map_err(Error::from_tss_err)
    }

    fn get_policy_digest(&mut self, policy_session: PolicySession) -> Result<Tpm2bDigest> {
        self.ctx
            .policy_get_digest(policy_session)
            .map(Into::into)
            .map_err(Error::from_tss_err)
    }

    pub(in super::super) fn compute_auth_policy(
        &mut self,
        policy: &mut PolicyData,
    ) -> Result<Tpm2bDigest> {
        let mut resources = CommandResources::default();

        let result = (|| {
            let policy_session = self
                .start_auth_session(&mut resources, SessionType::Trial, None)
                .map(|session| {
                    session
                        .try_into()
                        .expect("session must be a policy session")
                })?;
            let mut prefix = Vec::new();
            self.apply_trial_policy(policy_session, policy, &mut prefix)?;

            let auth_policy = self.get_policy_digest(policy_session)?;
            resources.flush_sessions(self)?;

            Ok(auth_policy)
        })();

        self.finalize_command(result, &mut resources)
    }

    fn apply_policy_pcr(&mut self, session: PolicySession, selection: &PcrSelection) -> Result<()> {
        let hash_alg = HashingAlgorithm::from(selection.hash_alg());
        let selected_slots = selection
            .slots()
            .iter()
            .copied()
            .map(Into::into)
            .collect::<Vec<_>>();
        let size_of_select = PcrSelectSize::try_parse_usize(selection.select_bytes().len())
            .expect("PCR select size must be between 1 and 3 bytes");

        let selection_list = PcrSelectionListBuilder::new()
            .with_selection(hash_alg, &selected_slots)
            .with_size_of_select(size_of_select)
            .build()
            .map_err(|e| {
                Error::invalid_state(format!("failed to build PCR selection list: {e:#}"))
            })?;
        let digest = self.compute_pcr_digest(selection_list.clone(), hash_alg)?;

        self.ctx
            .policy_pcr(session, digest.into(), selection_list)
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
        digests: &TpmlDigest,
        selected_branch: &PolicyData,
    ) -> Result<()> {
        self.apply_policy_step(session, selected_branch)?;
        self.execute_policy_or(session, digests)
    }

    fn execute_policy_or(&mut self, session: PolicySession, digests: &TpmlDigest) -> Result<()> {
        let mut digest_list = DigestList::new();

        for digest in digests.items() {
            digest_list
                .add(Digest::from(digest.clone()))
                .expect("TpmlDigest must contain at most 8 items");
        }

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

    fn compute_pcr_digest(
        &mut self, 
        selection_list: PcrSelectionList,
        hash: HashingAlgorithm,
    ) -> Result<Tpm2bDigest> {
        let mut hasher = Sha256::new();
        let mut update_counter = None;
        let mut remaining = selection_list;

        while !remaining.is_empty() {
            let (counter, returned_selection, digest_list) =
                self
                    .ctx
                    .pcr_read(remaining.clone())
                    .map_err(Error::from_tss_err)?;

            match update_counter {
                Some(expected_counter) if expected_counter != counter => {
                    return Err(Error::authorization_failed("PCR value changed during read"));
                }
                None => update_counter = Some(counter),
                _ => {}
            }

            let Some(returned_select) = returned_selection
                .get_selections()
                .iter()
                .find(|selection| selection.hashing_algorithm() == hash)
            else {
                debug!("requested PCR hash bank is missing");
                return Err(Error::InvalidData);
            };

            if returned_select.is_empty() {
                return Err(Error::unsupported(
                    "requested PCR selection is unavailable"
                ));
            }

            for digest in digest_list.value() {
                hasher.update(digest.value());
            }

            remaining
                .subtract(&returned_selection)
                .map_err(|e| {
                    Error::invalid_state(format!(
                        "failed to update remaining PCR selection: {e:#}"
                    ))
                })?;
        }

        hasher.finalize().to_vec().try_into()
    }

    fn apply_policy_step(&mut self, session: PolicySession, policy: &PolicyData) -> Result<()> {
        match policy {
            PolicyData::Pcr(selection) => self.apply_policy_pcr(session, selection),
            PolicyData::Command(command) => self.apply_policy_command_code(session, *command),
            PolicyData::AuthValue => self.apply_policy_auth(session),
            PolicyData::Password => self.apply_policy_password(session),
            PolicyData::Or { .. } => {
                let (digests, selected_branch) = policy.selected_branch()?;
                self.apply_policy_or(session, digests, selected_branch)
            }
            PolicyData::Sequence(steps) => self.apply_sequence_steps(session, steps),
        }
    }

    fn apply_trial_policy(
        &mut self,
        session: PolicySession,
        policy: &mut PolicyData,
        prefix: &mut Vec<PolicyData>,
    ) -> Result<()> {
        match policy {
            PolicyData::Sequence(steps) => {
                for step in steps {
                    self.apply_trial_policy(session, step, prefix)?;
                }
            }
            PolicyData::Or { branches, .. } => {
                let digests = self.policy_or_for_trial(session, branches, prefix)?;
                let digests = policy.set_branch_digests(digests)?;
                self.execute_policy_or(session, digests)?;
                prefix.push(policy.clone());
            }
            _ => {
                self.apply_policy_step(session, policy)?;
                prefix.push(policy.clone());
            }
        }

        Ok(())
    }

    fn policy_or_for_trial(
        &mut self,
        session: PolicySession,
        branches: &mut [PolicyBranchData],
        prefix: &[PolicyData],
    ) -> Result<TpmlDigest> {
        let (first_branch, remaining_branches) = branches
            .split_first_mut()
            .expect("normalized PolicyOR must contain at least two branches");
        let mut branch_prefix = prefix.to_vec();
        self.apply_trial_policy(session, &mut first_branch.policy, &mut branch_prefix)?;

        let mut digests = vec![self.get_policy_digest(session)?];
        for branch in remaining_branches {
            let mut branch_path = prefix.to_vec();
            branch_path.push(branch.policy.clone());
            let mut branch_path = PolicyData::Sequence(branch_path);

            digests.push(self.compute_auth_policy(&mut branch_path)?);

            let PolicyData::Sequence(mut steps) = branch_path else {
                unreachable!("branch path must be a policy sequence");
            };
            branch.policy = steps
                .pop()
                .expect("branch path must contain the branch policy");
        }

        let mut remaining_digests = digests.into_iter();
        let mut digest_list = TpmlDigest::try_from(
            remaining_digests
                .by_ref()
                .take(TpmlDigest::MAX_COUNT)
                .collect::<Vec<_>>(),
        )?;

        while remaining_digests.len() != 0 {
            self.execute_policy_or(session, &digest_list)?;

            let mut next = vec![self.get_policy_digest(session)?];
            next.extend(remaining_digests.by_ref().take(TpmlDigest::MAX_COUNT - 1));
            digest_list = TpmlDigest::try_from(next)?;
        }

        Ok(digest_list)
    }
}
