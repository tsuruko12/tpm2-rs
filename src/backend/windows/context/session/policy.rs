use sha2::{Digest, Sha256};
use tracing::debug;

use super::super::{
    Command, CommandResources, Context, PcrReadResponse, PolicyGetDigestResponse,
    response::ensure_no_response_body
};
use crate::{
    Error, Result, backend::windows::{
        context::session::generate_caller_nonce, types::{Tpm2bEncryptedSecret, TpmSe, TpmiShPolicy},
    }, types::{
        PcrSelection, PolicyData,
        tpm::{Tpm2bDigest, TpmCc, TpmMarshal, TpmlDigest, TpmlPcrSelection, TpmsPcrSelection},
    },
};

const RESPONSE_HANDLE_COUNT: usize = 0;

impl Context {
    pub(super) fn apply_policy(
        &mut self, 
        policy_session: TpmiShPolicy, 
        policy: &PolicyData
    ) -> Result<()> {
        self.apply_policy_step(policy_session, TpmSe::Policy, policy)
    }

    pub(in super::super) fn compute_auth_policy(
        &mut self,
        policy: &PolicyData,
    ) -> Result<Tpm2bDigest> {
        let nonce_caller = generate_caller_nonce()?;
        let encrypted_salt = Tpm2bEncryptedSecret::default();

        let mut resources = CommandResources::default();

        let result = (|| {
            let policy_session = self
                .start_auth_session(
                    &mut resources,
                    &nonce_caller,
                    &encrypted_salt,
                    TpmSe::Trial,
                    None,
                )
                .map(|response| {
                    response
                        .session_handle
                        .try_into()
                        .expect("session must be a policy session")
                })?;
            self.apply_trial_policy(policy_session, policy, &mut Vec::new())?;

            let digest = self.get_policy_digest(policy_session)?;
            resources.flush_sessions(self)?;

            Ok(digest)
        })();

        self.cleanup_on_error(result, &mut resources)
    }

    fn get_policy_digest(&mut self, policy_session: TpmiShPolicy) -> Result<Tpm2bDigest> {
            let mut command = Command::new(TpmCc::POLICY_GET_DIGEST)
                .with_handles([policy_session]);

            let response_body = self.submit(
                &mut command, 
                RESPONSE_HANDLE_COUNT, 
                &mut CommandResources::default(),
            )?;
            
            PolicyGetDigestResponse::try_from(response_body)
                .map(|response| response.policy_digest)
    }

    fn apply_policy_pcr(
        &mut self, 
        policy_session: TpmiShPolicy, 
        selection: PcrSelection,
    ) -> Result<()> {
        let selection = TpmsPcrSelection::from(selection);
        let pcrs = TpmlPcrSelection::from(vec![selection.clone()]);
        let pcr_digest = self.compute_pcr_digest(selection)?;

        let mut command_params = Vec::new();
        pcr_digest.marshal(&mut command_params)?;
        pcrs.marshal(&mut command_params)?;

        let mut command = Command::new(TpmCc::POLICY_PCR)
            .with_handles([policy_session])
            .with_parameters(&mut command_params);

        self.submit(
            &mut command,
            RESPONSE_HANDLE_COUNT,
            &mut CommandResources::default(),
        )
        .and_then(|response_body| ensure_no_response_body(&response_body))
    }

    fn apply_policy_command_code(
        &mut self, 
        policy_session: TpmiShPolicy, 
        command_code: TpmCc
    ) -> Result<()> {
        let mut command_params = Vec::new();
        command_code.marshal(&mut command_params)?;

        let mut command = Command::new(TpmCc::POLICY_COMMAND_CODE)
            .with_handles([policy_session])
            .with_parameters(&mut command_params);

        self.submit(
            &mut command,
            RESPONSE_HANDLE_COUNT,
            &mut CommandResources::default(),
        )
        .and_then(|response_body| ensure_no_response_body(&response_body))
    }

    fn apply_policy_auth(&mut self, policy_session: TpmiShPolicy) -> Result<()> {
        let mut command = Command::new(TpmCc::POLICY_AUTH_VALUE)
            .with_handles([policy_session]);

        self.submit(
            &mut command,
            RESPONSE_HANDLE_COUNT,
            &mut CommandResources::default(),
        )
        .and_then(|response_body| ensure_no_response_body(&response_body))
    }

    fn apply_policy_password(&mut self, policy_session: TpmiShPolicy) -> Result<()> {
        let mut command = Command::new(TpmCc::POLICY_PASSWORD)
            .with_handles([policy_session]);

        self.submit(
            &mut command,
            RESPONSE_HANDLE_COUNT,
            &mut CommandResources::default(),
        )
        .and_then(|response_body| ensure_no_response_body(&response_body))
    }

    fn apply_policy_or(
        &mut self,
        policy_session: TpmiShPolicy,
        session_type: TpmSe,
        p_hash_list: &TpmlDigest,
        selected_branch: &PolicyData,
    ) -> Result<()> {
        self.apply_policy_step(policy_session, session_type, selected_branch)?;

        self.submit_policy_or(policy_session, p_hash_list)
    }

    fn submit_policy_or(
        &mut self,
        policy_session: TpmiShPolicy,
        p_hash_list: &TpmlDigest,
    ) -> Result<()> {
        let mut command_params = Vec::new();
        p_hash_list.marshal(&mut command_params)?;

        let mut command = Command::new(TpmCc::POLICY_OR)
            .with_handles([policy_session])
            .with_parameters(&mut command_params);

        self.submit(
            &mut command,
            RESPONSE_HANDLE_COUNT,
            &mut CommandResources::default(),
        )
        .and_then(|response_body| ensure_no_response_body(&response_body))
    }

    fn apply_sequence_steps(
        &mut self, 
        policy_session: TpmiShPolicy, 
        session_type: TpmSe,
        steps: &[PolicyData]
    ) -> Result<()> {
        for step in steps {
            if matches!(step, PolicyData::Sequence(_)) {
                return Err(Error::invalid_state("unexpected nested policy sequence"));
            }
            self.apply_policy_step(policy_session, session_type, step)?;
        }

        Ok(())
    }

    fn compute_pcr_digest(&mut self, selection: TpmsPcrSelection) -> Result<Tpm2bDigest> {
        let mut hasher = Sha256::new();
        let mut update_counter = None;
        let mut remaining = selection.pcr_select().to_vec();

        let hash = selection.hash();

        while remaining.iter().any(|&byte| byte != 0) {
            let pcr_selection_in = TpmlPcrSelection::from(vec![
                TpmsPcrSelection::new(hash, remaining.clone())?
            ]);
            let response = self.read_pcr(&pcr_selection_in)?;

            match update_counter {
                Some(expected) if expected != response.pcr_update_counter => {
                    return Err(Error::authorization_failed(
                        "PCR value changed during read",
                    ));
                }
                None => {
                    update_counter = Some(response.pcr_update_counter);
                }
                _ => {}
            }

            let Some(returned_select) = response
                .pcr_selection_out
                .select_for_hash(hash) 
            else {
                debug!("requested hash bank is missing");
                return Err(Error::InvalidData);
            };
            if returned_select.iter().all(|&byte| byte == 0) {
                return Err(Error::unsupported(
                    "requested PCR selection is unavailable",
                ));
            }

            for (remaining, &returned) in remaining.iter_mut().zip(returned_select) {
                *remaining &= !returned;
            }

            for digest in response.pcr_values.items() {
                hasher.update(digest.as_bytes());
            }
        }

        hasher.finalize().to_vec().try_into()
    }

    fn read_pcr(&mut self, pcr_selection_in: &TpmlPcrSelection) -> Result<PcrReadResponse> {
        let mut command_params = Vec::new();
        pcr_selection_in.marshal(&mut command_params)?;

        let mut command = Command::new(TpmCc::PCR_READ)
            .with_parameters(&mut command_params);

        let response_body = self.submit(
            &mut command, 
            RESPONSE_HANDLE_COUNT,
            &mut CommandResources::default()
        )?;
        PcrReadResponse::try_from(response_body)
    }

    fn apply_policy_step(
        &mut self, 
        policy_session: TpmiShPolicy,
        session_type: TpmSe,
        policy: &PolicyData
    ) -> Result<()> {
        match policy {
            PolicyData::Pcr(selection) => self.apply_policy_pcr(policy_session, selection.clone()),
            PolicyData::Command(command) => {
                self.apply_policy_command_code(policy_session, (*command).into())
            }
            PolicyData::AuthValue => self.apply_policy_auth(policy_session),
            PolicyData::Password => self.apply_policy_password(policy_session),
            PolicyData::Or { .. } => {
                if session_type == TpmSe::Trial {
                    self.apply_trial_policy(policy_session, policy, &mut Vec::new())
                } else {
                    let (digests, selected_branch) = policy.selected_or_branch()?;
                    self.apply_policy_or(policy_session, session_type, digests, selected_branch)
                }
            }
            PolicyData::Sequence(steps) => {
                self.apply_sequence_steps(policy_session, session_type, steps)
            }
        }
    }

    fn apply_trial_policy(
        &mut self,
        policy_session: TpmiShPolicy,
        policy: &PolicyData,
        prefix: &mut Vec<PolicyData>,
    ) -> Result<()> {
        match policy {
            PolicyData::Sequence(steps) => {
                for step in steps {
                    self.apply_trial_policy(policy_session, step, prefix)?;
                }
            }
            PolicyData::Or { .. } => {
                self.policy_or_for_trial(policy_session, policy, prefix)?;
                prefix.push(policy.clone());
            }
            _ => {
                self.apply_policy_step(policy_session, TpmSe::Trial, policy)?;
                prefix.push(policy.clone());
            }
        }

        Ok(())
    }

    fn policy_or_for_trial(
        &mut self, 
        policy_session: TpmiShPolicy, 
        policy: &PolicyData,
        prefix: &[PolicyData],
    ) -> Result<()> {
        let PolicyData::Or { branches, .. } = policy else {
            return Err(Error::invalid_state("expected PolicyOR"));
        };

        let mut digests = Vec::with_capacity(branches.len());
        for branch in branches {
            let mut branch_path = prefix.to_vec();
            branch_path.push(branch.clone());
            digests.push(self.compute_auth_policy(&PolicyData::Sequence(branch_path))?);
        }

        let p_hash_list = TpmlDigest::try_from(digests)?;
        self.submit_policy_or(policy_session, &p_hash_list)
    }
}
