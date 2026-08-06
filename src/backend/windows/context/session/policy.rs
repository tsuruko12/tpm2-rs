use sha2::{Digest, Sha256};
use tracing::debug;

use super::super::super::{
    codec::{PcrReadResponse, TpmMarshal, marshal_tpm2b},
    commands::Command,
    macros::reject_trailing_bytes,
    types::{TpmiShPolicy, TpmlDigest},
};
use super::super::Context;
use crate::{
    Error, Result,
    types::{
        PcrSelection, PcrSlot, PolicyData, Tpm2bDigest, TpmCc, TpmHandle, TpmiAlgHash,
        TpmlPcrSelection, TpmsPcrSelection,
    },
};

const PCR_SELECT_SIZE: usize = 3;
const MAX_PCRS_PER_READ: usize = 8;

impl Context {
    pub(super) fn apply_policy(&mut self, handle: TpmiShPolicy, policy: &PolicyData) -> Result<()> {
        self.apply_policy_step(TpmHandle::from(handle), policy)
    }

    fn apply_policy_pcr(&mut self, handle: TpmHandle, selection: &PcrSelection) -> Result<()> {
        let hash = TpmiAlgHash::from(selection.hash_alg());
        let slots = selection.slots();

        let pcr_select = slots_to_pcr_select(slots);
        let selection_list = TpmlPcrSelection::from(vec![TpmsPcrSelection::new(hash, pcr_select)]);

        let digest = self.compute_pcr_digest(hash, slots)?;

        let mut request_params = Vec::new();
        marshal_tpm2b(&mut request_params, digest.as_bytes())?;
        selection_list.marshal(&mut request_params)?;

        let command = Command::new(TpmCc::POLICY_PCR)
            .with_handles([handle])
            .with_parameters(&request_params);

        let response_body = self.submit(command)?;

        if !response_body.is_empty() {
            reject_trailing_bytes!(response_body.len());
        }

        Ok(())
    }

    fn apply_policy_command_code(
        &mut self,
        handle: TpmHandle,
        command_code: impl Into<TpmCc>,
    ) -> Result<()> {
        let mut request_params = Vec::new();
        command_code.into().raw().marshal(&mut request_params)?;

        let command = Command::new(TpmCc::POLICY_COMMAND_CODE)
            .with_handles([handle])
            .with_parameters(&request_params);
        let response_body = self.submit(command)?;

        if !response_body.is_empty() {
            reject_trailing_bytes!(response_body.len());
        }

        Ok(())
    }

    fn apply_policy_auth(&mut self, handle: TpmHandle) -> Result<()> {
        let command = Command::new(TpmCc::POLICY_AUTH_VALUE).with_handles([handle]);

        let response_body = self.submit(command)?;

        if !response_body.is_empty() {
            reject_trailing_bytes!(response_body.len());
        }

        Ok(())
    }

    fn apply_policy_password(&mut self, handle: TpmHandle) -> Result<()> {
        let command = Command::new(TpmCc::POLICY_PASSWORD).with_handles(vec![handle]);

        let response_body = self.submit(command)?;

        if !response_body.is_empty() {
            reject_trailing_bytes!(response_body.len());
        }

        Ok(())
    }

    fn apply_policy_or(
        &mut self,
        handle: TpmHandle,
        digests: &[Tpm2bDigest],
        selected_branch: &PolicyData,
    ) -> Result<()> {
        if matches!(selected_branch, PolicyData::Or { .. }) {
            return Err(Error::invalid_state("unexpected nested PolicyOr"));
        }

        self.apply_policy_step(handle, selected_branch)?;

        let mut request_params = Vec::new();
        TpmlDigest::from(digests).marshal(&mut request_params)?;

        let command = Command::new(TpmCc::POLICY_OR)
            .with_handles([handle])
            .with_parameters(&request_params);

        let response_body = self.submit(command)?;

        if !response_body.is_empty() {
            reject_trailing_bytes!(response_body.len());
        }

        Ok(())
    }

    fn apply_sequence_steps(&mut self, handle: TpmHandle, steps: &[PolicyData]) -> Result<()> {
        for step in steps {
            if matches!(step, PolicyData::Sequence(_)) {
                return Err(Error::invalid_state("unexpected nested policy sequence"));
            }

            self.apply_policy_step(handle, step)?;
        }

        Ok(())
    }

    fn compute_pcr_digest(&mut self, hash: TpmiAlgHash, slots: &[PcrSlot]) -> Result<Tpm2bDigest> {
        let mut hasher = Sha256::new();
        let mut update_counter = None;

        for slots in slots.chunks(MAX_PCRS_PER_READ) {
            let pcr_select = slots_to_pcr_select(slots);
            let selection = TpmlPcrSelection::from(vec![TpmsPcrSelection::new(hash, pcr_select)]);

            let (counter, returned_selection, digest_list) =
                self.read_pcr(&selection).map(|response| {
                    (
                        response.pcr_update_counter,
                        response.pcr_selection_out,
                        response.pcr_values,
                    )
                })?;

            match update_counter {
                Some(expected_counter) => {
                    if expected_counter != counter {
                        return Err(Error::authorization_failed("PCR value changed during read"));
                    }
                }
                None => update_counter = Some(counter),
            }

            if selection != returned_selection {
                debug!("PCR selection does not match requested PCR selection");
                return Err(Error::InvalidData);
            }

            if digest_list.len() != slots.len() {
                debug!("PCR value count does not match requested slots");
                return Err(Error::InvalidData);
            }

            for digest in digest_list.items() {
                hasher.update(digest.as_bytes());
            }
        }

        hasher.finalize().to_vec().try_into()
    }

    fn read_pcr(&mut self, selection: &TpmlPcrSelection) -> Result<PcrReadResponse> {
        let mut request_params = Vec::new();
        selection.marshal(&mut request_params)?;

        let command = Command::new(TpmCc::PCR_READ).with_parameters(&request_params);
        let response_body = self.submit(command)?;

        PcrReadResponse::parse(&response_body)
    }

    fn apply_policy_step(&mut self, handle: TpmHandle, policy: &PolicyData) -> Result<()> {
        match policy {
            PolicyData::Pcr(selection) => self.apply_policy_pcr(handle, selection),
            PolicyData::Command(command) => self.apply_policy_command_code(handle, *command),
            PolicyData::AuthValue => self.apply_policy_auth(handle),
            PolicyData::Password => self.apply_policy_password(handle),
            PolicyData::Or { .. } => {
                let (digests, selected_branch) = policy.selected_or_branch()?;
                self.apply_policy_or(handle, digests, selected_branch)
            }
            PolicyData::Sequence(steps) => self.apply_sequence_steps(handle, steps),
        }
    }
}

fn slots_to_pcr_select(slots: &[PcrSlot]) -> Vec<u8> {
    let mut pcr_select = vec![0u8; PCR_SELECT_SIZE];

    for &slot in slots {
        let slot = slot as usize;
        pcr_select[slot / 8] |= 1 << (slot % 8);
    }

    pcr_select
}
