use tracing::debug;

use super::{Command, CommandResources, Context};
use super::super::ReadPublicResponse;
use crate::{
    Error, Result,
    types::tpm::{Tpm2bName, Tpm2bPublicKeyRsa, TpmCc, TpmiDhObject, TpmuPublicId},
};

const RESPONSE_HANDLE_COUNT: usize = 0;

impl Context {
    pub(in super::super) fn read_rsa_public_unique(
        &mut self,
        obj_handle: TpmiDhObject,
    ) -> Result<Tpm2bPublicKeyRsa> {
        let response = self.read_obj_public(obj_handle)?;
        into_rsa_public_unique(response.out_public.into_inner().unique().clone())
    }

    pub(in super::super) fn read_obj_name(
        &mut self,
        obj_handle: TpmiDhObject,
    ) -> Result<Tpm2bName> {
        self.read_obj_public(obj_handle)
            .map(|response| response.name)
    }

    pub(super) fn read_obj_public(
        &mut self,
        obj_handle: TpmiDhObject,
    ) -> Result<ReadPublicResponse> {
        let mut command = Command::new(TpmCc::READ_PUBLIC).with_handles([obj_handle]);

        self.submit(
            &mut command,
            RESPONSE_HANDLE_COUNT,
            &mut CommandResources::default(),
        )
        .and_then(ReadPublicResponse::try_from)
    }
}

fn into_rsa_public_unique(unique: TpmuPublicId) -> Result<Tpm2bPublicKeyRsa> {
    match unique {
        TpmuPublicId::Rsa(public_key) => Ok(public_key),
        _ => Err(Error::invalid_state("expected RSA public unique")),
    }
}

pub(super) fn validate_obj_name(name: &[u8], expected_name: &[u8]) -> Result<()> {
    if name != expected_name {
        debug!("stored TPM object name does not match");
        return Err(Error::corrupted_store())
    }

    Ok(())
}
