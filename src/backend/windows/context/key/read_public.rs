use tracing::debug;

use super::{Context, codec::ReadPublicResponse, commands::Command};
use crate::{
    Error, Result,
    types::{TpmCc, TpmiDhObject, TpmuPublicId},
};

impl Context {
    pub(crate) fn read_rsa_public_unique(&mut self, handle: TpmiDhObject) -> Result<Vec<u8>> {
        let response = self.read_object_public(handle)?;
        into_rsa_public_unique(response.out_public.unique())
    }

    pub(crate) fn read_object_name(&mut self, handle: TpmiDhObject) -> Result<Vec<u8>> {
        // return type should be Tpm2BName
        self.read_object_public(handle)
            .map(|response| response.name.into_bytes())
    }

    pub(crate) fn validate_object_name(
        &mut self,
        handle: TpmiDhObject,
        expected_name: &[u8],
    ) -> Result<()> {
        let name = self.read_object_name(handle)?;
        validate_name(&name, expected_name)
    }

    fn read_object_public(&mut self, handle: TpmiDhObject) -> Result<ReadPublicResponse> {
        let command = Command::new(TpmCc::READ_PUBLIC).with_handles(vec![handle.into()]);
        let response_body = self.submit(command)?;

        ReadPublicResponse::parse(&response_body)
    }
}

fn into_rsa_public_unique(unique: &TpmuPublicId) -> Result<Vec<u8>> {
    match unique {
        TpmuPublicId::Rsa(public_key) => Ok(public_key.clone().into_bytes()),
        _ => Err(Error::invalid_state("expected RSA public unique")),
    }
}

fn validate_name(name: &[u8], expected_name: &[u8]) -> Result<()> {
    if name != expected_name {
        debug!("stored TPM object name doesn't match");
        return Err(Error::corrupted_store());
    }

    Ok(())
}
