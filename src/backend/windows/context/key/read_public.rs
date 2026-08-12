use tracing::debug;

use super::{Context, codec::ReadPublicResponse, commands::Command};
use crate::{
    Error, Result,
    types::{TpmCc, TpmiDhObject, TpmuPublicId, Tpm2bName},
};

impl Context {
    pub(crate) fn read_rsa_public_unique(&mut self, obj_handle: TpmiDhObject) -> Result<Vec<u8>> {
        let response = self.read_object_public(obj_handle)?;
        into_rsa_public_unique(response.out_public.unique())
    }

    pub(crate) fn validate_obj_name(
        &mut self,
        obj_handle: impl Into<TpmiDhObject>,
        expected_name: &Tpm2bName,
        name: Option<&Tpm2bName>,
    ) -> Result<()> {
        match name {
            Some(name) => validate_name(name.as_bytes(), expected_name.as_bytes()),
            None => {
                let name = self.read_obj_name(obj_handle.into())?;
                validate_name(name.as_bytes(), expected_name.as_bytes())
            }
        }
    }

    pub(crate) fn read_obj_name(&mut self, obj_handle: TpmiDhObject) -> Result<Vec<u8>> {
        self.read_object_public(obj_handle)
            .map(|response| response.name.into_bytes())
    }

    fn read_obj_public(&mut self, obj_handle: TpmiDhObject) -> Result<ReadPublicResponse> {
        let command = Command::new(TpmCc::READ_PUBLIC)
            .with_handles(vec![obj_handle.into()]);
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
        debug!("stored TPM object name does not match");
        return Err(Error::corrupted_store());
    }

    Ok(())
}
