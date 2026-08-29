use tss_esapi::{
    structures::{Public, PublicKeyRsa}, traits::{Marshall, UnMarshall}
};

use crate::{
    Error, Result,
    types::tpm::{
        Tpm2bPublic, Tpm2bPublicKeyRsa, TpmMarshal, TpmUnmarshal, TpmtPublic
    },
};

impl TryFrom<&Public> for Tpm2bPublic {
    type Error = Error;

    fn try_from(public: &Public) -> Result<Self> {
        to_tpm2b_public(public)
    }
}

impl TryFrom<Public> for Tpm2bPublic {
    type Error = Error;

    fn try_from(public: Public) -> Result<Self> {
        to_tpm2b_public(&public)
    }
}

fn to_tpm2b_public(public: &Public) -> Result<Tpm2bPublic> {
    let public_area_bytes = public
        .marshall()
        .map_err(|e| Error::invalid_state(
            format!("failed to marshal tss-esapi public: {e:?}")
        ))?;
    let mut input = public_area_bytes.as_slice();

    Ok(TpmtPublic::unmarshal(&mut input)?.into())
}

impl TryFrom<&Tpm2bPublic> for Public {
    type Error = Error;

    fn try_from(public: &Tpm2bPublic) -> Result<Self> {
        to_esapi_public(public)
    }
}

impl TryFrom<Tpm2bPublic> for Public {
    type Error = Error;

    fn try_from(public: Tpm2bPublic) -> Result<Self> {
        to_esapi_public(&public)
    }
}

fn to_esapi_public(public: &Tpm2bPublic) -> Result<Public> {
    let mut public_area_bytes = Vec::new();
    public.as_inner().marshal(&mut public_area_bytes)?;

    Public::unmarshall(&public_area_bytes)
        .map_err(|e| {
            Error::invalid_state(format!(
                "failed to unmarshal tss-esapi public: {e:?}"
            ))
        })
}

impl From<Tpm2bPublicKeyRsa> for PublicKeyRsa {
    fn from(public_key: Tpm2bPublicKeyRsa) -> Self {
        public_key
            .as_bytes()
            .try_into()
            .expect("Tpm2bPublicKeyRsa must be valid for PublicKeyRsa")
    }
}

impl From<PublicKeyRsa> for Tpm2bPublicKeyRsa {
    fn from(public_key: PublicKeyRsa) -> Self {
        public_key
            .value()
            .try_into()
            .expect("PublicKeyRsa must be valid for Tpm2bPublicKeyRsa")
    }
}

