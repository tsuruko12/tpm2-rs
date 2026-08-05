use tracing::error;

use super::super::{
    codec::read_tpm2b_exact,
    commands::TpmsAuthResponse,
    types::{
        Tpm2bCreationData, Tpm2bName, Tpm2bNonce, Tpm2bPrivate, TpmiShAuthSession,
        TpmlDigest, TpmtTkCreation,
    },
};
use super::{TpmUnmarshal, ensure_consumed, read_tpm2b, read_u8, read_u32, read_vec};
use crate::{
    Error, Result,
    types::{
        CapabilityData, Tpm2bDigest, TpmCap, TpmHandle, TpmlAlgProperty, TpmlCc, TpmlCca,
        TpmlEccCurve, TpmlHandle, TpmlPcrSelection, TpmlTaggedPcrProperty, TpmlTaggedTpmProperty,
        TpmtPublic, Tpm2bPublic, 
    },
};

pub(crate) fn parse_response_params_and_authorizations(
    bytes: &mut &[u8],
    auth_count: usize,
) -> Result<(Vec<u8>, Vec<TpmsAuthResponse>)> {
    let param_size = usize::try_from(read_u32(bytes)?).map_err(|_| Error::InvalidData)?;
    let params = read_vec(bytes, param_size)?;

    let mut authorizations = Vec::with_capacity(auth_count);

    for _ in 0..auth_count {
        authorizations.push(TpmsAuthResponse::unmarshal(bytes)?);
    }

    ensure_consumed(bytes)?;

    Ok((params, authorizations))
}

pub(crate) struct GetRandomResponse {
    pub(crate) parameters: Vec<u8>,
    pub(crate) authorizations: Vec<TpmsAuthResponse>,
}

impl GetRandomResponse {
    pub(crate) fn parse(mut bytes: &[u8], auth_count: usize) -> Result<Self> {
        let (parameters, authorizations) =
            parse_response_params_and_authorizations(&mut bytes, auth_count)?;

        Ok(Self {
            parameters,
            authorizations,
        })
    }

    pub(crate) fn into_parts(self) -> Result<Tpm2bDigest> {
        let mut params = self.parameters.as_slice();
        let random_bytes = Tpm2bDigest::try_from(read_tpm2b_exact(&mut params)?)?;

        Ok(random_bytes)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GetCapabilityResponse {
    pub(crate) more_data: bool,
    pub(crate) capability_data: CapabilityData,
}

impl GetCapabilityResponse {
    pub(crate) fn parse(mut bytes: &[u8], capability: TpmCap) -> Result<Self> {
        let more_data = match read_u8(&mut bytes)? {
            0 => false,
            1 => true,
            value => {
                error!(value, "invalid TPMI_YES_NO value in capability response");
                return Err(Error::InvalidData);
            }
        };
        let returned_capability = TpmCap::try_from(read_u32(&mut bytes)?)?;

        if capability != returned_capability {
            error!(
                requested = ?capability,
                returned = ?returned_capability,
                "unexpected capability type"
            );
            return Err(Error::InvalidData);
        }

        let capability_data = CapabilityData::parse(&mut bytes, returned_capability)?;

        ensure_consumed(bytes)?;

        Ok(Self {
            more_data,
            capability_data,
        })
    }
}

impl CapabilityData {
    pub(crate) fn parse(bytes: &mut &[u8], capability: TpmCap) -> Result<Self> {
        match capability {
            TpmCap::Algorithms => Ok(Self::Algorithms(TpmlAlgProperty::unmarshal(bytes)?)),
            TpmCap::Handles => Ok(Self::Handles(TpmlHandle::unmarshal(bytes)?)),
            TpmCap::Commands => Ok(Self::Commands(TpmlCca::unmarshal(bytes)?)),
            TpmCap::PPCommands => Ok(Self::PpCommands(TpmlCc::unmarshal(bytes)?)),
            TpmCap::AuditCommands => Ok(Self::AuditCommands(TpmlCc::unmarshal(bytes)?)),
            TpmCap::Pcrs => Ok(Self::Pcrs(TpmlPcrSelection::unmarshal(bytes)?)),
            TpmCap::TpmProperties => Ok(Self::TpmProperties(TpmlTaggedTpmProperty::unmarshal(
                bytes,
            )?)),
            TpmCap::PcrProperties => Ok(Self::PcrProperties(TpmlTaggedPcrProperty::unmarshal(
                bytes,
            )?)),
            TpmCap::ECCCurves => Ok(Self::EccCurves(TpmlEccCurve::unmarshal(bytes)?)),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ReadPublicResponse {
    pub(crate) out_public: Tpm2bPublic,
    pub(crate) name: Tpm2bName,
    pub(crate) qualified_name: Tpm2bName,
}

impl ReadPublicResponse {
    pub(crate) fn parse(mut bytes: &[u8]) -> Result<Self> {
        let out_public = Tpm2bPublic::unmarshal(&mut bytes)?;
        let name = Tpm2bName::from(read_tpm2b(&mut bytes)?);
        let qualified_name = Tpm2bName::from(read_tpm2b_exact(bytes)?);

        Ok(Self {
            out_public,
            name,
            qualified_name,
        })
    }
}

pub(crate) struct StartAuthSessionResponse {
    pub(crate) session_handle: TpmiShAuthSession,
    pub(crate) nonce: Tpm2bNonce,
}

impl StartAuthSessionResponse {
    pub(crate) fn parse(mut bytes: &[u8]) -> Result<Self> {
        let session_handle = TpmiShAuthSession::try_from(u32::unmarshal(&mut bytes)?)?;
        let nonce = Tpm2bNonce::from(read_tpm2b_exact(bytes)?);

        Ok(Self {
            session_handle,
            nonce,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PcrReadResponse {
    pub(crate) pcr_update_counter: u32,
    pub(crate) pcr_selection_out: TpmlPcrSelection,
    pub(crate) pcr_values: TpmlDigest,
}

impl PcrReadResponse {
    pub(crate) fn parse(mut bytes: &[u8]) -> Result<Self> {
        let pcr_update_counter = u32::unmarshal(&mut bytes)?;
        let pcr_selection_out = TpmlPcrSelection::unmarshal(&mut bytes)?;
        let pcr_values = TpmlDigest::unmarshal(&mut bytes)?;

        ensure_consumed(bytes)?;

        Ok(Self {
            pcr_update_counter,
            pcr_selection_out,
            pcr_values,
        })
    }
}

pub(crate) struct CreatePrimaryResponse {
    pub(crate) object_handle: TpmHandle,
    pub(crate) parameters: Vec<u8>,
    pub(crate) authorizations: Vec<TpmsAuthResponse>,
}

impl CreatePrimaryResponse {
    pub(crate) fn parse(mut bytes: &[u8], auth_count: usize) -> Result<Self> {
        let object_handle = TpmHandle::unmarshal(&mut bytes)?;
        let (parameters, authorizations) =
            parse_response_params_and_authorizations(&mut bytes, auth_count)?;

        Ok(Self {
            object_handle,
            parameters,
            authorizations,
        })
    }

    pub(crate) fn into_parts(self) -> Result<(TpmHandle, TpmtPublic, Tpm2bName)> {
        let mut params = self.parameters.as_slice();

        let out_public = Tpm2bPublic::unmarshal(&mut params)?;
        let _ = Tpm2bCreationData::unmarshal(&mut params)?;
        let _ = Tpm2bDigest::try_from(read_tpm2b(&mut params)?)?;
        let _ = TpmtTkCreation::unmarshal(&mut params)?;
        let name = Tpm2bName::from(read_tpm2b(&mut params)?);

        ensure_consumed(params)?;

        Ok((self.object_handle, out_public.into(), name))
    }
}

pub(crate) struct CreateResponse {
    pub(crate) parameters: Vec<u8>,
    pub(crate) authorizations: Vec<TpmsAuthResponse>,
}

impl CreateResponse {
    pub(crate) fn parse(mut bytes: &[u8], auth_count: usize) -> Result<Self> {
        let (parameters, authorizations) =
            parse_response_params_and_authorizations(&mut bytes, auth_count)?;

        Ok(Self {
            parameters,
            authorizations,
        })
    }

    pub(crate) fn into_parts(self) -> Result<(Tpm2bPrivate, Tpm2bPublic, Vec<TpmsAuthResponse>)> {
        let mut params = self.parameters.as_slice();

        let out_private = Tpm2bPrivate::from(read_tpm2b(&mut params)?);
        let out_public = Tpm2bPublic::unmarshal(&mut params)?;
        let _ = Tpm2bCreationData::unmarshal(&mut params)?;
        let _ = read_tpm2b(&mut params)?;
        let _ = TpmtTkCreation::unmarshal(&mut params)?;

        ensure_consumed(params)?;

        Ok((out_private, out_public, self.authorizations))
    }
}

pub(crate) struct LoadResponse {
    pub(crate) object_handle: TpmHandle,
    pub(crate) parameters: Vec<u8>,
    pub(crate) authorizations: Vec<TpmsAuthResponse>,
}

impl LoadResponse {
    pub(crate) fn parse(mut bytes: &[u8], auth_count: usize) -> Result<Self> {
        let object_handle = TpmHandle::unmarshal(&mut bytes)?;
        let (parameters, authorizations) =
            parse_response_params_and_authorizations(&mut bytes, auth_count)?;

        Ok(Self {
            object_handle,
            parameters,
            authorizations,
        })
    }

    pub(crate) fn into_parts(self) -> Result<(TpmHandle, Tpm2bName)> {
        let mut params = self.parameters.as_slice();
        let name = Tpm2bName::from(read_tpm2b_exact(&mut params)?);

        ensure_consumed(params)?;

        Ok((self.object_handle, name))
    }
}
