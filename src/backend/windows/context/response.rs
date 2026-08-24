use tracing::debug;

use super::super::types::{Tpm2bCreationData, Tpm2bNonce, TpmiShAuthSession, TpmtTkCreation};
use super::ResponseBody;
use crate::{
    Error, Result,
    types::tpm::{
        CapabilityData, Tpm2bDigest, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, Tpm2bPublicKeyRsa,
        TpmCap, TpmHandle, TpmUnmarshal, TpmlAlgProperty, TpmlCc, TpmlCca, TpmlDigest,
        TpmlEccCurve, TpmlHandle, TpmlPcrSelection, TpmlTaggedPcrProperty, TpmlTaggedTpmProperty,
        ensure_consumed,
    },
};

pub(super) struct GetRandomResponse {
    pub(super) random_bytes: Tpm2bDigest,
}

impl TryFrom<ResponseBody> for GetRandomResponse {
    type Error = Error;

    fn try_from(response_body: ResponseBody) -> Result<Self> {
        ensure_response_handle_count(&response_body.handles, 0)?;

        let mut parameters = response_body.parameters.as_slice();
        let random_bytes = Tpm2bDigest::unmarshal(&mut parameters)?;
        ensure_consumed(parameters)?;

        Ok(Self { random_bytes })
    }
}

#[derive(Debug, Clone)]
pub(super) struct GetCapabilityResponse {
    pub(super) more_data: bool,
    pub(super) capability_data: CapabilityData,
}

impl GetCapabilityResponse {
    pub(super) fn parse(response_body: ResponseBody, capability: TpmCap) -> Result<Self> {
        ensure_response_handle_count(&response_body.handles, 0)?;

        let mut parameters = response_body.parameters.as_slice();
        let more_data = match u8::unmarshal(&mut parameters)? {
            0 => false,
            1 => true,
            value => {
                debug!(value, "invalid TPMI_YES_NO value");
                return Err(Error::InvalidData);
            }
        };
        let returned_capability = TpmCap::try_from(u32::unmarshal(&mut parameters)?)?;
        if capability != returned_capability {
            debug!(
                requested = ?capability,
                returned = ?returned_capability,
                "unexpected capability type"
            );
            return Err(Error::InvalidData);
        }
        let capability_data = CapabilityData::parse(&mut parameters, returned_capability)?;
        ensure_consumed(parameters)?;

        Ok(Self {
            more_data,
            capability_data,
        })
    }
}

impl CapabilityData {
    pub(super) fn parse(bytes: &mut &[u8], capability: TpmCap) -> Result<Self> {
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
pub(super) struct ReadPublicResponse {
    pub(super) out_public: Tpm2bPublic,
    pub(super) name: Tpm2bName,
    pub(super) qualified_name: Tpm2bName,
}

impl TryFrom<ResponseBody> for ReadPublicResponse {
    type Error = Error;

    fn try_from(response_body: ResponseBody) -> Result<Self> {
        ensure_response_handle_count(&response_body.handles, 0)?;

        let mut parameters = response_body.parameters.as_slice();
        let out_public = Tpm2bPublic::unmarshal(&mut parameters)?;
        let name = Tpm2bName::unmarshal(&mut parameters)?;
        let qualified_name = Tpm2bName::unmarshal(&mut parameters)?;
        ensure_consumed(parameters)?;

        Ok(Self {
            out_public,
            name,
            qualified_name,
        })
    }
}

pub(super) struct StartAuthSessionResponse {
    pub(super) session_handle: TpmiShAuthSession,
    pub(super) nonce_tpm: Tpm2bNonce,
}

impl TryFrom<ResponseBody> for StartAuthSessionResponse {
    type Error = Error;

    fn try_from(response_body: ResponseBody) -> Result<Self> {
        ensure_response_handle_count(&response_body.handles, 1)?;
        let session_handle = TpmiShAuthSession::try_from(response_body.handles[0])?;

        let mut parameters = response_body.parameters.as_slice();
        let nonce_tpm = Tpm2bNonce::unmarshal(&mut parameters)?;
        ensure_consumed(parameters)?;

        Ok(Self {
            session_handle,
            nonce_tpm,
        })
    }
}

#[derive(Debug, Clone)]
pub(super) struct PcrReadResponse {
    pub(super) pcr_update_counter: u32,
    pub(super) pcr_selection_out: TpmlPcrSelection,
    pub(super) pcr_values: TpmlDigest,
}

impl TryFrom<ResponseBody> for PcrReadResponse {
    type Error = Error;

    fn try_from(response_body: ResponseBody) -> Result<Self> {
        ensure_response_handle_count(&response_body.handles, 0)?;

        let mut parameters = response_body.parameters.as_slice();
        let pcr_update_counter = u32::unmarshal(&mut parameters)?;
        let pcr_selection_out = TpmlPcrSelection::unmarshal(&mut parameters)?;
        let pcr_values = TpmlDigest::unmarshal(&mut parameters)?;
        ensure_consumed(parameters)?;

        Ok(Self {
            pcr_update_counter,
            pcr_selection_out,
            pcr_values,
        })
    }
}

pub(super) struct CreatePrimaryResponse {
    pub(super) object_handle: TpmHandle,
    pub(super) out_public: Tpm2bPublic,
    pub(super) creation_data: Tpm2bCreationData,
    pub(super) creation_hash: Tpm2bDigest,
    pub(super) creation_ticket: TpmtTkCreation,
    pub(super) name: Tpm2bName,
}

impl TryFrom<ResponseBody> for CreatePrimaryResponse {
    type Error = Error;

    fn try_from(response_body: ResponseBody) -> Result<Self> {
        ensure_response_handle_count(&response_body.handles, 1)?;
        let object_handle = response_body.handles[0];

        let mut parameters = response_body.parameters.as_slice();
        let out_public = Tpm2bPublic::unmarshal(&mut parameters)?;
        let creation_data = Tpm2bCreationData::unmarshal(&mut parameters)?;
        let creation_hash = Tpm2bDigest::unmarshal(&mut parameters)?;
        let creation_ticket = TpmtTkCreation::unmarshal(&mut parameters)?;
        let name = Tpm2bName::unmarshal(&mut parameters)?;
        ensure_consumed(parameters)?;

        Ok(Self {
            object_handle,
            out_public,
            creation_data,
            creation_hash,
            creation_ticket,
            name,
        })
    }
}

pub(super) struct CreateResponse {
    pub(super) out_private: Tpm2bPrivate,
    pub(super) out_public: Tpm2bPublic,
    pub(super) creation_data: Tpm2bCreationData,
    pub(super) creation_hash: Tpm2bDigest,
    pub(super) creation_ticket: TpmtTkCreation,
}

impl TryFrom<ResponseBody> for CreateResponse {
    type Error = Error;

    fn try_from(response_body: ResponseBody) -> Result<Self> {
        ensure_response_handle_count(&response_body.handles, 0)?;

        let mut parameters = response_body.parameters.as_slice();
        let out_private = Tpm2bPrivate::unmarshal(&mut parameters)?;
        let out_public = Tpm2bPublic::unmarshal(&mut parameters)?;
        let creation_data = Tpm2bCreationData::unmarshal(&mut parameters)?;
        let creation_hash = Tpm2bDigest::unmarshal(&mut parameters)?;
        let creation_ticket = TpmtTkCreation::unmarshal(&mut parameters)?;
        ensure_consumed(parameters)?;

        Ok(Self {
            out_private,
            out_public,
            creation_data,
            creation_hash,
            creation_ticket,
        })
    }
}

pub(super) struct LoadResponse {
    pub(super) object_handle: TpmHandle,
    pub(super) name: Tpm2bName,
}

impl TryFrom<ResponseBody> for LoadResponse {
    type Error = Error;

    fn try_from(response_body: ResponseBody) -> Result<Self> {
        ensure_response_handle_count(&response_body.handles, 1)?;
        let object_handle = response_body.handles[0];

        let mut parameters = response_body.parameters.as_slice();
        let name = Tpm2bName::unmarshal(&mut parameters)?;
        ensure_consumed(parameters)?;

        Ok(Self {
            object_handle,
            name,
        })
    }
}

pub(super) struct PolicyGetDigestResponse {
    pub(super) policy_digest: Tpm2bDigest,
}

impl TryFrom<ResponseBody> for PolicyGetDigestResponse {
    type Error = Error;

    fn try_from(response_body: ResponseBody) -> Result<Self> {
        ensure_response_handle_count(&response_body.handles, 0)?;

        let mut parameters = response_body.parameters.as_slice();
        let policy_digest = Tpm2bDigest::unmarshal(&mut parameters)?;

        Ok(Self { policy_digest })
    }
}

pub(super) struct RsaEncryptResponse {
    pub(super) out_data: Tpm2bPublicKeyRsa,
}

impl TryFrom<ResponseBody> for RsaEncryptResponse {
    type Error = Error;

    fn try_from(response_body: ResponseBody) -> Result<Self> {
        ensure_response_handle_count(&response_body.handles, 0)?;

        let mut parameters = response_body.parameters.as_slice();
        let out_data = Tpm2bPublicKeyRsa::unmarshal(&mut parameters)?;

        Ok(Self { out_data })
    }
}

pub(super) fn ensure_no_response_body(response_body: &ResponseBody) -> Result<()> {
    if response_body.handles.is_empty() && response_body.parameters.is_empty() {
        Ok(())
    } else {
        debug!("expected no response body");
        Err(Error::InvalidData)
    }
}

fn ensure_response_handle_count(handles: &[TpmHandle], expected_count: usize) -> Result<()> {
    if handles.len() == expected_count {
        Ok(())
    } else {
        debug!(
            handle_count = handles.len(),
            expected_count, "unexpected response handle count"
        );
        Err(Error::InvalidData)
    }
}
