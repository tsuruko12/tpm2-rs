use tracing::debug;

use super::super::{
    commands::{
        Command, ResponseHeader, TPM_HEADER_SIZE, TpmSt, TpmiStCommandTag, TpmsAuthCommand,
        TpmsAuthResponse,
    },
    types::{
        Tpm2bCreationData, Tpm2bData, Tpm2bName, Tpm2bNonce, TpmRc, TpmaLocality,
        TpmaSession, TpmiRhHierarchy, TpmsCreationData, TpmsSensitiveCreate,
        TpmtTkCreation,
    },
};
use crate::{
    error::{Error, Result}, 
    types::{
        Tpm2bAuth, Tpm2bDigest, TpmAlgId, TpmCc, TpmEccCurve, TpmHandle, TpmKeyBits, TpmPt, TpmPtPcr, 
        TpmaAlgorithm, TpmaCc, TpmaObject, TpmiAlgEccScheme, TpmiAlgHash, TpmiAlgKdf, 
        TpmiAlgKeyedHashScheme, TpmiAlgPublic, TpmiAlgRsaScheme, TpmiAlgSymMode, TpmiAlgSymObject, 
        TpmiEccCurve, TpmiRsaKeyBits, TpmlAlgProperty, TpmlCc, TpmlCca, TpmlEccCurve, TpmlHandle, 
        TpmlPcrSelection, TpmlTaggedPcrProperty, TpmlTaggedTpmProperty, TpmsAlgProperty, 
        TpmsEccParms, TpmsEmpty, TpmsKeyedHashParms, TpmsPcrSelection, TpmsRsaParms, 
        TpmsSchemeEcdaa, TpmsSchemeHash, TpmsSchemeXor, TpmsTaggedPcrSelect, TpmsTaggedProperty, 
        TpmtEccScheme, TpmtKdfScheme, TpmtKeyedHashScheme, TpmtPublic, TpmtRsaScheme, 
        TpmtSymDefObject, TpmuEccScheme, TpmuKdfScheme, TpmuPublicId, TpmuPublicParms, 
        TpmuRsaScheme, TpmuSchemeKeyedHash, Tpm2bPublic, TpmMarshal, TpmUnmarshal,
        marshal_list, marshal_tpm2b, read_tpm2b, read_u16, read_u32, read_vec, unmarshal_list,
    },
};

impl TpmMarshal for u8 {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        buf.push(*self);
        Ok(())
    }
}

impl<'a> TpmMarshal for Command<'_> {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        let handles = self.handles();
        let authorizations = self.authorizations();
        let parameters = self.parameters();

        let mut authorization_bytes = Vec::new();

        for authorization in authorizations {
            authorization.marshal(&mut authorization_bytes)?;
        }

        let authorization_size = if authorization_bytes.is_empty() {
            None
        } else {
            Some(
                u32::try_from(authorization_bytes.len())
                    .map_err(|_| Error::invalid_state("authorization area length exceeds u32"))?,
            )
        };

        let command_size = TPM_HEADER_SIZE
            + handles.len() * size_of::<u32>()
            + parameters.len()
            + authorization_size
                .map(|_| size_of::<u32>() + authorization_bytes.len())
                .unwrap_or_default();
        let command_size = u32::try_from(command_size)
            .map_err(|_| Error::invalid_state("TPM command length exceeds u32"))?;

        let header = self.header();
        header.tag().raw().marshal(buf)?;
        command_size.marshal(buf)?;
        header.command_code().raw().marshal(buf)?;

        for handle in handles {
            handle.raw().marshal(buf)?;
        }

        if let Some(authorization_size) = authorization_size {
            authorization_size.marshal(buf)?;
            buf.extend_from_slice(&authorization_bytes);
        }

        buf.extend_from_slice(parameters);

        Ok(())
    }
}

impl TpmMarshal for TpmsAuthCommand {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        let (session_handle, nonce, session_attributes, hmac) = self.as_parts();

        session_handle.raw().marshal(buf)?;
        marshal_tpm2b(buf, nonce.as_bytes())?;
        session_attributes.bits().marshal(buf)?;
        marshal_tpm2b(buf, hmac.as_bytes())?;

        Ok(())
    }
}

impl TpmMarshal for TpmsEmpty {
    fn marshal(&self, _buf: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }
}

impl TpmMarshal for TpmsSensitiveCreate {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        let (auth, data) = self.as_parts();

        marshal_tpm2b(buf, auth.as_bytes())?;
        marshal_tpm2b(buf, data.as_bytes())?;

        Ok(())
    }
}

impl TpmMarshal for TpmsCreationData {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.pcr_select().marshal(buf)?;
        marshal_tpm2b(buf, self.pcr_digest().as_bytes())?;
        self.locality().bits().marshal(buf)?;
        self.parent_name_alg().raw().marshal(buf)?;
        marshal_tpm2b(buf, self.parent_name().as_bytes())?;
        marshal_tpm2b(buf, self.parent_qualified_name().as_bytes())?;
        marshal_tpm2b(buf, self.outside_info().as_bytes())?;

        Ok(())
    }
}

impl TpmMarshal for TpmlPcrSelection {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        marshal_list(buf, self.items(), |buf, selection| {
            let pcr_select = selection.pcr_select();
            let size_of_select = u8::try_from(pcr_select.len())
                .map_err(|_| Error::invalid_state("PCR select size exceeds u8"))?;

            selection.hash().marshal(buf)?;
            size_of_select.marshal(buf)?;
            pcr_select.marshal(buf)?;

            Ok(())
        })
    }
}

impl TpmUnmarshal for TpmEccCurve {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        u16::unmarshal(input)?.try_into()
    }
}

impl TpmUnmarshal for TpmHandle {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        Ok(u32::unmarshal(input)?.into())
    }
}

impl TpmUnmarshal for ResponseHeader {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let tag = TpmiStCommandTag::try_from(u16::unmarshal(input)?)?;
        let response_size = u32::unmarshal(input)?;
        let response_code = TpmRc::from(u32::unmarshal(input)?);

        debug!(
            ?tag,
            response_size,
            ?response_code,
            "unmarshaled TPM response header"
        );

        Ok(ResponseHeader::new(tag, response_size, response_code))
    }
}

impl TpmUnmarshal for TpmsAuthResponse {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let nonce = Tpm2bNonce::from(read_tpm2b(input)?);
        let session_attributes =
            TpmaSession::from_bits(read_u8(input)?).ok_or(Error::InvalidData)?;
        let hmac = Tpm2bAuth::from(read_tpm2b(input)?);

        Ok(Self::new(nonce, session_attributes, hmac))
    }
}

impl TpmUnmarshal for Tpm2bPublic {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let public_area = read_tpm2b(input)?;
        let mut public_area = public_area.as_slice();
        let public = TpmtPublic::unmarshal(&mut public_area)?;
        ensure_consumed(public_area)?;

        Ok(public.into())
    }
}

impl TpmUnmarshal for Tpm2bCreationData {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let data = read_tpm2b(input)?;
        let mut remaining = data.as_slice();
        let creation_data = TpmsCreationData::unmarshal(&mut remaining)?;

        ensure_consumed(remaining)?;

        Ok(creation_data.into())
    }
}

impl TpmUnmarshal for TpmsCreationData {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let pcr_select = TpmlPcrSelection::unmarshal(input)?;
        let pcr_digest = Tpm2bDigest::try_from(read_tpm2b(input)?)?;
        let locality_raw = read_u8(input)?;
        let locality = TpmaLocality::from_bits(locality_raw).ok_or_else(|| {
            debug!(
                value = format_args!("{locality_raw:#04x}"),
                "invalid locality attributes"
            );
            Error::InvalidData
        })?;
        let parent_name_alg = TpmAlgId::try_from(u16::unmarshal(input)?)?;
        let parent_name = Tpm2bName::from(read_tpm2b(input)?);
        let parent_qualified_name = Tpm2bName::from(read_tpm2b(input)?);
        let outside_info = Tpm2bData::from(read_tpm2b(input)?);

        Ok(Self::new(
            pcr_select,
            pcr_digest,
            locality,
            parent_name_alg,
            parent_name,
            parent_qualified_name,
            outside_info,
        ))
    }
}

impl TpmUnmarshal for TpmtTkCreation {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let tag = TpmSt::try_from(u16::unmarshal(input)?)?;
        let hierarchy = TpmiRhHierarchy::try_from(TpmHandle::unmarshal(input)?)?;
        let digest = Tpm2bDigest::try_from(read_tpm2b(input)?)?;

        Ok(TpmtTkCreation::new(tag, hierarchy, digest))
    }
}

impl TpmUnmarshal for TpmlAlgProperty {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, |input| {
            let alg_id = TpmAlgId::unmarshal(input)?;
            let alg_properties = TpmaAlgorithm::from(u32::unmarshal(input)?);

            Ok(TpmsAlgProperty::new(alg_id, alg_properties))
        })?;

        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlHandle {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, |input| TpmHandle::unmarshal(input))?;
        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlCca {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, |input| TpmaCc::try_from(u32::unmarshal(input)?))?;
        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlCc {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, |input| TpmCc::try_from(u32::unmarshal(input)?))?;
        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlPcrSelection {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, |input| {
            let hash_alg = TpmiAlgHash::unmarshal(input)?;
            let size_of_select = read_u8(input)? as usize;
            let pcr_select = read_vec(input, size_of_select)?;

            Ok(TpmsPcrSelection::new(hash_alg, pcr_select))
        })?;

        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlTaggedTpmProperty {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, |input| {
            let property = TpmPt::try_from(u32::unmarshal(input)?)?;
            let value = u32::unmarshal(input)?;

            Ok(TpmsTaggedProperty::new(property, value))
        })?;

        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlTaggedPcrProperty {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, |input| {
            let tag = TpmPtPcr::try_from(u32::unmarshal(input)?)?;
            let size_of_select = read_u8(input)? as usize;
            let pcr_select = read_vec(input, size_of_select)?;

            Ok(TpmsTaggedPcrSelect::new(tag, pcr_select))
        })?;

        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlEccCurve {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, |input| {
            TpmEccCurve::unmarshal(input)
        })?;

        Ok(items.into())
    }
}

pub(crate) fn tpm2b_payload_mut(input: &mut [u8]) -> Result<&mut [u8]> {
    require_len(input, size_of::<u16>())?;

    let size = u16::from_be_bytes([input[0], input[1]]) as usize;
    let end = size_of::<u16>()
        .checked_add(size)
        .ok_or_else(|| Error::invalid_state("TPM2B payload size overflow"))?;

    require_len(input, end)?;

    Ok(&mut input[size_of::<u16>()..end])
}

pub(crate) fn read_tpm2b_exact(input: &[u8]) -> Result<Vec<u8>> {
    let mut slice = input;
    let bytes = read_tpm2b(&mut slice)?;
    ensure_consumed(slice)?;

    Ok(bytes)
}

pub(crate) fn ensure_consumed(input: &[u8]) -> Result<()> {
    if !input.is_empty() {
        debug!(remaining_size = input.len(), "trailing bytes remain");
        return Err(Error::InvalidData);
    }

    Ok(())
}

pub(crate) fn read_u8(input: &mut &[u8]) -> Result<u8> {
    require_len(*input, 1)?;
    let (&value, remaining) = input.split_first().unwrap();

    *input = remaining;

    Ok(value)
}

fn require_len(bytes: &[u8], required: usize) -> Result<()> {
    if bytes.len() < required {
        debug!(
            required_size = required,
            actual_size = bytes.len(),
            "parameter buffer too short"
        );
        return Err(Error::InvalidData);
    }

    Ok(())
}
