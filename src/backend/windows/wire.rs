use tracing::debug;

use super::{
    TpmRc,
    commands::{
        Command, CommandHeader, ResponseHeader, TpmSt, TpmiStCommandTag, 
        TpmsAuthCommand, TpmsAuthResponse,
    },
    types::{
        TpmtRsaDecrypt, Tpm2bCreationData, Tpm2bData, Tpm2bNonce,
        TpmaLocality, TpmsCreationData, TpmsSensitiveCreate, TpmtTkCreation,
        TpmSe, Tpm2bEncryptedSecret
    },
};
use crate::{
    error::{Error, Result}, 
    types::tpm::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bSensitiveData, TpmAlgId, TpmCap, TpmCc, 
        TpmEccCurve, TpmHandle, TpmMarshal, TpmPt, TpmPtPcr, TpmUnmarshal, TpmaAlgorithm, TpmaCc, 
        TpmaSession, TpmiAlgHash, TpmiRhHierarchy, TpmlAlgProperty, TpmlCc, TpmlCca, TpmlEccCurve, 
        TpmlHandle, TpmlPcrSelection, TpmlTaggedPcrProperty, TpmlTaggedTpmProperty, TpmsAlgProperty, 
        TpmsEmpty, TpmsPcrSelection, TpmsTaggedPcrSelect, TpmsTaggedProperty, TpmuRsaScheme, 
        ensure_consumed, marshal_list, marshal_tpm2b, read_tpm2b, read_vec, unmarshal_list,
    },
};

impl<'a> TpmMarshal for Command<'_> {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        let handles = self.handles();
        let authorization_area = self.authorization_area();
        let parameters = self.parameters();

        let mut authorization_bytes = Vec::new();
        for authorization in authorization_area {
            authorization.marshal(&mut authorization_bytes)?;
        }

        let authorization_size = if authorization_bytes.is_empty() {
            None
        } else {
            Some(
                u32::try_from(authorization_bytes.len())
                    .map_err(|_| Error::invalid_state(
                        "authorization area length exceeds u32::MAX"
                    ))?,
            )
        };

        let command_size = CommandHeader::SIZE
            + handles.len() * size_of::<u32>()
            + parameters.len()
            + authorization_size
                .map(|_| size_of::<u32>() + authorization_bytes.len())
                .unwrap_or_default();
        let command_size = u32::try_from(command_size)
            .map_err(|_| Error::invalid_state("TPM command length exceeds u32::MAX"))?;

        let header = self.header();
        header.tag().marshal(buf)?;
        command_size.marshal(buf)?;
        header.command_code().marshal(buf)?;

        for handle in handles {
            handle.marshal(buf)?;
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
        self.session_handle().marshal(buf)?;
        self.nonce().marshal(buf)?;
        self.session_attributes().bits().marshal(buf)?;
        self.hmac().marshal(buf)?;

        Ok(())
    }
}

impl TpmMarshal for TpmsEmpty {
    fn marshal(&self, _buf: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }
}

impl TpmMarshal for TpmSe {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        buf.push(*self as u8);
        Ok(())
    }
}

impl TpmMarshal for TpmCap {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.value().marshal(buf)
    }
}

impl TpmMarshal for TpmtRsaDecrypt {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        let (scheme, details) = self.parts();
        scheme.marshal(buf)?;
        details.marshal(buf)?;

        Ok(())
    }
}

impl TpmMarshal for TpmuRsaScheme {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Oaep(scheme_hash)
            | Self::RsaPss(scheme_hash)
            | Self::RsaSsa(scheme_hash) => scheme_hash.hash_alg.marshal(buf),
            Self::RsaEs(empty) => empty.marshal(buf),
            Self::Null => Ok(()),
        }
    }
}

impl TpmMarshal for TpmsSensitiveCreate {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.user_auth.marshal(buf)?;
        self.data.marshal(buf)?;

        Ok(())
    }
}

impl TpmMarshal for TpmsCreationData {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.pcr_select().marshal(buf)?;
        self.pcr_digest().marshal(buf)?;
        self.locality().bits().marshal(buf)?;
        self.parent_name_alg().marshal(buf)?;
        self.parent_name().marshal(buf)?;
        self.parent_qualified_name().marshal(buf)?;
        self.outside_info().marshal(buf)?;

        Ok(())
    }
}

impl TpmMarshal for Tpm2bEncryptedSecret {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        marshal_tpm2b(buf, self.as_inner().value())
    }
}

impl TpmMarshal for TpmlPcrSelection {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        marshal_list(buf, self.items(), |buf, selection| {
            let pcr_select = selection.pcr_select();
            let size_of_select = u8::try_from(pcr_select.len())
                .map_err(|_| Error::invalid_state(
                    "TPMS_PCR_SELECTION sizeofSelect exceeds u8::MAX"
                ))?;

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

impl TpmUnmarshal for ResponseHeader {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let tag = TpmiStCommandTag::try_from(u16::unmarshal(input)?)?;
        let response_size = u32::unmarshal(input)?;
        let response_code = TpmRc::from(u32::unmarshal(input)?);

        Ok(Self {
            tag,
            response_size,
            response_code,
        })
    }
}

impl TpmUnmarshal for TpmsAuthResponse {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let nonce = Tpm2bNonce::unmarshal(input)?;
        let session_attributes =
            TpmaSession::from_bits(u8::unmarshal(input)?).ok_or(Error::InvalidData)?;
        let hmac = Tpm2bAuth::unmarshal(input)?;

        Ok(Self {
            nonce,
            session_attributes,
            hmac,
        })
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
        let pcr_digest = Tpm2bDigest::unmarshal(input)?;
        let locality_value = u8::unmarshal(input)?;
        let locality = TpmaLocality::from_bits(locality_value).ok_or_else(|| {
            debug!(
                value = format_args!("{locality_value:#04x}"),
                "invalid locality attributes"
            );
            Error::InvalidData
        })?;
        let parent_name_alg = TpmAlgId::unmarshal(input)?;
        let parent_name = Tpm2bName::unmarshal(input)?;
        let parent_qualified_name = Tpm2bName::unmarshal(input)?;
        let outside_info = Tpm2bData::unmarshal(input)?;

        Self::new(
            pcr_select,
            pcr_digest,
            locality,
            parent_name_alg,
            parent_name,
            parent_qualified_name,
            outside_info,
        )
        .map_err(|e| {
            debug!("{e:?}");
            Error::InvalidData
        })
    }
}

impl TpmUnmarshal for TpmtTkCreation {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let tag = TpmSt::try_from(u16::unmarshal(input)?)?;
        if tag != TpmSt::CREATION {
            debug!(?tag, "invalid TPMT_TK_CREATION tag");
            return Err(Error::InvalidData)
        }

        let hierarchy = TpmiRhHierarchy::unmarshal(input)?;
        let digest = Tpm2bDigest::unmarshal(input)?;

        Ok(TpmtTkCreation::new(hierarchy, digest))
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

impl TpmUnmarshal for TpmsSensitiveCreate {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let user_auth = Tpm2bAuth::unmarshal(input)?;
        let data = Tpm2bSensitiveData::unmarshal(input)?;

        Ok(Self { user_auth, data })
    }
}

impl TpmUnmarshal for TpmlPcrSelection {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, |input| {
            let hash_alg = TpmiAlgHash::unmarshal(input)?;
            let size_of_select = u8::unmarshal(input)? as usize;
            let pcr_select = read_vec(input, size_of_select)?;

            TpmsPcrSelection::new(hash_alg, pcr_select)
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
            let size_of_select = u8::unmarshal(input)? as usize;
            let pcr_select = read_vec(input, size_of_select)?;

            Ok(TpmsTaggedPcrSelect::new(tag, pcr_select))
        })?;

        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlEccCurve {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, |input| TpmEccCurve::unmarshal(input))?;

        Ok(items.into())
    }
}
