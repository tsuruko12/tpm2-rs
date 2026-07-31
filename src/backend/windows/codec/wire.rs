use tracing::{debug, error};

use super::super::{
    commands::{
        Command, ResponseHeader, TPM_HEADER_SIZE, TpmSt, TpmiStCommandTag, TpmsAuthCommand,
        TpmsAuthResponse,
    },
    types::{
        Tpm2bCreationData, Tpm2bData, Tpm2bName, Tpm2bNonce, Tpm2bPublic, TpmRc, TpmaLocality,
        TpmaSession, TpmiRhHierarchy, TpmlDigest, TpmsCreationData, TpmsSensitiveCreate,
        TpmtTkCreation,
    },
};
use crate::{
    error::{Error, Result},
    types::{
        Tpm2bAuth, Tpm2bDigest, TpmAlgId, TpmCc, TpmEccCurve, TpmHandle, TpmKeyBits, TpmPt,
        TpmPtPcr, TpmaAlgorithm, TpmaCc, TpmaObject, TpmiAlgEccScheme, TpmiAlgHash, TpmiAlgKdf,
        TpmiAlgPublic, TpmiAlgRsaScheme, TpmiAlgSymMode, TpmiAlgSymObject, TpmiEccCurve,
        TpmiRsaKeyBits, TpmlAlgProperty, TpmlCc, TpmlCca, TpmlEccCurve, TpmlHandle,
        TpmlPcrSelection, TpmlTaggedPcrProperty, TpmlTaggedTpmProperty, TpmsAlgProperty,
        TpmsEccParms, TpmsPcrSelection, TpmsRsaParms, TpmsSchemeEcdaa, TpmsTaggedPcrSelect,
        TpmsTaggedProperty, TpmtEccScheme, TpmtKdfScheme, TpmtPublic, TpmtRsaScheme,
        TpmtSymDefObject, TpmuEccScheme, TpmuPublicId, TpmuPublicParms,
    },
};

// memo: implement both traits for TpmAlgId and TpmiAlgHash to clearn up code, (TpmsEmpty as well)

pub(crate) trait TpmMarshal {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()>;
}

impl TpmMarshal for u8 {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        buf.push(*self);
        Ok(())
    }
}

impl TpmMarshal for u16 {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        buf.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl TpmMarshal for u32 {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        buf.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl TpmMarshal for [u8] {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        buf.extend_from_slice(self);
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

impl TpmMarshal for TpmtPublic {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        let alg_type = self.alg_type();
        alg_type.raw().marshal(buf)?;

        self.name_alg().raw().marshal(buf)?;
        self.object_attributes().bits().marshal(buf)?;
        marshal_tpm2b(buf, self.auth_policy().as_bytes())?;

        // memo: changed TpmuPublicParms varinants
        match self.parameters() {
            TpmuPublicParms::Ecc(params) => {
                params.marshal(buf)?;
            }
            TpmuPublicParms::Rsa(params) => {
                params.marshal(buf)?;
            } // memo: add the rest branches
        }

        self.unique().marshal(buf)?;

        Ok(())
    }
}

impl TpmMarshal for TpmsRsaParms {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.symmetric().marshal(buf)?;

        let (scheme, hash) = self.scheme().into_parts();
        scheme.raw().marshal(buf)?;
        hash.map(|alg| alg.raw().marshal(buf)).transpose()?;

        self.key_bits().raw().marshal(buf)?;
        self.exponent().marshal(buf)?;

        Ok(())
    }
}

impl TpmMarshal for TpmsEccParms {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.symmetric().marshal(buf)?;

        let (scheme, details) = self.scheme().into_parts();
        scheme.raw().marshal(buf)?;

        match details {
            TpmuEccScheme::Ecdsa(hash)
            | TpmuEccScheme::Ecdh(hash)
            | TpmuEccScheme::Sm2(hash)
            | TpmuEccScheme::EcSchnorr(hash)
            | TpmuEccScheme::EcMqv(hash) => hash.hash_alg.raw().marshal(buf)?,
            TpmuEccScheme::Ecdaa(details) => {
                let (hash_alg, count) = details.into_parts();
                hash_alg.raw().marshal(buf)?;
                count.marshal(buf)?;
            }
            TpmuEccScheme::Null => {}
        }

        self.curve_id().raw().marshal(buf)?;

        let (kdf, hash_alg) = self.kdf().into_parts();
        kdf.raw().marshal(buf)?;
        if let Some(hash_alg) = hash_alg {
            hash_alg.raw().marshal(buf)?;
        }

        Ok(())
    }
}

impl TpmMarshal for TpmtSymDefObject {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.algorithm().raw().marshal(buf)?;
        self.key_bits().raw().marshal(buf)?;
        self.mode().raw().marshal(buf)?;

        Ok(())
    }
}

impl TpmMarshal for TpmuPublicId {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Ecc(point) => {
                let (x, y) = point.as_parts();
                marshal_tpm2b(buf, x.as_bytes())?;
                marshal_tpm2b(buf, y.as_bytes())?;
            }
            Self::Rsa(public_key) => marshal_tpm2b(buf, public_key.as_bytes())?,
        }

        Ok(())
    }
}

impl TpmMarshal for TpmlPcrSelection {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        marshal_list(buf, self.items(), |buf, selection| {
            let hash = selection.hash();
            let pcr_select = selection.pcr_select();
            let size_of_select = u8::try_from(pcr_select.len())
                .map_err(|_| Error::invalid_state("PCR select size exceeds u8"))?;

            hash.raw().marshal(buf)?;
            size_of_select.marshal(buf)?;
            pcr_select.marshal(buf)?;

            Ok(())
        })
    }
}

impl TpmMarshal for TpmlDigest {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        marshal_list(buf, self.items(), |buf, digest| {
            marshal_tpm2b(buf, digest.as_bytes())
        })
    }
}

pub(crate) trait TpmUnmarshal: Sized {
    fn unmarshal(input: &mut &[u8]) -> Result<Self>;
}

impl TpmUnmarshal for u16 {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        read_u16(input)
    }
}

impl TpmUnmarshal for u32 {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        read_u32(input)
    }
}

impl TpmUnmarshal for TpmHandle {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        Ok(Self::from(u32::unmarshal(input)?))
    }
}

impl TpmUnmarshal for ResponseHeader {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let tag = TpmiStCommandTag::try_from(u16::unmarshal(input)?)?;
        let response_size = u32::unmarshal(input)?;
        let response_code = TpmRc::from(u32::unmarshal(input)?);

        debug!(
            tag = format_args!("{tag:?}"),
            response_size,
            response_code = format_args!("{:#010X}", response_code.raw()),
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
        let mut remaining = public_area.as_slice();

        let alg_type = TpmiAlgPublic::try_from(u16::unmarshal(&mut remaining)?)?;
        let name_alg = TpmiAlgHash::try_from(u16::unmarshal(&mut remaining)?)?;

        let raw = u32::unmarshal(&mut remaining)?;
        let object_attributes = TpmaObject::from_bits(raw).ok_or_else(|| {
            error!(
                value = format_args!("{raw:#010x}"),
                "invalid object attributes"
            );
            Error::InvalidData
        })?;

        let auth_policy = Tpm2bDigest::try_from(read_tpm2b(&mut remaining)?)?;
        // memo: Changed TpmuPublicParms variants
        let (parameters, unique) = match alg_type {
            TpmiAlgPublic::RSA => {
                let parameters = TpmuPublicParms::Rsa(TpmsRsaParms::unmarshal(&mut remaining)?);
                let unique = TpmuPublicId::rsa(read_tpm2b(&mut remaining)?);
                (parameters, unique)
            }
            TpmiAlgPublic::ECC => {
                let parameters = TpmuPublicParms::Ecc(TpmsEccParms::unmarshal(&mut remaining)?);
                let x = read_tpm2b(&mut remaining)?;
                let y = read_tpm2b(&mut remaining)?;
                let unique = TpmuPublicId::ecc(x, y);
                (parameters, unique)
            }
            alg_type => {
                error!(?alg_type, "unsupported TPM public algorithm");
                return Err(Error::InvalidData);
            }
        };

        Ok(Self::from(TpmtPublic::new(
            alg_type,
            name_alg,
            object_attributes,
            auth_policy,
            parameters,
            unique,
        )))
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
            error!(
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

impl TpmUnmarshal for TpmtSymDefObject {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let algorithm = TpmiAlgSymObject::try_from(u16::unmarshal(input)?)?;
        let key_bits = TpmKeyBits::from(u16::unmarshal(input)?);
        let mode = TpmiAlgSymMode::try_from(u16::unmarshal(input)?)?;

        Ok(Self::new(algorithm, key_bits, mode))
    }
}

impl TpmUnmarshal for TpmsRsaParms {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let symmetric = TpmtSymDefObject::unmarshal(input)?;
        let scheme = TpmiAlgRsaScheme::try_from(u16::unmarshal(input)?)?;

        // memo: changed TpmtRsaScheme so refactor this
        let scheme = match scheme {
            TpmiAlgRsaScheme::RSA_SSA => {
                TpmtRsaScheme::RsaSsa(TpmiAlgHash::try_from(u16::unmarshal(input)?)?)
            }
            TpmiAlgRsaScheme::RSA_ES => TpmtRsaScheme::RsaEs,
            TpmiAlgRsaScheme::RSA_PSS => {
                TpmtRsaScheme::RsaPss(TpmiAlgHash::try_from(u16::unmarshal(input)?)?)
            }
            TpmiAlgRsaScheme::OAEP => {
                TpmtRsaScheme::Oaep(TpmiAlgHash::try_from(u16::unmarshal(input)?)?)
            }
            TpmiAlgRsaScheme::NULL => TpmtRsaScheme::Null,
            _ => unreachable!("TpmiAlgRsaScheme only contains RSA schemes"),
        };

        let key_bits = TpmiRsaKeyBits::from(u16::unmarshal(input)?);
        let exponent = u32::unmarshal(input)?;

        Ok(Self::new(symmetric, scheme, key_bits, exponent))
    }
}

impl TpmUnmarshal for TpmsEccParms {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let symmetric = TpmtSymDefObject::unmarshal(input)?;
        let scheme = match TpmiAlgEccScheme::try_from(u16::unmarshal(input)?)? {
            TpmiAlgEccScheme::ECDSA => {
                TpmtEccScheme::ecdsa(TpmiAlgHash::try_from(u16::unmarshal(input)?)?)
            }
            TpmiAlgEccScheme::ECDH => {
                TpmtEccScheme::ecdh(TpmiAlgHash::try_from(u16::unmarshal(input)?)?)
            }
            TpmiAlgEccScheme::ECDAA => {
                let hash_alg = TpmiAlgHash::try_from(u16::unmarshal(input)?)?;
                let count = u16::unmarshal(input)?;
                TpmtEccScheme::ecdaa(TpmsSchemeEcdaa::new(hash_alg, count))
            }
            TpmiAlgEccScheme::SM2 => {
                TpmtEccScheme::sm2(TpmiAlgHash::try_from(u16::unmarshal(input)?)?)
            }
            TpmiAlgEccScheme::EC_SCHNORR => {
                TpmtEccScheme::ec_schnorr(TpmiAlgHash::try_from(u16::unmarshal(input)?)?)
            }
            TpmiAlgEccScheme::EC_MQV => {
                TpmtEccScheme::ec_mqv(TpmiAlgHash::try_from(u16::unmarshal(input)?)?)
            }
            TpmiAlgEccScheme::NULL => TpmtEccScheme::null(),
            scheme => {
                error!(?scheme, "unsupported TPM ECC scheme");
                return Err(Error::InvalidData);
            }
        };

        let curve_id = TpmiEccCurve::try_from(u16::unmarshal(input)?)?;
        let kdf_scheme = TpmiAlgKdf::try_from(u16::unmarshal(input)?)?;
        let kdf_hash_alg = if kdf_scheme == TpmiAlgKdf::NULL {
            None
        } else {
            Some(TpmiAlgHash::try_from(u16::unmarshal(input)?)?)
        };
        let kdf = TpmtKdfScheme::from_parts(kdf_scheme, kdf_hash_alg)?;

        Ok(Self::with_kdf(symmetric, scheme, curve_id, kdf))
    }
}

impl TpmUnmarshal for TpmtTkCreation {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let tag = TpmSt::try_from(u16::unmarshal(input)?)?;

        let handle = TpmHandle::unmarshal(input)?;
        let hierarchy = TpmiRhHierarchy::try_from(handle)?;

        let digest = Tpm2bDigest::try_from(read_tpm2b(input)?)?;

        Ok(TpmtTkCreation::new(tag, hierarchy, digest))
    }
}

impl TpmUnmarshal for TpmlAlgProperty {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, 6, None, |input| {
            let alg_id = TpmAlgId::try_from(read_u16(input)?)?;
            let alg_properties = TpmaAlgorithm::from(read_u32(input)?);

            Ok(TpmsAlgProperty::new(alg_id, alg_properties))
        })?;

        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlHandle {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, 4, None, |input| TpmHandle::unmarshal(input))?;

        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlCca {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, 4, None, |input| TpmaCc::try_from(read_u32(input)?))?;

        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlCc {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, 4, None, |input| TpmCc::try_from(read_u32(input)?))?;

        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlPcrSelection {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, 3, None, |input| {
            let hash = TpmiAlgHash::try_from(read_u16(input)?)?;
            let size_of_select = read_u8(input)? as usize;
            let pcr_select = read_vec(input, size_of_select)?;

            Ok(TpmsPcrSelection::new(hash, pcr_select))
        })?;

        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlTaggedTpmProperty {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, 8, None, |input| {
            let property = TpmPt::try_from(read_u32(input)?)?;
            let value = read_u32(input)?;

            Ok(TpmsTaggedProperty::new(property, value))
        })?;

        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlTaggedPcrProperty {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, 5, None, |input| {
            let tag = TpmPtPcr::try_from(read_u32(input)?)?;
            let size_of_select = read_u8(input)? as usize;
            let pcr_select = read_vec(input, size_of_select)?;

            Ok(TpmsTaggedPcrSelect::new(tag, pcr_select))
        })?;

        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlEccCurve {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, 2, None, |input| {
            TpmEccCurve::try_from(read_u16(input)?)
        })?;

        Ok(items.into())
    }
}

impl TpmUnmarshal for TpmlDigest {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let items = unmarshal_list(input, 2, Some(8), |input| {
            Tpm2bDigest::try_from(read_tpm2b(input)?)
        })?;

        Ok(items.into())
    }
}

fn marshal_list<T>(
    buf: &mut Vec<u8>,
    items: &[T],
    mut marshal_item: impl FnMut(&mut Vec<u8>, &T) -> Result<()>,
) -> Result<()> {
    let count = u32::try_from(items.len())
        .map_err(|_| Error::invalid_state("TPM list item count exceeds u32"))?;
    count.marshal(buf)?;

    for item in items {
        marshal_item(buf, item)?;
    }

    Ok(())
}

fn unmarshal_list<T>(
    input: &mut &[u8],
    min_item_size: usize,
    max_item_count: Option<usize>,
    mut unmarshal_item: impl FnMut(&mut &[u8]) -> Result<T>,
) -> Result<Vec<T>> {
    let count = u32::unmarshal(input)? as usize;
    validate_count(input.len(), count, min_item_size, max_item_count)?;

    let mut items = Vec::with_capacity(count);

    for _ in 0..count {
        items.push(unmarshal_item(input)?);
    }

    Ok(items)
}

fn validate_count(
    bytes_len: usize,
    count: usize,
    min_item_size: usize,
    max_count: Option<usize>,
) -> Result<()> {
    let min_size = count.checked_mul(min_item_size).ok_or_else(|| {
        error!(
            count,
            min_item_size, "TPM list item count overflow while calculating required size"
        );
        Error::InvalidData
    })?;

    if bytes_len < min_size {
        error!(
            count,
            required_size = min_size,
            actual_size = bytes_len,
            "buffer too short for TPM list item count"
        );
        return Err(Error::InvalidData);
    }

    if let Some(max_count) = max_count {
        if count > max_count {
            error!(
                item_count = count,
                max_count, "TPM list item count exceeds the maximum"
            );
            return Err(Error::InvalidData);
        }
    }

    Ok(())
}

pub(crate) fn marshal_tpm2b<T: TpmMarshal + ?Sized>(buf: &mut Vec<u8>, value: &T) -> Result<()> {
    let mut inner = Vec::new();
    value.marshal(&mut inner)?;

    let size = u16::try_from(inner.len())
        .map_err(|_| Error::invalid_state("TPM2B buffer size exceeds u16"))?;

    size.marshal(buf)?;
    buf.extend_from_slice(&inner);

    Ok(())
}

pub(crate) fn read_tpm2b(input: &mut &[u8]) -> Result<Vec<u8>> {
    read_bytes_for_size(input)
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
    let bytes = read_bytes_for_size(&mut slice)?;
    ensure_consumed(slice)?;

    Ok(bytes)
}

fn read_bytes_for_size(input: &mut &[u8]) -> Result<Vec<u8>> {
    let size = read_u16(input)? as usize;
    read_vec(input, size)
}

pub(crate) fn ensure_consumed(input: &[u8]) -> Result<()> {
    if !input.is_empty() {
        error!(remaining_size = input.len(), "trailing bytes remain");
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

pub(crate) fn read_u16(input: &mut &[u8]) -> Result<u16> {
    require_len(*input, 2)?;
    let bytes = input.get(..2).unwrap();
    let value = u16::from_be_bytes(bytes.try_into().unwrap());

    *input = &input[2..];

    Ok(value)
}

pub(crate) fn read_u32(input: &mut &[u8]) -> Result<u32> {
    require_len(*input, 4)?;
    let bytes = input.get(..4).unwrap();
    let value = u32::from_be_bytes(bytes.try_into().unwrap());

    *input = &input[4..];

    Ok(value)
}

pub(crate) fn read_vec(input: &mut &[u8], len: usize) -> Result<Vec<u8>> {
    require_len(*input, len)?;
    let value = input.get(..len).unwrap();
    let value = value.to_vec();

    *input = &input[len..];

    Ok(value)
}

fn require_len(bytes: &[u8], required: usize) -> Result<()> {
    if bytes.len() < required {
        error!(
            required_size = required,
            actual_size = bytes.len(),
            "parameter buffer too short"
        );
        return Err(Error::InvalidData);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::tpm2b_payload_mut;

    #[test]
    fn tpm2b_payload_excludes_its_size_and_following_bytes() {
        let mut bytes = [0, 3, 1, 2, 3, 4];

        {
            let payload = tpm2b_payload_mut(&mut bytes).unwrap();
            payload.copy_from_slice(&[9, 8, 7]);
        }

        assert_eq!(bytes, [0, 3, 9, 8, 7, 4]);
    }

    #[test]
    fn tpm2b_payload_rejects_a_truncated_value() {
        let mut bytes = [0, 3, 1, 2];

        assert!(tpm2b_payload_mut(&mut bytes).is_err());
    }
}
