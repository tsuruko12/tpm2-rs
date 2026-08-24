use tracing::debug;

use crate::types::tpm::{Tpm2bPublic, TpmsEccPoint};
use crate::{Error, Result};

use super::algorithm::TpmuSymMode;
use super::{
    Tpm2bDigest, Tpm2bPublicKeyRsa, TpmAlgId, TpmKeyBits, TpmaObject, TpmiAlgEccScheme,
    TpmiAlgHash, TpmiAlgKdf, TpmiAlgKeyedHashScheme, TpmiAlgPublic, TpmiAlgRsaScheme,
    TpmiAlgSymMode, TpmiAlgSymObject, TpmiEccCurve, TpmiRsaKeyBits, TpmlDigest, TpmsEccParms,
    TpmsKeyedHashParms, TpmsRsaParms, TpmsSchemeEcdaa, TpmsSchemeHash, TpmsSchemeXor,
    TpmtEccScheme, TpmtKdfScheme, TpmtKeyedHashScheme, TpmtPublic, TpmtRsaScheme, TpmtSymDefObject,
    TpmuEccScheme, TpmuKdfScheme, TpmuPublicId, TpmuPublicParms, TpmuRsaScheme,
    TpmuSchemeKeyedHash,
};

pub(crate) trait TpmMarshal {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()>;
}

pub(crate) trait TpmUnmarshal: Sized {
    fn unmarshal(input: &mut &[u8]) -> Result<Self>;
}

pub(crate) fn marshal_list<T>(
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

pub(crate) fn unmarshal_list<T>(
    input: &mut &[u8],
    mut unmarshal_item: impl FnMut(&mut &[u8]) -> Result<T>,
) -> Result<Vec<T>> {
    let count = u32::unmarshal(input)? as usize;

    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(unmarshal_item(input)?);
    }

    Ok(items)
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

impl TpmMarshal for TpmAlgId {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.value().marshal(buf)
    }
}

impl TpmMarshal for TpmlDigest {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        marshal_list(buf, self.items(), |buf, digest| digest.marshal(buf))
    }
}

impl TpmMarshal for Tpm2bPublic {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        marshal_tpm2b(buf, self.as_inner())
    }
}

impl TpmMarshal for TpmtPublic {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.alg_type().marshal(buf)?;
        self.name_alg().marshal(buf)?;
        self.object_attributes().bits().marshal(buf)?;
        self.auth_policy().marshal(buf)?;
        self.parameters().marshal(buf)?;
        self.unique().marshal(buf)
    }
}

impl TpmMarshal for TpmuPublicParms {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::EccDetail(params) => params.marshal(buf),
            Self::RsaDetail(params) => params.marshal(buf),
            Self::SymDetail(params) => params.sym().marshal(buf),
            Self::KeyedHashDetail(params) => params.marshal(buf),
        }
    }
}

impl TpmMarshal for TpmsRsaParms {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.symmetric().marshal(buf)?;

        let (scheme, details) = self.scheme().into_parts();
        scheme.marshal(buf)?;
        match details {
            TpmuRsaScheme::Oaep(scheme_hash)
            | TpmuRsaScheme::RsaPss(scheme_hash)
            | TpmuRsaScheme::RsaSsa(scheme_hash) => scheme_hash.hash_alg.marshal(buf)?,
            _ => {}
        }

        self.key_bits().value().marshal(buf)?;
        self.exponent().marshal(buf)?;

        Ok(())
    }
}

impl TpmMarshal for TpmsEccParms {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.symmetric().marshal(buf)?;

        let (ecc_scheme, ecc_details) = self.scheme().into_parts();
        ecc_scheme.marshal(buf)?;
        match ecc_details {
            TpmuEccScheme::Ecdsa(scheme_hash)
            | TpmuEccScheme::Ecdh(scheme_hash)
            | TpmuEccScheme::Sm2(scheme_hash)
            | TpmuEccScheme::EcSchnorr(scheme_hash)
            | TpmuEccScheme::EcMqv(scheme_hash) => scheme_hash.hash_alg.marshal(buf)?,
            TpmuEccScheme::Ecdaa(scheme_ecdaa) => {
                scheme_ecdaa.hash_alg.marshal(buf)?;
                scheme_ecdaa.count.marshal(buf)?;
            }
            _ => {}
        }

        self.curve_id().value().marshal(buf)?;

        let (kdf_scheme, kdf_details) = self.kdf().into_parts();
        kdf_scheme.marshal(buf)?;
        match kdf_details {
            TpmuKdfScheme::Kdf1Sp800_56a(scheme_hash)
            | TpmuKdfScheme::Kdf1Sp800_108(scheme_hash)
            | TpmuKdfScheme::Kdf2(scheme_hash)
            | TpmuKdfScheme::Mgf1(scheme_hash) => scheme_hash.hash_alg.marshal(buf)?,
            _ => {}
        }

        Ok(())
    }
}

impl TpmMarshal for TpmsKeyedHashParms {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        let (scheme, details) = self.scheme.into_parts();
        scheme.marshal(buf)?;
        match details {
            TpmuSchemeKeyedHash::Hmac(scheme_hash) => scheme_hash.hash_alg.marshal(buf)?,
            TpmuSchemeKeyedHash::Xor(scheme_xor) => {
                scheme_xor.hash_alg.marshal(buf)?;
                scheme_xor.kdf.marshal(buf)?;
            }
            _ => {}
        }

        Ok(())
    }
}

impl TpmMarshal for TpmtSymDefObject {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        let alg_sym_mode = match (self.algorithm(), self.mode()) {
            (TpmiAlgSymObject::AES, TpmuSymMode::Aes(mode))
            | (TpmiAlgSymObject::SM4, TpmuSymMode::Sm4(mode))
            | (TpmiAlgSymObject::CAMELLIA, TpmuSymMode::Camellia(mode)) => Some(mode),
            (TpmiAlgSymObject::NULL, TpmuSymMode::Null(_)) => None,
            (algorithm, mode) => {
                debug!(
                    ?algorithm,
                    ?mode,
                    "symmetric mode does not match its algorithm"
                );
                return Err(Error::invalid_state(
                    "symmetric mode does not match its algorithm",
                ));
            }
        };
        self.algorithm().marshal(buf)?;

        if let Some(mode) = alg_sym_mode {
            self.key_bits().value().marshal(buf)?;
            mode.marshal(buf)?;
        }

        Ok(())
    }
}

impl TpmMarshal for TpmuPublicId {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Ecc(point) => {
                let (x, y) = point.as_parts();
                x.marshal(buf)?;
                y.marshal(buf)?;

                Ok(())
            }
            Self::Rsa(public_key) => public_key.marshal(buf),
            Self::Sym(digest) | Self::KeyedHash(digest) => digest.marshal(buf),
        }
    }
}

impl TpmUnmarshal for u8 {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        Ok(take(input, 1)?[0])
    }
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

impl TpmUnmarshal for TpmAlgId {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        u16::unmarshal(input)?.try_into()
    }
}

impl TpmUnmarshal for TpmlDigest {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let count = u32::unmarshal(input)? as usize;
        if count > Self::MAX_COUNT {
            debug!(
                item_count = count,
                max_count = TpmlDigest::MAX_COUNT,
                "TPML_DIGEST item count exceeds maximum"
            );
            return Err(Error::InvalidData);
        }

        let mut digests = Vec::with_capacity(count);
        for _ in 0..count {
            digests.push(Tpm2bDigest::unmarshal(input)?);
        }

        TpmlDigest::try_from(digests)
    }
}

impl TpmUnmarshal for TpmsSchemeHash {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        Ok(Self {
            hash_alg: TpmiAlgHash::unmarshal(input)?,
        })
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

impl TpmUnmarshal for TpmtPublic {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let alg_type = TpmiAlgPublic::unmarshal(input)?;
        let name_alg = TpmiAlgHash::unmarshal(input)?;
        let attributes = u32::unmarshal(input)?;
        let object_attributes = TpmaObject::from_bits(attributes).ok_or_else(|| {
            debug!(?attributes, "invalid object attributes");
            Error::InvalidData
        })?;
        let auth_policy = Tpm2bDigest::unmarshal(input)?;
        let (parameters, unique) = match alg_type {
            TpmiAlgPublic::RSA => (
                TpmuPublicParms::RsaDetail(TpmsRsaParms::unmarshal(input)?),
                TpmuPublicId::rsa(Tpm2bPublicKeyRsa::unmarshal(input)?),
            ),
            TpmiAlgPublic::ECC => {
                let parameters = TpmuPublicParms::EccDetail(TpmsEccParms::unmarshal(input)?);
                let x = read_tpm2b(input)?;
                let y = read_tpm2b(input)?;

                (parameters, TpmuPublicId::ecc(TpmsEccPoint::new(x, y)?))
            }
            TpmiAlgPublic::SYM_CIPHER => (
                TpmuPublicParms::SymDetail(TpmtSymDefObject::unmarshal(input)?.into()),
                TpmuPublicId::sym(Tpm2bDigest::unmarshal(input)?),
            ),
            TpmiAlgPublic::KEYED_HASH => (
                TpmuPublicParms::KeyedHashDetail(TpmsKeyedHashParms::unmarshal(input)?),
                TpmuPublicId::keyed_hash(Tpm2bDigest::unmarshal(input)?),
            ),
            _ => {
                debug!(?alg_type, "unsupported TPM public algorithm");
                return Err(Error::InvalidData);
            }
        };

        Ok(Self::new(
            alg_type,
            name_alg,
            object_attributes,
            auth_policy,
            parameters,
            unique,
        ))
    }
}

impl TpmUnmarshal for TpmtSymDefObject {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let algorithm = TpmiAlgSymObject::unmarshal(input)?;
        if algorithm == TpmiAlgSymObject::NULL {
            return Ok(Self::null());
        }
        let key_bits = TpmKeyBits::from(u16::unmarshal(input)?);
        let alg_sym_mode = TpmiAlgSymMode::unmarshal(input)?;
        let mode = match algorithm {
            TpmiAlgSymObject::AES => TpmuSymMode::Aes(alg_sym_mode),
            TpmiAlgSymObject::SM4 => TpmuSymMode::Sm4(alg_sym_mode),
            TpmiAlgSymObject::CAMELLIA => TpmuSymMode::Camellia(alg_sym_mode),
            _ => {
                debug!(?algorithm, "unsupported symmetric object algorithm");
                return Err(Error::InvalidData);
            }
        };

        Ok(Self::new(algorithm, key_bits, mode))
    }
}

impl TpmUnmarshal for TpmsRsaParms {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let symmetric = TpmtSymDefObject::unmarshal(input)?;
        let scheme = TpmiAlgRsaScheme::unmarshal(input)?;

        let scheme = match scheme {
            TpmiAlgRsaScheme::OAEP => TpmtRsaScheme::oaep(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgRsaScheme::RSA_SSA => TpmtRsaScheme::rsa_ssa(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgRsaScheme::RSA_PSS => TpmtRsaScheme::rsa_pss(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgRsaScheme::RSA_ES => TpmtRsaScheme::rsa_es(),
            TpmiAlgRsaScheme::NULL => TpmtRsaScheme::null(),
            _ => {
                debug!(?scheme, "unsupported TPM RSA scheme");
                return Err(Error::InvalidData);
            }
        };

        Ok(Self::new(
            symmetric,
            scheme,
            TpmiRsaKeyBits::from(u16::unmarshal(input)?),
            u32::unmarshal(input)?,
        ))
    }
}

impl TpmUnmarshal for TpmsEccParms {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let symmetric = TpmtSymDefObject::unmarshal(input)?;
        let ecc_scheme = match TpmiAlgEccScheme::unmarshal(input)? {
            TpmiAlgEccScheme::ECDSA => TpmtEccScheme::ecdsa(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgEccScheme::ECDH => TpmtEccScheme::ecdh(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgEccScheme::SM2 => TpmtEccScheme::sm2(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgEccScheme::EC_SCHNORR => {
                TpmtEccScheme::ec_schnorr(TpmsSchemeHash::unmarshal(input)?)
            }
            TpmiAlgEccScheme::EC_MQV => TpmtEccScheme::ec_mqv(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgEccScheme::ECDAA => TpmtEccScheme::ecdaa(TpmsSchemeEcdaa {
                hash_alg: TpmiAlgHash::unmarshal(input)?,
                count: u16::unmarshal(input)?,
            }),
            TpmiAlgEccScheme::NULL => TpmtEccScheme::null(),
            scheme => {
                debug!(?scheme, "unsupported TPM ECC scheme");
                return Err(Error::InvalidData);
            }
        };

        let curve_id = TpmiEccCurve::try_from(u16::unmarshal(input)?)?;
        let kdf_scheme = match TpmiAlgKdf::unmarshal(input)? {
            TpmiAlgKdf::KDF1_SP800_56A => {
                TpmtKdfScheme::kdf1_sp800_56a(TpmsSchemeHash::unmarshal(input)?)
            }
            TpmiAlgKdf::KDF1_SP800_108 => {
                TpmtKdfScheme::kdf1_sp800_108(TpmsSchemeHash::unmarshal(input)?)
            }
            TpmiAlgKdf::KDF2 => TpmtKdfScheme::kdf2(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgKdf::MGF1 => TpmtKdfScheme::mgf1(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgKdf::NULL => TpmtKdfScheme::null(),
            scheme => {
                debug!(?scheme, "unsupported TPM KDF scheme");
                return Err(Error::InvalidData);
            }
        };

        Ok(Self::new(symmetric, ecc_scheme, curve_id, kdf_scheme))
    }
}

impl TpmUnmarshal for TpmsKeyedHashParms {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let scheme = match TpmiAlgKeyedHashScheme::unmarshal(input)? {
            TpmiAlgKeyedHashScheme::HMAC => {
                TpmtKeyedHashScheme::hmac(TpmsSchemeHash::unmarshal(input)?)
            }
            TpmiAlgKeyedHashScheme::XOR => TpmtKeyedHashScheme::xor(TpmsSchemeXor {
                hash_alg: TpmiAlgHash::unmarshal(input)?,
                kdf: TpmiAlgKdf::unmarshal(input)?,
            }),
            TpmiAlgKeyedHashScheme::NULL => TpmtKeyedHashScheme::null(),
            scheme => {
                debug!(?scheme, "unsupported TPM keyed-hash scheme");
                return Err(Error::InvalidData);
            }
        };

        Ok(Self { scheme })
    }
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
    let size = read_u16(input)? as usize;
    read_vec(input, size)
}

pub(crate) fn read_u16(input: &mut &[u8]) -> Result<u16> {
    let bytes = take(input, size_of::<u16>())?;
    Ok(u16::from_be_bytes(
        bytes.try_into().expect("slice has exactly two bytes"),
    ))
}

pub(crate) fn read_u32(input: &mut &[u8]) -> Result<u32> {
    let bytes = take(input, size_of::<u32>())?;
    Ok(u32::from_be_bytes(
        bytes.try_into().expect("slice has exactly four bytes"),
    ))
}

pub(crate) fn read_vec(input: &mut &[u8], len: usize) -> Result<Vec<u8>> {
    Ok(take(input, len)?.to_vec())
}

pub(crate) fn ensure_consumed(input: &[u8]) -> Result<()> {
    if !input.is_empty() {
        debug!(remaining_size = input.len(), "trailing bytes remain");
        return Err(Error::InvalidData);
    }

    Ok(())
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    let Some((value, remaining)) = input.split_at_checked(len) else {
        debug!(
            required_size = len,
            actual_size = input.len(),
            "parameter buffer too short"
        );
        return Err(Error::InvalidData);
    };

    *input = remaining;

    Ok(value)
}
