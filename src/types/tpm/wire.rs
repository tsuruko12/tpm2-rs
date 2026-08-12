use tracing::debug;

use crate::{Error, Result, types::TpmsEccPoint};

use super::{
    Tpm2bDigest, TpmAlgId, TpmKeyBits, TpmaObject, TpmiAlgEccScheme,
    TpmiAlgHash, TpmiAlgKdf, TpmiAlgKeyedHashScheme, TpmiAlgPublic, TpmiAlgRsaScheme,
    TpmiAlgSymMode, TpmiAlgSymObject, TpmiEccCurve, TpmiRsaKeyBits, TpmsEccParms,
    TpmsKeyedHashParms, TpmsRsaParms, TpmsSchemeEcdaa, TpmsSchemeHash, TpmsSchemeXor,
    TpmlDigest, TpmtEccScheme, TpmtKdfScheme, TpmtKeyedHashScheme, TpmtPublic, TpmtRsaScheme,
    TpmtSymDefObject, TpmuEccScheme, TpmuKdfScheme, TpmuPublicId, TpmuPublicParms,
    TpmuRsaScheme, TpmuSchemeKeyedHash,
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
    let count = read_u32(input)? as usize;

    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(unmarshal_item(input)?);
    }

    Ok(items)
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
        self.raw().marshal(buf)
    }
}

impl TpmMarshal for TpmiAlgHash {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.raw().marshal(buf)
    }
}

impl TpmMarshal for TpmlDigest {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        marshal_list(buf, self.items(), |buf, digest| {
            marshal_tpm2b(buf, digest.as_bytes())
        })
    }
}

impl TpmMarshal for TpmtPublic {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.alg_type().raw().marshal(buf)?;
        self.name_alg().raw().marshal(buf)?;
        self.object_attributes().bits().marshal(buf)?;
        marshal_tpm2b(buf, self.auth_policy().as_bytes())?;
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
        scheme.raw().marshal(buf)?;

        match details {
            TpmuRsaScheme::Oaep(scheme_hash)
            | TpmuRsaScheme::RsaPss(scheme_hash)
            | TpmuRsaScheme::RsaSsa(scheme_hash) => scheme_hash.hash_alg.marshal(buf)?,
            _ => {},
        }

        self.key_bits().raw().marshal(buf)?;
        self.exponent().marshal(buf)
    }
}

impl TpmMarshal for TpmsEccParms {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.symmetric().marshal(buf)?;

        let (ecc_scheme, ecc_details) = self.scheme().into_parts();
        ecc_scheme.raw().marshal(buf)?;

        match ecc_details {
            TpmuEccScheme::Ecdsa(scheme_hash)
            | TpmuEccScheme::Ecdh(scheme_hash)
            | TpmuEccScheme::Sm2(scheme_hash)
            | TpmuEccScheme::EcSchnorr(scheme_hash)
            | TpmuEccScheme::EcMqv(scheme_hash) => scheme_hash.hash_alg.marshal(buf)?,
            TpmuEccScheme::Ecdaa(scheme_ecdaa) => {
                scheme_ecdaa.hash_alg.marshal(buf)?;
                scheme_ecdaa.count.marshal(buf)?;
            },
            _ => {},
        }

        self.curve_id().raw().marshal(buf)?;

        let (kdf_scheme, kdf_details) = self.kdf().into_parts();
        kdf_scheme.raw().marshal(buf)?;

        match kdf_details {
            TpmuKdfScheme::Kdf1Sp800_56a(scheme_hash)
            | TpmuKdfScheme::Kdf1Sp800_108(scheme_hash)
            | TpmuKdfScheme::Kdf2(scheme_hash)
            | TpmuKdfScheme::Mgf1(scheme_hash) => scheme_hash.hash_alg.marshal(buf)?,
            _ => {},
        }

        Ok(())
    }
}

impl TpmMarshal for TpmsKeyedHashParms {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        let (scheme, details) = self.scheme.into_parts();
        scheme.raw().marshal(buf)?;

        match details {
            TpmuSchemeKeyedHash::Hmac(scheme_hash) => scheme_hash.hash_alg.marshal(buf)?,
            TpmuSchemeKeyedHash::Xor(scheme_xor) => {
                scheme_xor.hash_alg.marshal(buf)?;
                scheme_xor.kdf.raw().marshal(buf)?;
            },
            _ => {},
        }

        Ok(())
    }
}

impl TpmMarshal for TpmtSymDefObject {
    fn marshal(&self, buf: &mut Vec<u8>) -> Result<()> {
        self.algorithm().raw().marshal(buf)?;

        if self.algorithm() != TpmiAlgSymObject::NULL {
            self.key_bits().raw().marshal(buf)?;
            self.mode().raw().marshal(buf)?;
        }

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
            },
            Self::Rsa(public_key) => marshal_tpm2b(buf, public_key.as_bytes())?,
            Self::Sym(digest) | Self::KeyedHash(digest) => marshal_tpm2b(buf, digest.as_bytes())?,
        }

        Ok(())
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

impl TpmUnmarshal for TpmiAlgHash {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        TpmAlgId::unmarshal(input)?.try_into()
    }
}

impl TpmUnmarshal for TpmlDigest {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let count = read_u32(input)? as usize;
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
            digests.push(Tpm2bDigest::try_from(read_tpm2b(input)?)?);
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

impl TpmUnmarshal for TpmtPublic {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let alg_type = TpmiAlgPublic::try_from(TpmAlgId::unmarshal(input)?)?;
        let name_alg = TpmiAlgHash::unmarshal(input)?;
        let attributes = u32::unmarshal(input)?;
        let object_attributes = TpmaObject::from_bits(attributes).ok_or_else(|| {
            debug!(?attributes, "invalid object attributes");
            Error::InvalidData
        })?;
        let auth_policy = Tpm2bDigest::try_from(read_tpm2b(input)?)?;

        let (parameters, unique) = match alg_type {
            TpmiAlgPublic::RSA => (
                TpmuPublicParms::RsaDetail(TpmsRsaParms::unmarshal(input)?),
                TpmuPublicId::rsa(read_tpm2b(input)?.try_into()?),
            ),
            TpmiAlgPublic::ECC => {
                let parameters = TpmuPublicParms::EccDetail(TpmsEccParms::unmarshal(input)?);
                let x = read_tpm2b(input)?;
                let y = read_tpm2b(input)?;

                (parameters, TpmuPublicId::ecc(TpmsEccPoint::new(x, y)?))
            },
            TpmiAlgPublic::SYM_CIPHER => (
                TpmuPublicParms::SymDetail(TpmtSymDefObject::unmarshal(input)?.into()),
                TpmuPublicId::sym(read_tpm2b(input)?.try_into()?),
            ),
            TpmiAlgPublic::KEYED_HASH => (
                TpmuPublicParms::KeyedHashDetail(TpmsKeyedHashParms::unmarshal(input)?),
                TpmuPublicId::keyed_hash(read_tpm2b(input)?.try_into()?),
            ),
            _ => {
                debug!(?alg_type, "unsupported TPM public algorithm");
                return Err(Error::InvalidData);
            },
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
        let algorithm = TpmiAlgSymObject::try_from(u16::unmarshal(input)?)?;

        if algorithm == TpmiAlgSymObject::NULL {
            return Ok(Self::null());
        }

        Ok(Self::new(
            algorithm,
            TpmKeyBits::from(u16::unmarshal(input)?),
            TpmiAlgSymMode::try_from(u16::unmarshal(input)?)?,
        ))
    }
}

impl TpmUnmarshal for TpmsRsaParms {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let symmetric = TpmtSymDefObject::unmarshal(input)?;
        let scheme = TpmiAlgRsaScheme::try_from(TpmAlgId::unmarshal(input)?)?;

        let scheme = match scheme {
            TpmiAlgRsaScheme::OAEP => TpmtRsaScheme::oaep(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgRsaScheme::RSA_SSA => TpmtRsaScheme::rsa_ssa(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgRsaScheme::RSA_PSS => TpmtRsaScheme::rsa_pss(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgRsaScheme::RSA_ES => TpmtRsaScheme::rsa_es(),
            TpmiAlgRsaScheme::NULL => TpmtRsaScheme::null(),
            _ => {
                debug!(?scheme, "unsupported TPM RSA scheme");
                return Err(Error::InvalidData);
            },
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
        let ecc_scheme = match TpmiAlgEccScheme::try_from(TpmAlgId::unmarshal(input)?)? {
            TpmiAlgEccScheme::ECDSA => TpmtEccScheme::ecdsa(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgEccScheme::ECDH => TpmtEccScheme::ecdh(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgEccScheme::SM2 => TpmtEccScheme::sm2(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgEccScheme::EC_SCHNORR => TpmtEccScheme::ec_schnorr(
                TpmsSchemeHash::unmarshal(input)?
            ),
            TpmiAlgEccScheme::EC_MQV => TpmtEccScheme::ec_mqv(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgEccScheme::ECDAA => TpmtEccScheme::ecdaa(TpmsSchemeEcdaa {
                hash_alg: TpmiAlgHash::unmarshal(input)?,
                count: u16::unmarshal(input)?,
            }),
            TpmiAlgEccScheme::NULL => TpmtEccScheme::null(),
            scheme => {
                debug!(?scheme, "unsupported TPM ECC scheme");
                return Err(Error::InvalidData);
            },
        };

        let curve_id = TpmiEccCurve::try_from(u16::unmarshal(input)?)?;
        let kdf_scheme = match TpmiAlgKdf::try_from(TpmAlgId::unmarshal(input)?)? {
            TpmiAlgKdf::KDF1_SP800_56A => TpmtKdfScheme::kdf1_sp800_56a(
                TpmsSchemeHash::unmarshal(input)?
            ),
            TpmiAlgKdf::KDF1_SP800_108 => TpmtKdfScheme::kdf1_sp800_108(
                TpmsSchemeHash::unmarshal(input)?
            ),
            TpmiAlgKdf::KDF2 => TpmtKdfScheme::kdf2(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgKdf::MGF1 => TpmtKdfScheme::mgf1(TpmsSchemeHash::unmarshal(input)?),
            TpmiAlgKdf::NULL => TpmtKdfScheme::null(),
            scheme => {
                debug!(?scheme, "unsupported TPM KDF scheme");
                return Err(Error::InvalidData);
            },
        };

        Ok(Self::new(symmetric, ecc_scheme, curve_id, kdf_scheme))
    }
}

impl TpmUnmarshal for TpmsKeyedHashParms {
    fn unmarshal(input: &mut &[u8]) -> Result<Self> {
        let scheme = match TpmiAlgKeyedHashScheme::try_from(TpmAlgId::unmarshal(input)?)? {
            TpmiAlgKeyedHashScheme::HMAC => TpmtKeyedHashScheme::hmac(
                TpmsSchemeHash::unmarshal(input)?
            ),
            TpmiAlgKeyedHashScheme::XOR => TpmtKeyedHashScheme::xor(TpmsSchemeXor {
                hash_alg: TpmiAlgHash::unmarshal(input)?,
                kdf: TpmiAlgKdf::try_from(TpmAlgId::unmarshal(input)?)?,
            }),
            TpmiAlgKeyedHashScheme::NULL => TpmtKeyedHashScheme::null(),
            scheme => {
                debug!(?scheme, "unsupported TPM keyed-hash scheme");
                return Err(Error::InvalidData);
            },
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
    Ok(u16::from_be_bytes(bytes.try_into().expect("slice has exactly two bytes")))
}

pub(crate) fn read_u32(input: &mut &[u8]) -> Result<u32> {
    let bytes = take(input, size_of::<u32>())?;
    Ok(u32::from_be_bytes(bytes.try_into().expect("slice has exactly four bytes")))
}

pub(crate) fn read_vec(input: &mut &[u8], len: usize) -> Result<Vec<u8>> {
    Ok(take(input, len)?.to_vec())
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    let Some((value, remaining)) = input.split_at_checked(len) else {
        debug!(required_size = len, actual_size = input.len(), "parameter buffer too short");
        return Err(Error::InvalidData);
    };

    *input = remaining;
    
    Ok(value)
}
