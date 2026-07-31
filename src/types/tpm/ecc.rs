use super::{TpmAlgId, TpmiAlgHash, TpmtSymDefObject};
use crate::{
    Error, Result,
    macros::{newtype, tpm_list_type, tpm2b_bytes_type},
    types::{TpmsSchemeHash, TpmtKdfScheme},
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmsEccParms {
    symmetric: TpmtSymDefObject,
    scheme: TpmtEccScheme,
    curve_id: TpmiEccCurve,
    kdf: TpmtKdfScheme,
}

impl TpmsEccParms {
    pub(crate) fn new(
        symmetric: TpmtSymDefObject,
        scheme: TpmtEccScheme,
        curve_id: TpmiEccCurve,
        kdf: TpmtKdfScheme,
    ) -> Self {
        Self {
            symmetric,
            scheme,
            curve_id,
            kdf,
        }
    }

    fn ecdsa(curve_id: TpmiEccCurve, scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            symmetric: TpmtSymDefObject::null(),
            scheme: TpmtEccScheme::ecdsa(scheme_hash),
            curve_id,
            kdf: TpmtKdfScheme::null(),
        }
    }

    pub(crate) fn symmetric(&self) -> TpmtSymDefObject {
        self.symmetric
    }

    pub(crate) fn scheme(&self) -> TpmtEccScheme {
        self.scheme
    }

    pub(crate) fn curve_id(&self) -> TpmiEccCurve {
        self.curve_id
    }

    pub(crate) fn kdf(&self) -> TpmtKdfScheme {
        self.kdf
    }
}

tpm_list_type!(TpmlEccCurve(TpmEccCurve););

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TpmEccCurve {
    None = 0x0000,
    NistP192 = 0x0001,
    NistP224 = 0x0002,
    NistP256 = 0x0003,
    NistP384 = 0x0004,
    NistP521 = 0x0005,
    BnP256 = 0x0010,
    BnP638 = 0x0011,
    Sm2P256 = 0x0020,
    BpP256R1 = 0x0030,
    BpP384R1 = 0x0031,
    BpP512R1 = 0x0032,
    Curve25519 = 0x0040,
    Curve448 = 0x0041,
}

impl TpmEccCurve {
    pub(crate) fn raw(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for TpmEccCurve {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0x0000 => Ok(Self::None),
            0x0001 => Ok(Self::NistP192),
            0x0002 => Ok(Self::NistP224),
            0x0003 => Ok(Self::NistP256),
            0x0004 => Ok(Self::NistP384),
            0x0005 => Ok(Self::NistP521),
            0x0010 => Ok(Self::BnP256),
            0x0011 => Ok(Self::BnP638),
            0x0020 => Ok(Self::Sm2P256),
            0x0030 => Ok(Self::BpP256R1),
            0x0031 => Ok(Self::BpP384R1),
            0x0032 => Ok(Self::BpP512R1),
            0x0040 => Ok(Self::Curve25519),
            0x0041 => Ok(Self::Curve448),
            _ => Err(Error::conversion::<u16, TpmEccCurve>(None)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmtEccScheme {
    scheme: TpmiAlgEccScheme,
    details: TpmuEccScheme,
}

impl TpmtEccScheme {
    pub(crate) fn ecdsa(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgEccScheme::ECDSA,
            details: TpmuEccScheme::Ecdsa(scheme_hash),
        }
    }

    pub(crate) fn ecdh(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgEccScheme::ECDH,
            details: TpmuEccScheme::Ecdh(scheme_hash),
        }
    }

    pub(crate) fn ecdaa(details: TpmsSchemeEcdaa) -> Self {
        Self {
            scheme: TpmiAlgEccScheme::ECDAA,
            details: TpmuEccScheme::Ecdaa(details),
        }
    }

    pub(crate) fn sm2(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgEccScheme::SM2,
            details: TpmuEccScheme::Sm2(scheme_hash),
        }
    }

    pub(crate) fn ec_schnorr(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgEccScheme::EC_SCHNORR,
            details: TpmuEccScheme::EcSchnorr(scheme_hash),
        }
    }

    pub(crate) fn ec_mqv(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgEccScheme::EC_MQV,
            details: TpmuEccScheme::EcMqv(scheme_hash),
        }
    }

    pub(crate) fn null() -> Self {
        Self {
            scheme: TpmiAlgEccScheme::NULL,
            details: TpmuEccScheme::Null,
        }
    }

    pub(crate) fn into_parts(self) -> (TpmiAlgEccScheme, TpmuEccScheme) {
        (self.scheme, self.details)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TpmuEccScheme {
    Ecdsa(TpmsSchemeHash),
    Ecdh(TpmsSchemeHash),
    Ecdaa(TpmsSchemeEcdaa),
    Sm2(TpmsSchemeHash),
    EcSchnorr(TpmsSchemeHash),
    EcMqv(TpmsSchemeHash),
    Null,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmtSigScheme {
    scheme: TpmiAlgSigScheme,
    details: TpmuSigScheme,
}

impl TpmtSigScheme {
    pub(crate) fn rsa_ssa(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::RSA_SSA,
            details: TpmuSigScheme::RsaSsa(scheme_hash),
        }
    }

    pub(crate) fn rsa_pss(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::RSA_PSS,
            details: TpmuSigScheme::RsaPss(scheme_hash),
        }
    }

    pub(crate) fn ecdsa(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::ECDSA,
            details: TpmuSigScheme::Ecdsa(scheme_hash),
        }
    }

    pub(crate) fn ecdaa(scheme_ecdaa: TpmsSchemeEcdaa) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::ECDAA,
            details: TpmuSigScheme::Ecdaa(scheme_ecdaa),
        }
    }

    pub(crate) fn sm2(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::SM2,
            details: TpmuSigScheme::Sm2(scheme_hash),
        }
    }

    pub(crate) fn ec_schnorr(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::EC_SCHNORR,
            details: TpmuSigScheme::EcSchnorr(scheme_hash),
        }
    }

    pub(crate) fn hmac(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::HMAC,
            details: TpmuSigScheme::Hmac(scheme_hash),
        }
    }

    pub(crate) fn null() -> Self {
        Self {
            scheme: TpmiAlgSigScheme::NULL,
            details: TpmuSigScheme::Null,
        }
    }

    pub(crate) fn into_parts(self) -> (TpmiAlgSigScheme, TpmuSigScheme) {
        (self.scheme, self.details)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TpmuSigScheme {
    RsaSsa(TpmsSchemeHash),
    RsaPss(TpmsSchemeHash),
    Ecdsa(TpmsSchemeHash),
    Sm2(TpmsSchemeHash),
    EcSchnorr(TpmsSchemeHash),
    Eddsa(TpmsSchemeHash),
    Hmac(TpmsSchemeHash),
    Ecdaa(TpmsSchemeEcdaa),
    Null,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmsSchemeEcdaa {
    pub(crate) hash_alg: TpmiAlgHash,
    pub(crate) count: u16,
}

newtype!(TpmiAlgSigScheme(TpmAlgId) => u16);

impl TpmiAlgSigScheme {
    pub(crate) const RSA_SSA: Self = Self(TpmAlgId::RsaSsa);
    pub(crate) const RSA_PSS: Self = Self(TpmAlgId::RsaPss);
    pub(crate) const ECDSA: Self = Self(TpmAlgId::Ecdsa);
    pub(crate) const ECDAA: Self = Self(TpmAlgId::Ecdaa);
    pub(crate) const SM2: Self = Self(TpmAlgId::Sm2);
    pub(crate) const EC_SCHNORR: Self = Self(TpmAlgId::EcSchnorr);
    pub(crate) const HMAC: Self = Self(TpmAlgId::Hmac);
    pub(crate) const NULL: Self = Self(TpmAlgId::Null);
}

impl TryFrom<u16> for TpmiAlgSigScheme {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        TpmAlgId::try_from(value)?.try_into()
    }
}

impl TryFrom<TpmAlgId> for TpmiAlgSigScheme {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        match alg {
            TpmAlgId::RsaSsa
            | TpmAlgId::RsaPss
            | TpmAlgId::Ecdsa
            | TpmAlgId::Ecdaa
            | TpmAlgId::Sm2
            | TpmAlgId::EcSchnorr
            | TpmAlgId::EdDsa
            | TpmAlgId::HashEdDsa
            | TpmAlgId::Hmac
            | TpmAlgId::MlDsa
            | TpmAlgId::HashMlDsa
            | TpmAlgId::Null => Ok(Self(alg)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgSigScheme>(Some(&alg))),
        }
    }
}

newtype!(TpmiAlgEccScheme(TpmAlgId) => u16);

impl TpmiAlgEccScheme {
    const ECDSA: Self = Self(TpmAlgId::Ecdsa);
    const ECDH: Self = Self(TpmAlgId::Ecdh);
    const ECDAA: Self = Self(TpmAlgId::Ecdaa);
    const SM2: Self = Self(TpmAlgId::Sm2);
    const EC_SCHNORR: Self = Self(TpmAlgId::EcSchnorr);
    const EC_MQV: Self = Self(TpmAlgId::EcMqv);
    const NULL: Self = Self(TpmAlgId::Null);
}

impl TryFrom<u16> for TpmiAlgEccScheme {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        TpmAlgId::try_from(value)?.try_into()
    }
}

impl TryFrom<TpmAlgId> for TpmiAlgEccScheme {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        match alg {
            TpmAlgId::Ecdsa
            | TpmAlgId::Ecdaa
            | TpmAlgId::Sm2
            | TpmAlgId::EcSchnorr
            | TpmAlgId::EdDsa
            | TpmAlgId::HashEdDsa
            | TpmAlgId::Ecdh
            | TpmAlgId::EcMqv
            | TpmAlgId::Null => Ok(Self(alg)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgEccScheme>(Some(&alg))),
        }
    }
}

newtype!(TpmiEccCurve(TpmEccCurve) => u16);

impl TpmiEccCurve {
    pub(crate) const NIST_P256: Self = Self(TpmEccCurve::NistP256);
    pub(crate) const NIST_P384: Self = Self(TpmEccCurve::NistP384);
    pub(crate) const NIST_P521: Self = Self(TpmEccCurve::NistP521);
}

impl TryFrom<u16> for TpmiEccCurve {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        TpmEccCurve::try_from(value)?.try_into()
    }
}

impl TryFrom<TpmEccCurve> for TpmiEccCurve {
    type Error = Error;

    fn try_from(curve: TpmEccCurve) -> Result<Self> {
        match curve {
            TpmEccCurve::NistP192
            | TpmEccCurve::NistP224
            | TpmEccCurve::NistP256
            | TpmEccCurve::NistP384
            | TpmEccCurve::NistP521
            | TpmEccCurve::BnP256
            | TpmEccCurve::BnP638
            | TpmEccCurve::Sm2P256
            | TpmEccCurve::BpP256R1
            | TpmEccCurve::BpP384R1
            | TpmEccCurve::BpP512R1
            | TpmEccCurve::Curve25519
            | TpmEccCurve::Curve448 => Ok(Self(curve)),
            _ => Err(Error::conversion::<TpmEccCurve, TpmiEccCurve>(Some(&curve))),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TpmsEccPoint {
    x: Tpm2bEccParameter,
    y: Tpm2bEccParameter,
}

impl Default for TpmsEccPoint {
    fn default() -> Self {
        Self {
            x: Tpm2bEccParameter::default(),
            y: Tpm2bEccParameter::default(),
        }
    }
}

impl TpmsEccPoint {
    pub(super) fn new(x: Vec<u8>, y: Vec<u8>) -> Self {
        Self {
            x: Tpm2bEccParameter::from(x),
            y: Tpm2bEccParameter::from(y),
        }
    }

    pub(crate) fn as_parts(&self) -> (&Tpm2bEccParameter, &Tpm2bEccParameter) {
        (&self.x, &self.y)
    }
}

tpm2b_bytes_type!(Tpm2bEccParameter);
