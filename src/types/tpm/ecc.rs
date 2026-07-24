use super::{TpmAlgId, TpmiAlgHash, TpmtSymDefObject};
use crate::{
    Error, Result,
    macros::{tpm2b_bytes_type, tpm_list_type, unknown_tpm_data},
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmsEccParams {
    symmetric: TpmtSymDefObject,
    scheme: TpmtEccScheme,
    curve_id: TpmiEccCurve,
    kdf: TpmtKdfScheme, // fixed to null
}

impl TpmsEccParams {
    pub(crate) fn new(
        symmetric: TpmtSymDefObject,
        scheme: TpmtEccScheme,
        curve_id: TpmiEccCurve,
    ) -> Self {
        Self {
            symmetric,
            scheme,
            curve_id,
            kdf: TpmtKdfScheme::Null,
        }
    }

    fn ecdsa(curve_id: TpmiEccCurve, hash_alg: TpmiAlgHash) -> Self {
        Self {
            symmetric: TpmtSymDefObject::null(),
            scheme: TpmtEccScheme::ecdsa(hash_alg),
            curve_id,
            kdf: TpmtKdfScheme::Null,
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
            _ => unknown_tpm_data!(value, "ECC curve identifier"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TpmtSigScheme {
    RsaSsa(TpmiAlgHash),
    RsaPss(TpmiAlgHash),
    Ecdsa(TpmiAlgHash),
    Null,
}

impl TpmtSigScheme {
    pub(crate) fn into_parts(self) -> (TpmiAlgSigScheme, Option<TpmiAlgHash>) {
        match self {
            Self::RsaSsa(hash) => (TpmiAlgSigScheme(TpmAlgId::RsaSsa), Some(hash)),
            Self::RsaPss(hash) => (TpmiAlgSigScheme(TpmAlgId::RsaPss), Some(hash)),
            Self::Ecdsa(hash) => (TpmiAlgSigScheme(TpmAlgId::Ecdsa), Some(hash)),
            Self::Null => (TpmiAlgSigScheme(TpmAlgId::Null), None),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmtEccScheme(TpmtSigScheme);

impl TpmtEccScheme {
    pub(crate) fn ecdsa(hash_alg: TpmiAlgHash) -> Self {
        TpmtEccScheme(TpmtSigScheme::Ecdsa(hash_alg))
    }

    pub(crate) fn null() -> Self {
        Self(TpmtSigScheme::Null)
    }

    pub(crate) fn into_parts(self) -> (TpmiAlgEccScheme, Option<TpmiAlgHash>) {
        match self.0 {
            TpmtSigScheme::Ecdsa(hash) => (TpmiAlgEccScheme(TpmAlgId::Ecdsa), Some(hash)),
            TpmtSigScheme::Null => (TpmiAlgEccScheme(TpmAlgId::Null), None),
            _ => unreachable!("TpmtEccScheme only contains ECC schemes"),
        }
    }
}

impl TryFrom<TpmtSigScheme> for TpmtEccScheme {
    type Error = Error;

    fn try_from(value: TpmtSigScheme) -> Result<Self> {
        match value {
            TpmtSigScheme::Ecdsa(_) | TpmtSigScheme::Null => Ok(Self(value)),
            _ => Err(Error::conversion::<TpmtSigScheme, TpmtEccScheme>()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmiAlgSigScheme(TpmAlgId);

impl TpmiAlgSigScheme {
    pub(crate) fn raw(self) -> u16 {
        self.0.raw()
    }
}

impl TryFrom<TpmAlgId> for TpmiAlgSigScheme {
    type Error = Error;

    fn try_from(value: TpmAlgId) -> Result<Self> {
        match value {
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
            | TpmAlgId::Null => Ok(Self(value)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgSigScheme>()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TpmiAlgEccScheme(TpmAlgId);

impl TpmiAlgEccScheme {
    pub(crate) const ECDSA: Self = Self(TpmAlgId::Ecdsa);
    pub(crate) const NULL: Self = Self(TpmAlgId::Null);

    pub(crate) fn raw(self) -> u16 {
        self.0.raw()
    }
}

impl TryFrom<u16> for TpmiAlgEccScheme {
    type Error = Error;

    fn try_from(raw: u16) -> Result<Self> {
        TpmAlgId::try_from(raw)?.try_into()
    }
}

impl TryFrom<TpmAlgId> for TpmiAlgEccScheme {
    type Error = Error;

    fn try_from(value: TpmAlgId) -> Result<Self> {
        match value {
            TpmAlgId::Ecdsa
            | TpmAlgId::Ecdaa
            | TpmAlgId::Sm2
            | TpmAlgId::EcSchnorr
            | TpmAlgId::EdDsa
            | TpmAlgId::HashEdDsa
            | TpmAlgId::Ecdh
            | TpmAlgId::EcMqv
            | TpmAlgId::Null => Ok(Self(value)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgEccScheme>()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmiEccCurve(TpmEccCurve);

impl TpmiEccCurve {
    pub(crate) const NIST_P256: Self = Self(TpmEccCurve::NistP256);
    pub(crate) const NIST_P384: Self = Self(TpmEccCurve::NistP384);
    pub(crate) const NIST_P521: Self = Self(TpmEccCurve::NistP521);

    pub(crate) fn raw(self) -> u16 {
        self.0 as u16
    }
}

impl TryFrom<u16> for TpmiEccCurve {
    type Error = Error;

    fn try_from(raw: u16) -> Result<Self> {
        TpmEccCurve::try_from(raw)?.try_into()
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
            _ => Err(Error::conversion::<TpmEccCurve, TpmiEccCurve>()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TpmtKdfScheme {
    Null,
}

impl TpmtKdfScheme {
    pub(crate) fn raw(self) -> u16 {
        TpmAlgId::Null.raw()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmiAlgKdf(TpmAlgId);

impl TpmiAlgKdf {
    pub(crate) const NULL: Self = Self(TpmAlgId::Null);

    pub(crate) fn raw(self) -> u16 {
        self.0.raw()
    }
}

impl TryFrom<u16> for TpmiAlgKdf {
    type Error = Error;

    fn try_from(raw: u16) -> Result<Self> {
        TpmAlgId::try_from(raw)?.try_into()
    }    
}

impl TryFrom<TpmAlgId> for TpmiAlgKdf {
    type Error = Error;

    fn try_from(alg_id: TpmAlgId) -> Result<Self> {
        match alg_id {
            TpmAlgId::Null => Ok(Self(alg_id)),
            _ => {
                tracing::error!(?alg_id, "unsupported KDF algorithm");
                Err(Error::InvalidData)
            }
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
