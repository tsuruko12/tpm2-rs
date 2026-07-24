use crate::{
    Error, Result, macros::{newtype, tpm2b_bytes_type}, types::rsa::{RsaKeyBits, RsaScheme},
};

use super::{TpmAlgId, TpmiAlgHash, TpmtSymDefObject};

tpm2b_bytes_type!(Tpm2bPublicKeyRsa);

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmsRsaParams {
    symmetric: TpmtSymDefObject,
    scheme: TpmtRsaScheme,
    key_bits: TpmiRsaKeyBits,
    exponent: u32,
}

impl TpmsRsaParams {
    const DEFAULT_EXPONENT: u32 = 0;

    pub(crate) fn new(
        symmetric: TpmtSymDefObject,
        scheme: TpmtRsaScheme,
        key_bits: TpmiRsaKeyBits,
        exponent: u32,
    ) -> Self {
        Self {
            symmetric,
            scheme,
            key_bits,
            exponent,
        }
    }

    pub(super) fn unrestricted(scheme: TpmtRsaScheme, key_bits: TpmiRsaKeyBits) -> Self {
        Self {
            symmetric: TpmtSymDefObject::null(),
            scheme,
            key_bits,
            exponent: Self::DEFAULT_EXPONENT,
        }
    }

    pub(super) fn storage_parent() -> Self {
        Self {
            symmetric: TpmtSymDefObject::aes_128_cfb(),
            scheme: TpmtRsaScheme::null(),
            key_bits: TpmiRsaKeyBits::BITS3072,
            exponent: Self::DEFAULT_EXPONENT,
        }
    }

    pub(crate) fn symmetric(&self) -> TpmtSymDefObject {
        self.symmetric
    }

    pub(crate) fn scheme(&self) -> TpmtRsaScheme {
        self.scheme
    }

    pub(crate) fn key_bits(&self) -> TpmiRsaKeyBits {
        self.key_bits
    }

    pub(crate) fn exponent(&self) -> u32 {
        self.exponent
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TpmtRsaScheme {
    RsaSsa(TpmiAlgHash),
    RsaPss(TpmiAlgHash),
    Oaep(TpmiAlgHash),
    RsaEs,
    Null,
}

impl TpmtRsaScheme {
    fn null() -> Self {
        Self::Null
    }

    pub(crate) fn into_parts(self) -> (TpmiAlgRsaScheme, Option<TpmiAlgHash>) {
        match self {
            Self::RsaSsa(hash) => (TpmiAlgRsaScheme::RSASSA, Some(hash)),
            Self::RsaPss(hash) => (TpmiAlgRsaScheme::RSAPSS, Some(hash)),
            Self::Oaep(hash) => (TpmiAlgRsaScheme::OAEP, Some(hash)),
            Self::RsaEs => (TpmiAlgRsaScheme::RSAES, None),
            Self::Null => (TpmiAlgRsaScheme::NULL, None),
        }
    }
}

impl From<RsaScheme> for TpmtRsaScheme {
    fn from(value: RsaScheme) -> Self {
        match value {
            RsaScheme::Oaep(hash) => Self::Oaep(hash.into()),
            RsaScheme::RsaSsa(hash) => Self::RsaSsa(hash.into()),
            RsaScheme::RsaPss(hash) => Self::RsaPss(hash.into()),
            RsaScheme::RsaEs => Self::RsaEs,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TpmiAlgRsaScheme(TpmAlgId);

impl TpmiAlgRsaScheme {
    pub(crate) const RSASSA: Self = Self(TpmAlgId::RsaSsa);
    pub(crate) const RSAES: Self = Self(TpmAlgId::RsaEs);
    pub(crate) const RSAPSS: Self = Self(TpmAlgId::RsaPss);
    pub(crate) const OAEP: Self = Self(TpmAlgId::Oaep);
    pub(crate) const NULL: Self = Self(TpmAlgId::Null);

    pub(crate) fn raw(self) -> u16 {
        self.0.raw()
    }
}

impl TryFrom<u16> for TpmiAlgRsaScheme {
    type Error = Error;

    fn try_from(raw: u16) -> Result<Self> {
        TpmAlgId::try_from(raw)?.try_into()
    }
}

impl TryFrom<TpmAlgId> for TpmiAlgRsaScheme {
    type Error = Error;

    fn try_from(alg_id: TpmAlgId) -> Result<Self> {
        match alg_id {
            TpmAlgId::RsaSsa
            | TpmAlgId::RsaEs
            | TpmAlgId::RsaPss
            | TpmAlgId::Oaep
            | TpmAlgId::Null => Ok(Self(alg_id)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgRsaScheme>()),
        }
    }
}

newtype!(TpmiRsaKeyBits(u16));

impl TpmiRsaKeyBits {
    pub(super) const BITS2048: Self = Self(2048);
    const BITS3072: Self = Self(3072);
    const BITS4096: Self = Self(4096);
}

impl From<u16> for TpmiRsaKeyBits {
    fn from(raw: u16) -> Self {
        Self(raw)
    }
}

impl From<RsaKeyBits> for TpmiRsaKeyBits {
    fn from(value: RsaKeyBits) -> Self {
        match value {
            RsaKeyBits::Bits2048 => Self::BITS2048,
            RsaKeyBits::Bits3072 => Self::BITS3072,
            RsaKeyBits::Bits4096 => Self::BITS4096,
        }
    }
}
