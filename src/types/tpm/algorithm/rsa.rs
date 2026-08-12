use crate::{
    Error, Result,
    macros::{newtype, tpm2b_bytes_type},
    types::public::rsa::{RsaKeyBits, RsaScheme},
};
use super::{TpmAlgId, TpmsEmpty, TpmsSchemeHash, TpmtSymDefObject};

tpm2b_bytes_type!(Tpm2bPublicKeyRsa);

impl Tpm2bPublicKeyRsa {
    const MAX_BYTES: usize = RsaKeyBits::MAX_BITS / 2;
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmsRsaParms {
    symmetric: TpmtSymDefObject,
    scheme: TpmtRsaScheme,
    key_bits: TpmiRsaKeyBits,
    exponent: u32,
}

impl TpmsRsaParms {
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

    pub(crate) fn unrestricted(scheme: TpmtRsaScheme, key_bits: TpmiRsaKeyBits) -> Self {
        Self {
            symmetric: TpmtSymDefObject::null(),
            scheme,
            key_bits,
            exponent: Self::DEFAULT_EXPONENT,
        }
    }

    pub(crate) fn storage_parent() -> Self {
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
pub(crate) struct TpmtRsaScheme {
    scheme: TpmiAlgRsaScheme,
    details: TpmuRsaScheme,
}

impl TpmtRsaScheme {
    pub(crate) fn oaep(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgRsaScheme::OAEP,
            details: TpmuRsaScheme::Oaep(scheme_hash),
        }
    }

    pub(crate) fn rsa_ssa(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgRsaScheme::RSA_SSA,
            details: TpmuRsaScheme::RsaSsa(scheme_hash),
        }
    }

    pub(crate) fn rsa_pss(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgRsaScheme::RSA_PSS,
            details: TpmuRsaScheme::RsaPss(scheme_hash),
        }
    }

    pub(crate) fn rsa_es() -> Self {
        Self {
            scheme: TpmiAlgRsaScheme::RSA_ES,
            details: TpmuRsaScheme::RsaEs(TpmsEmpty),
        }
    }

    pub(crate) fn null() -> Self {
        Self {
            scheme: TpmiAlgRsaScheme::NULL,
            details: TpmuRsaScheme::Null,
        }
    }

    pub(crate) fn into_parts(self) -> (TpmiAlgRsaScheme, TpmuRsaScheme) {
        (self.scheme, self.details)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TpmuRsaScheme {
    RsaSsa(TpmsSchemeHash),
    RsaPss(TpmsSchemeHash),
    Oaep(TpmsSchemeHash),
    RsaEs(TpmsEmpty),
    Null,
}

impl From<RsaScheme> for TpmtRsaScheme {
    fn from(rsa_scheme: RsaScheme) -> Self {
        match rsa_scheme {
            RsaScheme::Oaep(hash_alg) => Self::oaep(hash_alg.into()),
            RsaScheme::RsaSsa(hash_alg) => Self::rsa_ssa(hash_alg.into()),
            RsaScheme::RsaPss(hash_alg) => Self::rsa_pss(hash_alg.into()),
            RsaScheme::RsaEs => Self::rsa_es(),
        }
    }
}

newtype!(TpmiAlgRsaScheme(TpmAlgId));

impl TpmiAlgRsaScheme {
    pub(crate) const RSA_SSA: Self = Self(TpmAlgId::RsaSsa);
    pub(crate) const RSA_ES: Self = Self(TpmAlgId::RsaEs);
    pub(crate) const RSA_PSS: Self = Self(TpmAlgId::RsaPss);
    pub(crate) const OAEP: Self = Self(TpmAlgId::Oaep);
    pub(crate) const NULL: Self = Self(TpmAlgId::Null);
}

impl TryFrom<u16> for TpmiAlgRsaScheme {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        TpmAlgId::try_from(value)?.try_into()
    }
}

impl TryFrom<TpmAlgId> for TpmiAlgRsaScheme {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        match alg {
            TpmAlgId::RsaSsa
            | TpmAlgId::RsaEs
            | TpmAlgId::RsaPss
            | TpmAlgId::Oaep
            | TpmAlgId::Null => Ok(Self(alg)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgRsaScheme>(Some(&alg))),
        }
    }
}

newtype!(TpmiRsaKeyBits(u16));

impl TpmiRsaKeyBits {
    pub(crate) const BITS1024: Self = Self(1024);
    pub(crate) const BITS2048: Self = Self(2048);
    pub(crate) const BITS3072: Self = Self(3072);
    pub(crate) const BITS4096: Self = Self(4096);
}

impl From<u16> for TpmiRsaKeyBits {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<RsaKeyBits> for TpmiRsaKeyBits {
    fn from(key_bits: RsaKeyBits) -> Self {
        match key_bits {
            RsaKeyBits::Bits2048 => Self::BITS2048,
            RsaKeyBits::Bits3072 => Self::BITS3072,
            RsaKeyBits::Bits4096 => Self::BITS4096,
        }
    }
}
