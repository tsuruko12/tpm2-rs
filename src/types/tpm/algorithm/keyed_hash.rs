use super::{TpmAlgId, TpmiAlgHash, TpmiAlgKdf, TpmsSchemeHash};
use crate::{Error, Result, macros::newtype};

// Support for TPM_ALG_NULL for HMAC keys
// with the sign attribute was deprecated
#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmsKeyedHashParms {
    pub(crate) scheme: TpmtKeyedHashScheme,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmtKeyedHashScheme {
    scheme: TpmiAlgKeyedHashScheme,
    details: TpmuSchemeKeyedHash,
}

impl TpmtKeyedHashScheme {
    pub(crate) fn hmac(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgKeyedHashScheme::HMAC,
            details: TpmuSchemeKeyedHash::Hmac(scheme_hash),
        }
    }

    pub(crate) fn xor(scheme_xor: TpmsSchemeXor) -> Self {
        Self {
            scheme: TpmiAlgKeyedHashScheme::XOR,
            details: TpmuSchemeKeyedHash::Xor(scheme_xor),
        }
    }

    pub(crate) fn null() -> Self {
        Self {
            scheme: TpmiAlgKeyedHashScheme::NULL,
            details: TpmuSchemeKeyedHash::Null,
        }
    }

    pub(crate) fn into_parts(self) -> (TpmiAlgKeyedHashScheme, TpmuSchemeKeyedHash) {
        (self.scheme, self.details)
    }
}

newtype!(TpmiAlgKeyedHashScheme(TpmAlgId));

impl TpmiAlgKeyedHashScheme {
    pub(crate) const HMAC: Self = Self(TpmAlgId::Hmac);
    pub(crate) const XOR: Self = Self(TpmAlgId::Xor);
    pub(crate) const NULL: Self = Self(TpmAlgId::Null);
}

impl TryFrom<TpmAlgId> for TpmiAlgKeyedHashScheme {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        match alg {
            TpmAlgId::Hmac | TpmAlgId::Xor | TpmAlgId::Null => Ok(Self(alg)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgKeyedHashScheme>(
                Some(&alg)
            )),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TpmuSchemeKeyedHash {
    Hmac(TpmsSchemeHash),
    Xor(TpmsSchemeXor),
    Null,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmsSchemeXor {
    pub(crate) hash_alg: TpmiAlgHash,
    pub(crate) kdf: TpmiAlgKdf,
}
