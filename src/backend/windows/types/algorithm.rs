use crate::{Error, Result, macros::newtype_in_win, types::tpm::{TpmAlgId, TpmiAlgHash, TpmsSchemeHash, TpmuRsaScheme}};

#[derive(Debug, Clone, Copy)]
pub(in crate::backend::windows) struct TpmtRsaDecrypt {
    scheme: TpmiAlgRsaDecrypt,
    details: TpmuRsaScheme,
}

impl TpmtRsaDecrypt {
    pub(in crate::backend::windows) fn oaep() -> Self {
        Self {
            scheme: TpmiAlgRsaDecrypt::OAEP,
            details: TpmuRsaScheme::Oaep(TpmsSchemeHash { hash_alg: TpmiAlgHash::SHA256}),
        }
    }

    pub(in crate::backend::windows) fn parts(&self) -> (TpmiAlgRsaDecrypt, TpmuRsaScheme) {
        (self.scheme, self.details)
    }
}

newtype_in_win!(TpmiAlgRsaDecrypt(TpmAlgId));

impl TpmiAlgRsaDecrypt {
    pub(in crate::backend::windows) const RSA_ES: Self = Self(TpmAlgId::RsaEs);
    pub(in crate::backend::windows) const OAEP: Self = Self(TpmAlgId::Oaep);
    pub(in crate::backend::windows) const NULL: Self = Self(TpmAlgId::Null);
}

impl TryFrom<TpmAlgId> for TpmiAlgRsaDecrypt {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        match alg {
            TpmAlgId::RsaEs
            | TpmAlgId::Oaep
            | TpmAlgId::Null => Ok(Self(alg)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgRsaDecrypt>(Some(&alg))),
        }
    }
}