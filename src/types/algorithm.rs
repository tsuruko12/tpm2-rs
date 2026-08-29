use crate::{Error, Result};
use super::tpm::{TpmAlgId, TpmiAlgHash};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub(super) const DEFAULT: Self = Self::Sha256;
}

impl TryFrom<TpmiAlgHash> for HashAlgorithm {
    type Error = Error;

    fn try_from(hash_alg: TpmiAlgHash) -> Result<Self> {
        match TpmAlgId::from(hash_alg) {
            TpmAlgId::Sha1 => Ok(Self::Sha1),
            TpmAlgId::Sha256 => Ok(Self::Sha256),
            TpmAlgId::Sha384 => Ok(Self::Sha384),
            TpmAlgId::Sha512 => Ok(Self::Sha512),
            _ => Err(Error::conversion::<TpmiAlgHash, HashAlgorithm>(Some(
                &hash_alg,
            ))),
        }
    }
}
