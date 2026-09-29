use super::tpm::{TpmAlgId, TpmiAlgHash};
use crate::{Error, Result};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaSignature {
    hash_algorithm: HashAlgorithm,
    value: Vec<u8>,
}

impl RsaSignature {
    pub(crate) fn new(hash_algorithm: HashAlgorithm, value: &[u8]) -> Self {
        Self {
            hash_algorithm,
            value: value.to_vec(),
        }
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccSignature {
    hash_algorithm: HashAlgorithm,
    r: Vec<u8>,
    s: Vec<u8>,
}

impl EccSignature {
    pub(crate) fn new(hash_algorithm: HashAlgorithm, r: &[u8], s: &[u8]) -> Self {
        Self {
            hash_algorithm,
            r: r.to_vec(),
            s: s.to_vec(),
        }
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }

    pub fn r(&self) -> &[u8] {
        &self.r
    }

    pub fn s(&self) -> &[u8] {
        &self.s
    }
}
