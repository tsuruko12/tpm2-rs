use tracing::debug;

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub(super) const DEFAULT: Self = Self::Sha256;

    pub(crate) fn from_db(hash_alg: &str) -> Result<Self> {
        match hash_alg {
            "sha1" => Ok(HashAlgorithm::Sha1),
            "sha256" => Ok(HashAlgorithm::Sha256),
            "sha384" => Ok(HashAlgorithm::Sha384),
            "sha512" => Ok(HashAlgorithm::Sha512),
            _ => {
                debug!(%hash_alg, "invalid stored PCR hash algorithm");
                Err(Error::corrupted_store())
            }
        }
    }
}
