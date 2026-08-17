use crate::{
    Error, Result,
    macros::{newtype, tpm_list_type},
    types::{Tpm2bDigest, algorithm::HashAlgorithm},
};

use super::TpmAlgId;

newtype!(TpmiAlgHash(TpmAlgId));

impl TpmiAlgHash {
    pub(crate) const SHA1: Self = Self(TpmAlgId::Sha1);
    pub(crate) const SHA256: Self = Self(TpmAlgId::Sha256);
    pub(crate) const SHA384: Self = Self(TpmAlgId::Sha384);
    pub(crate) const SHA512: Self = Self(TpmAlgId::Sha512);
    pub(crate) const SHA256_192: Self = Self(TpmAlgId::Sha256_192);
    pub(crate) const SM3_256: Self = Self(TpmAlgId::Sm3_256);
    pub(crate) const SHA3_256: Self = Self(TpmAlgId::Sha3_256);
    pub(crate) const SHA3_384: Self = Self(TpmAlgId::Sha3_384);
    pub(crate) const SHA3_512: Self = Self(TpmAlgId::Sha3_512);
    pub(crate) const SHAKE256_192: Self = Self(TpmAlgId::Shake256_192);
    pub(crate) const SHAKE256_256: Self = Self(TpmAlgId::Shake256_256);
    pub(crate) const SHAKE256_512: Self = Self(TpmAlgId::Shake256_512);
    pub(crate) const NULL: Self = Self(TpmAlgId::Null);
}

impl TryFrom<TpmAlgId> for TpmiAlgHash {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        match alg {
            TpmAlgId::Sha1
            | TpmAlgId::Sha256
            | TpmAlgId::Sha384
            | TpmAlgId::Sha512
            | TpmAlgId::Sha256_192
            | TpmAlgId::Null
            | TpmAlgId::Sm3_256
            | TpmAlgId::Sha3_256
            | TpmAlgId::Sha3_384
            | TpmAlgId::Sha3_512
            | TpmAlgId::Shake256_192
            | TpmAlgId::Shake256_256
            | TpmAlgId::Shake256_512 => Ok(Self(alg)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgHash>(Some(&alg))),
        }
    }
}

impl TryFrom<u16> for TpmiAlgHash {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        Self::try_from(TpmAlgId::try_from(value)?)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmsSchemeHash {
    pub(crate) hash_alg: TpmiAlgHash,
}

impl From<HashAlgorithm> for TpmiAlgHash {
    fn from(hash_alg: HashAlgorithm) -> Self {
        match hash_alg {
            HashAlgorithm::Sha1 => Self::SHA1,
            HashAlgorithm::Sha256 => Self::SHA256,
            HashAlgorithm::Sha384 => Self::SHA384,
            HashAlgorithm::Sha512 => Self::SHA512,
        }
    }
}

impl From<HashAlgorithm> for TpmsSchemeHash {
    fn from(hash_alg: HashAlgorithm) -> Self {
        Self {
            hash_alg: hash_alg.into(),
        }
    }
}

impl From<TpmiAlgHash> for TpmsSchemeHash {
    fn from(hash_alg: TpmiAlgHash) -> Self {
        Self { hash_alg }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TpmtHa {
    hash_alg: TpmiAlgHash,
    digest: TpmuHa,
}

impl TpmtHa {
    pub(crate) const MAX_BYTES: usize = size_of::<TpmAlgId>() + Tpm2bDigest::MAX_BYTES;
}

#[derive(Debug, Clone)]
enum TpmuHa {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
    Sha384([u8; 48]),
    Sha512([u8; 64]),
    Sha256_192([u8; 24]),
    Sm3_256([u8; 32]),
    Sha3_256([u8; 32]),
    Sha3_384([u8; 48]),
    Sha3_512([u8; 64]),
    Shake256_192([u8; 24]),
    Shake256_256([u8; 32]),
    Shake256_512([u8; 64]),
    Null,
}

#[derive(Default, Clone)]
pub(crate) struct TpmlDigest {
    items: Vec<Tpm2bDigest>,
}

impl TpmlDigest {
    pub(crate) const MAX_COUNT: usize = 8;

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn items(&self) -> &[Tpm2bDigest] {
        &self.items
    }

    pub(crate) fn into_items(self) -> Vec<Tpm2bDigest> {
        self.items
    }
}

impl TryFrom<Vec<Tpm2bDigest>> for TpmlDigest {
    type Error = Error;

    fn try_from(items: Vec<Tpm2bDigest>) -> Result<Self> {
        if items.len() <= Self::MAX_COUNT {
            Ok(Self { items })
        } else {
            Err(Error::conversion::<Vec<Tpm2bDigest>, TpmlDigest>(None))
        }
    }
}

impl TryFrom<&[Tpm2bDigest]> for TpmlDigest {
    type Error = Error;

    fn try_from(items: &[Tpm2bDigest]) -> Result<Self> {
        if items.len() <= Self::MAX_COUNT {
            Ok(Self { items: items.to_vec() })
        } else {
            Err(Error::conversion::<Vec<Tpm2bDigest>, TpmlDigest>(None))
        }
    }
}