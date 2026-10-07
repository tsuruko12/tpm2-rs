use der::{Sequence, asn1::UintRef};

use crate::{Error, Result};

use super::algorithm::HashAlgorithm;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaSignature {
    hash_alg: HashAlgorithm,
    value: Vec<u8>,
}

impl RsaSignature {
    pub(crate) fn new(hash_alg: HashAlgorithm, value: &[u8]) -> Self {
        Self {
            hash_alg,
            value: value.to_vec(),
        }
    }

    pub fn hash_alg(&self) -> HashAlgorithm {
        self.hash_alg
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignature {
    hash_alg: HashAlgorithm,
    value: Vec<u8>, // DER format
}

impl EcdsaSignature {
    pub(crate) fn new(hash_alg: HashAlgorithm, value: Vec<u8>) -> Self {
        Self { hash_alg, value }
    }

    pub fn hash_alg(&self) -> HashAlgorithm {
        self.hash_alg
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    RsaSsa(RsaSignature),
    RsaPss(RsaSignature),
    Ecdsa(EcdsaSignature),
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    RsaSsa(HashAlgorithm),
    RsaPss(HashAlgorithm),
    Ecdsa(HashAlgorithm),
}

impl SignatureScheme {
    pub(crate) fn hash_alg(&self) -> HashAlgorithm {
        match self {
            Self::Ecdsa(hash_alg) | Self::RsaPss(hash_alg) | Self::RsaSsa(hash_alg) => *hash_alg,
        }
    }
}

#[derive(Sequence)]
pub(crate) struct EcdsaDerSignature<'a> {
    pub(crate) r: UintRef<'a>,
    pub(crate) s: UintRef<'a>,
}

impl<'a> EcdsaDerSignature<'a> {
    pub(crate) fn new(r: &'a [u8], s: &'a [u8]) -> Result<Self> {
        Ok(Self {
            r: UintRef::new(r)
                .map_err(|_| Error::invalid_state("failed to create UintRef for r"))?,
            s: UintRef::new(s)
                .map_err(|_| Error::invalid_state("failed to create UintRef for s"))?,
        })
    }
}
