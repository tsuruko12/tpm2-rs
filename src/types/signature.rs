use der::{Sequence, asn1::UintRef};
use tracing::debug;

use super::{
    algorithm::HashAlgorithm,
    tpm::{Tpm2bEccParameter, Tpm2bPublicKeyRsa},
};
use crate::{Error, Result};

const SEQUENCE_TAG: u8 = 0x30;

#[derive(Clone)]
pub struct RsaSignature {
    hash_alg: HashAlgorithm,
    value: Tpm2bPublicKeyRsa,
}

impl std::fmt::Debug for RsaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaSignature")
            .field("hash_alg", &self.hash_alg)
            .field("value", &self.value.as_bytes())
            .finish()
    }
}

impl PartialEq for RsaSignature {
    fn eq(&self, other: &Self) -> bool {
        self.hash_alg == other.hash_alg && self.value.as_bytes() == other.value.as_bytes()
    }
}

impl Eq for RsaSignature {}

impl RsaSignature {
    pub(crate) fn new(hash_alg: HashAlgorithm, value: Tpm2bPublicKeyRsa) -> Self {
        Self { hash_alg, value }
    }

    pub fn hash_alg(&self) -> HashAlgorithm {
        self.hash_alg
    }

    pub fn value(&self) -> &[u8] {
        self.value.as_bytes()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EccSignature {
    hash_alg: HashAlgorithm,
    r: Tpm2bEccParameter,
    s: Tpm2bEccParameter,
}

impl std::fmt::Debug for EccSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EccSignature")
            .field("hash_alg", &self.hash_alg)
            .field("r", &self.r.as_bytes())
            .field("s", &self.s.as_bytes())
            .finish()
    }
}

impl EccSignature {
    pub(crate) fn new(hash_alg: HashAlgorithm, r: Tpm2bEccParameter, s: Tpm2bEccParameter) -> Self {
        Self { hash_alg, r, s }
    }

    pub fn hash_alg(&self) -> HashAlgorithm {
        self.hash_alg
    }

    pub fn r(&self) -> &[u8] {
        self.r.as_bytes()
    }

    pub fn s(&self) -> &[u8] {
        self.s.as_bytes()
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
    Ecdsa(EcdsaSignature),
    RsaSsa(RsaSignature),
    RsaPss(RsaSignature),
}

impl Signature {
    pub fn ecdsa(hash_alg: HashAlgorithm, value: &[u8]) -> Result<Self> {
        if value.first().copied() != Some(SEQUENCE_TAG) {
            debug!("invalid ECDSA signature: value is not DER-encoded");
            return Err(Error::InvalidSignature);
        }

        let ecc_sig = EcdsaSignature {
            hash_alg,
            value: value.to_vec(),
        };

        Ok(Self::Ecdsa(ecc_sig))
    }

    pub fn rsa_pss(hash_alg: HashAlgorithm, value: &[u8]) -> Result<Self> {
        let rsa_sig = RsaSignature {
            hash_alg,
            value: value.try_into().map_err(|e| {
                debug!("{e:?}");
                Error::InvalidSignature
            })?,
        };

        Ok(Self::RsaPss(rsa_sig))
    }

    pub fn rsa_ssa(hash_alg: HashAlgorithm, value: &[u8]) -> Result<Self> {
        let rsa_sig = RsaSignature {
            hash_alg,
            value: value.try_into().map_err(|e| {
                debug!("{e:?}");
                Error::InvalidSignature
            })?,
        };

        Ok(Self::RsaSsa(rsa_sig))
    }

    pub fn hash_alg(&self) -> HashAlgorithm {
        match self {
            Self::RsaPss(rsa_sig) | Self::RsaSsa(rsa_sig) => rsa_sig.hash_alg,
            Self::Ecdsa(ecdsa_sig) => ecdsa_sig.hash_alg,
        }
    }

    pub fn value(&self) -> &[u8] {
        match self {
            Self::RsaPss(rsa_sig) | Self::RsaSsa(rsa_sig) => rsa_sig.value(),
            Self::Ecdsa(ecdsa_sig) => ecdsa_sig.value(),
        }
    }
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
