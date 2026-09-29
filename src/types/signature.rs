use super::algorithm::{EccSignature, HashAlgorithm, RsaSignature};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    RsaSsa(RsaSignature),
    RsaPss(RsaSignature),
    Ecdsa(EccSignature),
}

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
