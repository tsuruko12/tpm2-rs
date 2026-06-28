use super::HashAlgorithm;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccCurve {
    NistP256,
    NistP384,
    NistP521,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccScheme {
    EcDsa(HashAlgorithm),
    EcDh(HashAlgorithm),
}