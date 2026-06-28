use super::HashAlgorithm;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeyBits {
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaScheme {
    Oaep(HashAlgorithm),
    RsaSsa(HashAlgorithm),
    RsaPss(HashAlgorithm),
    RsaEs,
}

impl RsaScheme {
    pub fn oaep() -> Self {
        Self::Oaep(HashAlgorithm::Sha256)
    }

    pub fn rsa_ssa() -> Self {
        Self::RsaSsa(HashAlgorithm::Sha256)
    }

    pub fn rsa_pss() -> Self {
        Self::RsaPss(HashAlgorithm::Sha256)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaSignatureScheme {
    RsaSsa,
    RsaPss,
}
