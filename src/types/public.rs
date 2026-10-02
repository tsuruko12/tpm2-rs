pub mod ecc;
pub mod rsa;
pub mod symmetric;

pub use self::{
    ecc::{EccCurve, EccScheme, EccTemplate},
    rsa::{RsaKeyBits, RsaScheme, RsaTemplate},
    symmetric::{BlockCipher, CipherMode, SymmetricKeyBits, SymmetricTemplate},
};
use super::algorithm::HashAlgorithm;

// Note: about object attributes
// https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf (P.182)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyTemplate {
    Srk(RsaTemplate),
    Rsa(RsaTemplate),
    Ecc(EccTemplate),
    Symmetric(SymmetricTemplate),
}

impl KeyTemplate {
    pub fn storage_root() -> Self {
        Self::Rsa(RsaTemplate::storage_parent())
    }

    pub fn storage_parent() -> Self {
        Self::Rsa(RsaTemplate::storage_parent())
    }

    pub fn rsa_decrypt() -> Self {
        let scheme = RsaScheme::Oaep(HashAlgorithm::DEFAULT);
        Self::Rsa(RsaTemplate::fixed(RsaKeyBits::DEFAULT, scheme))
    }

    pub fn rsa_sign() -> Self {
        let scheme = RsaScheme::RsaPss(HashAlgorithm::DEFAULT);
        Self::Rsa(RsaTemplate::fixed(RsaKeyBits::DEFAULT, scheme))
    }

    pub fn ecc_sign() -> Self {
        let scheme = EccScheme::Ecdsa(HashAlgorithm::DEFAULT);
        Self::Ecc(EccTemplate::fixed(EccCurve::DEFAULT, scheme))
    }

    pub fn attestation_sign() -> Self {
        let scheme = EccScheme::Ecdsa(HashAlgorithm::DEFAULT);
        Self::Ecc(
            EccTemplate::fixed(EccCurve::DEFAULT, scheme)
                .with_restricted(true)
        )
    }

    pub fn aes_gcm_128() -> Self {
        Self::Symmetric(SymmetricTemplate::aes(SymmetricKeyBits::Bits128))
    }

    pub fn aes_gcm_256() -> Self {
        Self::Symmetric(SymmetricTemplate::aes(SymmetricKeyBits::Bits256))
    }

    pub fn camellia_gcm_128() -> Self {
        Self::Symmetric(SymmetricTemplate::camellia(SymmetricKeyBits::Bits128))
    }

    pub fn camellia_gcm_256() -> Self {
        Self::Symmetric(SymmetricTemplate::camellia(SymmetricKeyBits::Bits256))
    }

    pub fn rsa(template: RsaTemplate) -> Self {
        Self::Rsa(template)
    }

    pub fn ecc(template: EccTemplate) -> Self {
        Self::Ecc(template)
    }

    pub(crate) fn is_storage_parent(&self) -> bool {
        match self {
            Self::Srk(_) => true,
            Self::Rsa(template) => template.is_storage_parent(),
            _ => false,
        }
    }
}
