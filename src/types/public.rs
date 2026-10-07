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
        Self::Srk(RsaTemplate::storage_parent())
    }

    pub fn storage_parent() -> Self {
        Self::Rsa(RsaTemplate::storage_parent())
    }

    pub fn rsa_decrypt() -> Self {
        let scheme = RsaScheme::Oaep(HashAlgorithm::DEFAULT);
        Self::Rsa(RsaTemplate::unrestricted_decrypt(
            RsaKeyBits::DEFAULT,
            scheme,
        ))
    }

    pub fn rsa_sign() -> Self {
        let scheme = RsaScheme::RsaPss(HashAlgorithm::DEFAULT);
        Self::Rsa(RsaTemplate::unrestricted_sign(RsaKeyBits::DEFAULT, scheme))
    }

    pub fn ecc_sign() -> Self {
        let scheme = EccScheme::Ecdsa(HashAlgorithm::DEFAULT);
        Self::Ecc(EccTemplate::unrestricted(EccCurve::DEFAULT, scheme))
    }

    pub fn attestation_sign() -> Self {
        let scheme: EccScheme = EccScheme::Ecdsa(HashAlgorithm::DEFAULT);
        Self::Ecc(EccTemplate::restricted(EccCurve::DEFAULT, scheme))
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
}
