use super::{
    algorithm::HashAlgorithm,
    ecc::{EccCurve, EccScheme, EccTemplate},
    rsa::{RsaKeyBits, RsaScheme, RsaTemplate},
    symmetric::{SymmetricKeyBits, SymmetricTemplate},
};

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyTemplate {
    Rsa(RsaTemplate),
    Ecc(EccTemplate),
    Symmetric(SymmetricTemplate),
}

impl KeyTemplate {
    pub fn storage_root_key() -> Self {
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

    pub fn rsa(key_bits: RsaKeyBits, scheme: RsaScheme) -> Self {
        Self::Rsa(RsaTemplate::fixed(key_bits, scheme))
    }

    pub fn ecc(curve: EccCurve, scheme: EccScheme) -> Self {
        Self::Ecc(EccTemplate::fixed(curve, scheme))
    }

    pub fn exportable(mut self) -> Result<Self> {
        match &mut self {
            Self::Ecc(template) => template.set_exportable(),
            Self::Rsa(template) => {
                if template.is_storage_parent() {
                    return Err(Error::invalid_param(
                        "storage root key must not be exportable",
                    ));
                }

                template.set_exportable();
            }
            Self::Symmetric(_) => {
                return Err(Error::invalid_param("symmetric key must not be exportable"));
            }
        }

        Ok(self)
    }
}
