use super::super::{algorithm::HashAlgorithm, tpm::TpmtSymDefObject};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaTemplate {
    restricted: bool,
    exportable: bool,
    key_bits: RsaKeyBits,
    decrypt: bool,
    sign: bool,
    scheme: Option<RsaScheme>,
    symmetric: TpmtSymDefObject,
}

impl RsaTemplate {
    pub fn decrypt(key_bits: RsaKeyBits, scheme: RsaDecryptScheme) -> Self {
        Self::unrestricted_decrypt(key_bits, scheme.into())
    }

    pub fn sign(key_bits: RsaKeyBits, scheme: RsaSignScheme) -> Self {
        Self::unrestricted_sign(key_bits, scheme.into())
    }

    pub fn sign_decrypt(key_bits: RsaKeyBits) -> Self {
        Self {
            restricted: false,
            exportable: false,
            key_bits,
            decrypt: true,
            sign: true,
            scheme: None,
            symmetric: TpmtSymDefObject::null(),
        }
    }

    pub(super) fn storage_parent() -> Self {
        Self {
            restricted: true,
            exportable: false,
            key_bits: RsaKeyBits::DEFAULT,
            decrypt: true,
            sign: false,
            scheme: None,
            symmetric: TpmtSymDefObject::aes_128_cfb(),
        }
    }

    pub(super) fn unrestricted_decrypt(key_bits: RsaKeyBits, scheme: RsaScheme) -> Self {
        Self {
            restricted: false,
            exportable: false,
            key_bits,
            decrypt: true,
            sign: false,
            scheme: Some(scheme),
            symmetric: TpmtSymDefObject::null(),
        }
    }

    pub(super) fn unrestricted_sign(key_bits: RsaKeyBits, scheme: RsaScheme) -> Self {
        Self {
            restricted: false,
            exportable: false,
            key_bits,
            decrypt: false,
            sign: true,
            scheme: Some(scheme),
            symmetric: TpmtSymDefObject::null(),
        }
    }

    pub(crate) fn is_storage_parent(&self) -> bool {
        self.restricted && self.scheme.is_none() && !self.symmetric.is_null()
    }

    pub fn with_exportable(mut self, exportable: bool) -> Self {
        self.exportable = exportable;
        self
    }

    pub(crate) fn is_exportable(&self) -> bool {
        self.exportable
    }

    pub(crate) fn is_restricted(&self) -> bool {
        self.restricted
    }

    pub(crate) fn key_bits(&self) -> RsaKeyBits {
        self.key_bits
    }

    pub(crate) fn scheme(&self) -> Option<RsaScheme> {
        self.scheme
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeyBits {
    Bits2048,
    Bits3072,
    Bits4096,
}

impl RsaKeyBits {
    pub(super) const DEFAULT: Self = Self::Bits3072;
    pub(crate) const MAX_BITS: usize = 4096;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaScheme {
    Oaep(HashAlgorithm),
    RsaSsa(HashAlgorithm),
    RsaPss(HashAlgorithm),
    RsaEs,
}

impl RsaScheme {
    pub fn oaep_sha256() -> Self {
        Self::Oaep(HashAlgorithm::DEFAULT)
    }

    pub fn rsa_ssa_sha256() -> Self {
        Self::RsaSsa(HashAlgorithm::DEFAULT)
    }

    pub fn rsa_pss_sha256() -> Self {
        Self::RsaPss(HashAlgorithm::DEFAULT)
    }
}

impl From<RsaDecryptScheme> for RsaScheme {
    fn from(rsa_decrypt_scheme: RsaDecryptScheme) -> Self {
        match rsa_decrypt_scheme {
            RsaDecryptScheme::Oaep(hash_alg) => Self::Oaep(hash_alg),
            RsaDecryptScheme::RsaEs => Self::RsaEs,
        }
    }
}

impl From<RsaSignScheme> for RsaScheme {
    fn from(rsa_sign_scheme: RsaSignScheme) -> Self {
        match rsa_sign_scheme {
            RsaSignScheme::RsaSsa(hash_alg) => Self::RsaSsa(hash_alg),
            RsaSignScheme::RsaPss(hash_alg) => Self::RsaPss(hash_alg),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaDecryptScheme {
    Oaep(HashAlgorithm),
    RsaEs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaSignScheme {
    RsaSsa(HashAlgorithm),
    RsaPss(HashAlgorithm),
}
