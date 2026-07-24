use super::{algorithm::HashAlgorithm, tpm::TpmtSymDefObject};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaTemplate {
    restricted: bool,
    exportable: bool,
    key_bits: RsaKeyBits,
    scheme: Option<RsaScheme>,
    symmetric: TpmtSymDefObject,
}

impl RsaTemplate {
    pub(super) fn storage_parent() -> Self {
        Self {
            restricted: true,
            exportable: false,
            key_bits: RsaKeyBits::DEFAULT,
            scheme: None,
            symmetric: TpmtSymDefObject::aes_128_cfb(),
        }
    }

    pub(super) fn fixed(key_bits: RsaKeyBits, scheme: RsaScheme) -> Self {
        Self {
            restricted: false,
            exportable: false,
            key_bits,
            scheme: Some(scheme),
            symmetric: TpmtSymDefObject::null(),
        }
    }

    pub(super) fn is_storage_parent(&self) -> bool {
        self.restricted && self.scheme.is_none() && !self.symmetric.is_null()
    }

    pub(super) fn set_exportable(&mut self) {
        self.exportable = true;
    }

    pub fn exportable(&self) -> bool {
        self.exportable
    }

    pub fn key_bits(&self) -> RsaKeyBits {
        self.key_bits
    }

    pub fn scheme(&self) -> Option<RsaScheme> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaSignatureScheme {
    RsaSsa,
    RsaPss,
}
