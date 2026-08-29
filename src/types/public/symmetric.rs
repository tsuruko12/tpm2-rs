use tracing::debug;

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymmetricTemplate {
    block_cipher: BlockCipher,
    key_bits: SymmetricKeyBits,
    mode: CipherMode,
}

impl SymmetricTemplate {
    pub(super) fn aes(key_bits: SymmetricKeyBits) -> Self {
        Self {
            block_cipher: BlockCipher::Aes,
            key_bits,
            mode: CipherMode::DEFAULT,
        }
    }

    pub(super) fn camellia(key_bits: SymmetricKeyBits) -> Self {
        Self {
            block_cipher: BlockCipher::Camellia,
            key_bits,
            mode: CipherMode::DEFAULT,
        }
    }

    pub fn block_cipher(&self) -> BlockCipher {
        self.block_cipher
    }

    pub fn key_bits(&self) -> SymmetricKeyBits {
        self.key_bits
    }

    pub fn mode(&self) -> CipherMode {
        self.mode
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymmetricKeyBits {
    Bits128,
    Bits256,
}

impl SymmetricKeyBits {
    pub(crate) fn as_str(&self) -> u32 {
        match self {
            Self::Bits128 => 128,
            Self::Bits256 => 256,
        }
    }

    pub(crate) fn from_db(value: u32) -> Result<Self> {
        match value {
            128 => Ok(Self::Bits128),
            256 => Ok(Self::Bits256),
            _ => {
                debug!("stored symmetric key size is invalid");
                Err(Error::corrupted_store())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockCipher {
    Aes,
    Camellia,
}

impl BlockCipher {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Aes => "aes",
            Self::Camellia => "camellia",
        }
    }

    pub(crate) fn from_db(value: &str) -> Result<Self> {
        match value {
            "aes" => Ok(Self::Aes),
            "camellia" => Ok(Self::Camellia),
            _ => {
                debug!(%value, "invalid stored symmetric block cipher");
                Err(Error::corrupted_store())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymmetricAlgorithm {
    Aes,
    Camellia,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    Gcm,
}

impl CipherMode {
    const DEFAULT: Self = Self::Gcm;

    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Gcm => "gcm",
        }
    }

    pub(crate) fn from_db(value: &str) -> Result<Self> {
        match value {
            "gcm" => Ok(Self::Gcm),
            _ => {
                debug!("stored symmetric cipher mode is invalid");
                Err(Error::corrupted_store())
            }
        }
    }
}
