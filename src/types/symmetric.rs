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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockCipher {
    Aes,
    Camellia,
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
}
