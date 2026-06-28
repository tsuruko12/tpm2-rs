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

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CipherMode {
    Gcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SymmetricKeySpec {
    pub(crate) block_cipher: BlockCipher,
    pub(crate) key_bits: SymmetricKeyBits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymmetricAlgorithm {
    Aes,
    Camellia,
}
