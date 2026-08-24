use crate::{
    Error, Result, macros::tpm2b_zeroize_type_in_win, public::RsaKeyBits,
};

tpm2b_zeroize_type_in_win!(Tpm2bEncryptedSecret(TpmuEncryptedSecret));

impl Default for Tpm2bEncryptedSecret {
    fn default() -> Self {
        Self(TpmuEncryptedSecret::Rsa(Vec::new()))
    }
}

pub(in crate::backend::windows) enum TpmuEncryptedSecret {
    Rsa(Vec<u8>),
}

impl TpmuEncryptedSecret {
    pub(in crate::backend::windows) fn value(&self) -> &[u8] {
        match self {
            Self::Rsa(value) => value,
        }
    }

    pub(in crate::backend::windows) fn rsa(value: Vec<u8>) -> Result<Self> {
        if value.len() <= RsaKeyBits::MAX_BITS.div_ceil(8) {
            Ok(Self::Rsa(value.into()))
        } else {
            Err(Error::invalid_state(
                "RSA encrypted secret exceeds maximum size"
            ))
        }
    }
}