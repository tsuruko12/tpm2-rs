use crate::{Error, Result, macros::newtype};

use super::TpmAlgId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TpmtSymDefObject {
    algorithm: TpmiAlgSymObject,
    key_bits: TpmKeyBits,
    mode: TpmiAlgSymMode,
}

impl TpmtSymDefObject {
    pub(crate) fn new(
        algorithm: TpmiAlgSymObject,
        key_bits: TpmKeyBits,
        mode: TpmiAlgSymMode,
    ) -> Self {
        Self {
            algorithm,
            key_bits,
            mode,
        }
    }

    pub(crate) fn aes_128_cfb() -> Self {
        Self::new(
            TpmiAlgSymObject::AES,
            TpmKeyBits::AES_128,
            TpmiAlgSymMode::CFB
        )
    }

    pub(crate) fn null() -> Self {
        Self::new(
            TpmiAlgSymObject::NULL,
            TpmKeyBits::NULL,
            TpmiAlgSymMode::NULL,
        )
    }

    pub(crate) fn is_null(&self) -> bool {
        self.algorithm == TpmiAlgSymObject::NULL
            && self.key_bits == TpmKeyBits::NULL
            && self.mode == TpmiAlgSymMode::NULL
    }

    pub(crate) fn algorithm(&self) -> TpmiAlgSymObject {
        self.algorithm
    } 

    pub(crate) fn key_bits(&self) -> TpmKeyBits {
        self.key_bits
    } 
  
    pub(crate) fn mode(&self) -> TpmiAlgSymMode {
        self.mode
    } 

}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TpmiAlgSymObject(TpmAlgId);

impl TpmiAlgSymObject {
    pub(super) const AES: Self = Self(TpmAlgId::Aes);
    pub(super) const NULL: Self = Self(TpmAlgId::Null);

    pub(crate) fn raw(self) -> u16 {
        self.0.raw()
    }
}

impl TryFrom<u16> for TpmiAlgSymObject {
    type Error = Error;

    fn try_from(raw: u16) -> Result<Self> {
        TpmAlgId::try_from(raw)?.try_into()
    }
}

impl TryFrom<TpmAlgId> for TpmiAlgSymObject {
    type Error = Error;

    fn try_from(alg_id: TpmAlgId) -> Result<Self> {
        match alg_id {
            TpmAlgId::Tdes
            | TpmAlgId::Aes
            | TpmAlgId::Sm4
            | TpmAlgId::Camellia
            | TpmAlgId::Null => Ok(Self(alg_id)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgSymObject>()),
        }
    }
}

newtype!(TpmKeyBits(u16));

impl TpmKeyBits {
    pub(super) const AES_128: Self = Self(128);
    pub(super) const NULL: Self = Self(0);
}

impl From<u16> for TpmKeyBits {
    fn from(raw: u16) -> Self {
        Self(raw)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TpmiAlgSymMode(TpmAlgId);

impl TpmiAlgSymMode {
    pub(super) const CFB: Self = Self(TpmAlgId::Cfb);
    pub(super) const NULL: Self = Self(TpmAlgId::Null);

    pub(crate) fn raw(self) -> u16 {
        self.0.raw()
    }
}

impl TryFrom<u16> for TpmiAlgSymMode {
    type Error = Error;

    fn try_from(raw: u16) -> Result<Self> {
        TpmAlgId::try_from(raw)?.try_into()
    }
}

impl TryFrom<TpmAlgId> for TpmiAlgSymMode {
    type Error = Error;

    fn try_from(alg_id: TpmAlgId) -> Result<Self> {
        match alg_id {
            TpmAlgId::Ctr
            | TpmAlgId::Ofb
            | TpmAlgId::Cbc
            | TpmAlgId::Cfb
            | TpmAlgId::Ecb
            | TpmAlgId::Cmac
            | TpmAlgId::Null => Ok(Self(alg_id)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgSymMode>()),
        }
    }
}
