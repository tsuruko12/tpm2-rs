use super::TpmAlgId;
use crate::{Error, Result, macros::newtype, types::tpm::TpmsEmpty};

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmsSymCipherParms {
    sym: TpmtSymDefObject,
}

impl From<TpmtSymDefObject> for TpmsSymCipherParms {
    fn from(sym: TpmtSymDefObject) -> Self {
        Self { sym }
    }
}

impl TpmsSymCipherParms {
    pub(crate) fn sym(self) -> TpmtSymDefObject {
        self.sym
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TpmtSymDefObject {
    algorithm: TpmiAlgSymObject,
    key_bits: TpmKeyBits,
    mode: TpmuSymMode,
}
// details field isn't used for now

impl TpmtSymDefObject {
    pub(crate) fn new(
        algorithm: TpmiAlgSymObject,
        key_bits: TpmKeyBits,
        mode: TpmuSymMode,
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
            TpmuSymMode::Aes(TpmiAlgSymMode::CFB),
        )
    }

    pub(crate) fn null() -> Self {
        Self::new(
            TpmiAlgSymObject::NULL,
            TpmKeyBits::NULL,
            TpmuSymMode::null(),
        )
    }

    pub(crate) fn is_null(&self) -> bool {
        self.algorithm == TpmiAlgSymObject::NULL
            && self.key_bits == TpmKeyBits::NULL
            && self.mode == TpmuSymMode::null()
    }

    pub(crate) fn algorithm(&self) -> TpmiAlgSymObject {
        self.algorithm
    }

    pub(crate) fn key_bits(&self) -> TpmKeyBits {
        self.key_bits
    }

    pub(crate) fn mode(&self) -> TpmuSymMode {
        self.mode
    }
}

newtype!(TpmiAlgSymObject(TpmAlgId));

impl TpmiAlgSymObject {
    pub(crate) const AES: Self = Self(TpmAlgId::Aes);
    pub(crate) const SM4: Self = Self(TpmAlgId::Sm4);
    pub(crate) const CAMELLIA: Self = Self(TpmAlgId::Camellia);
    pub(crate) const NULL: Self = Self(TpmAlgId::Null);
}

impl TryFrom<TpmAlgId> for TpmiAlgSymObject {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        match alg {
            TpmAlgId::Tdes
            | TpmAlgId::Aes
            | TpmAlgId::Sm4
            | TpmAlgId::Camellia
            | TpmAlgId::Null => Ok(Self(alg)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgSymObject>(Some(&alg))),
        }
    }
}

newtype!(TpmKeyBits(u16));

impl TpmKeyBits {
    pub(super) const AES_128: Self = Self(128);
    pub(super) const NULL: Self = Self(0);
}

impl From<u16> for TpmKeyBits {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TpmuSymMode {
    Aes(TpmiAlgSymMode),
    Sm4(TpmiAlgSymMode),
    Camellia(TpmiAlgSymMode),
    Null(TpmsEmpty),
}

impl TpmuSymMode {
    fn null() -> Self {
        Self::Null(TpmsEmpty)
    }
}

newtype!(TpmiAlgSymMode(TpmAlgId));

impl TpmiAlgSymMode {
    pub(crate) const CFB: Self = Self(TpmAlgId::Cfb);
    pub(crate) const CTR: Self = Self(TpmAlgId::Ctr);
    pub(crate) const OFB: Self = Self(TpmAlgId::Ofb);
    pub(crate) const CBC: Self = Self(TpmAlgId::Cbc);
    pub(crate) const ECB: Self = Self(TpmAlgId::Ecb);
    pub(crate) const NULL: Self = Self(TpmAlgId::Null);
}

impl TryFrom<TpmAlgId> for TpmiAlgSymMode {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        match alg {
            TpmAlgId::Ctr
            | TpmAlgId::Ofb
            | TpmAlgId::Cbc
            | TpmAlgId::Cfb
            | TpmAlgId::Ecb
            | TpmAlgId::Cmac
            | TpmAlgId::Null => Ok(Self(alg)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgSymMode>(Some(&alg))),
        }
    }
}
