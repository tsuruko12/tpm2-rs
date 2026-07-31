use tss_esapi::{interface_types::algorithm::SymmetricMode, structures::SymmetricDefinitionObject};

use crate::{
    Error, Result,
    types::{TpmiAlgSymMode, TpmiAlgSymObject, TpmtSymDefObject},
};

impl TryFrom<SymmetricDefinitionObject> for TpmtSymDefObject {
    type Error = Error;

    fn try_from(sym_def_obj: SymmetricDefinitionObject) -> Result<Self> {
        match sym_def_obj {
            SymmetricDefinitionObject::Aes { key_bits, mode } => Ok(Self::new(
                TpmiAlgSymObject::AES,
                u16::from(key_bits).into(),
                mode.into(),
            )),
            SymmetricDefinitionObject::Camellia { key_bits, mode } => Ok(Self::new(
                TpmiAlgSymObject::CAMELLIA,
                u16::from(key_bits).into(),
                mode.into(),
            )),
            SymmetricDefinitionObject::Sm4 { key_bits, mode } => Ok(Self::new(
                TpmiAlgSymObject::SM4,
                u16::from(key_bits).into(),
                mode.into(),
            )),
            SymmetricDefinitionObject::Null => Ok(Self::null()),
        }
    }
}

impl From<SymmetricMode> for TpmiAlgSymMode {
    fn from(mode: SymmetricMode) -> Self {
        match mode {
            SymmetricMode::Cbc => Self::CBC,
            SymmetricMode::Cfb => Self::CFB,
            SymmetricMode::Ctr => Self::CTR,
            SymmetricMode::Ecb => Self::ECB,
            SymmetricMode::Ofb => Self::OFB,
            SymmetricMode::Null => Self::NULL,
        }
    }
}
