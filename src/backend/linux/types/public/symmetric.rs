use tss_esapi::{
    interface_types::algorithm::SymmetricMode,
    structures::SymmetricDefinitionObject,
    tss2_esys::{TPMS_SYMCIPHER_PARMS, TPMT_SYM_DEF_OBJECT, TPMU_SYM_KEY_BITS, TPMU_SYM_MODE},
};

use crate::{
    Error, Result,
    types::tpm::{
        TpmAlgId, TpmiAlgSymMode, TpmiAlgSymObject, TpmtSymDefObject, TpmuPublicParms,
    },
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

impl TryFrom<TPMS_SYMCIPHER_PARMS> for TpmuPublicParms {
    type Error = Error;

    fn try_from(sym_cipher_params: TPMS_SYMCIPHER_PARMS) -> Result<Self> {
        Ok(Self::SymDetail(TpmtSymDefObject::try_from(sym_cipher_params.sym)?.into()))
    }
}

impl TryFrom<TPMT_SYM_DEF_OBJECT> for TpmtSymDefObject {
    type Error = Error;

    fn try_from(sym_def: TPMT_SYM_DEF_OBJECT) -> Result<Self> {
        let algorithm = TpmAlgId::try_from(sym_def.algorithm)?;
        let (key_bits, mode) = match algorithm {
            TpmAlgId::Tdes => unsafe { (sym_def.keyBits.sym, sym_def.mode.sym) },
            TpmAlgId::Aes => unsafe { (sym_def.keyBits.aes, sym_def.mode.aes) },
            TpmAlgId::Sm4 => unsafe { (sym_def.keyBits.sm4, sym_def.mode.sm4) },
            TpmAlgId::Camellia => unsafe { (sym_def.keyBits.camellia, sym_def.mode.camellia) },
            TpmAlgId::Null => return Ok(Self::null()),
            _ => return Err(Error::conversion::<TpmAlgId, TpmtSymDefObject>(Some(&algorithm))),
        };

        Ok(Self::new(
            TpmiAlgSymObject::try_from(algorithm)?,
            key_bits.into(),
            TpmiAlgSymMode::try_from(mode)?,
        ))
    }
}

impl TryFrom<TpmtSymDefObject> for TPMT_SYM_DEF_OBJECT {
    type Error = Error;

    fn try_from(sym_def: TpmtSymDefObject) -> Result<Self> {
        let algorithm = sym_def.algorithm();
        let alg = TpmAlgId::try_from(algorithm.value())?;
        let (key_bits, mode) = match alg {
            TpmAlgId::Tdes => (
                TPMU_SYM_KEY_BITS { sym: sym_def.key_bits().value() },
                TPMU_SYM_MODE { sym: sym_def.mode().value() },
            ),
            TpmAlgId::Aes => (
                TPMU_SYM_KEY_BITS { aes: sym_def.key_bits().value() },
                TPMU_SYM_MODE { aes: sym_def.mode().value() },
            ),
            TpmAlgId::Sm4 => (
                TPMU_SYM_KEY_BITS { sm4: sym_def.key_bits().value() },
                TPMU_SYM_MODE { sm4: sym_def.mode().value() },
            ),
            TpmAlgId::Camellia => (
                TPMU_SYM_KEY_BITS { camellia: sym_def.key_bits().value() },
                TPMU_SYM_MODE { camellia: sym_def.mode().value() },
            ),
            TpmAlgId::Null => {
                if !sym_def.is_null() {
                    return Err(Error::invalid_state(
                        "symmetric definition algorithm and details are inconsistent",
                    ));
                }

                (TPMU_SYM_KEY_BITS::default(), TPMU_SYM_MODE::default())
            }
            _ => return Err(Error::conversion::<TpmAlgId, TPMT_SYM_DEF_OBJECT>(Some(&alg))),
        };

        Ok(Self {
            algorithm: algorithm.value(),
            keyBits: key_bits,
            mode,
        })
    }
}
