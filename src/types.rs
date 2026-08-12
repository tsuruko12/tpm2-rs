pub mod algorithm;
mod authorization;
pub mod hierarchy;
pub mod key;
pub mod policy;
pub mod public;
mod tpm;

pub(crate) use self::authorization::{Authorization, AuthorizationCache};
pub(crate) use self::key::*;
pub(crate) use self::policy::*;
pub(crate) use self::public::{EccCurve, KeyTemplate, RsaScheme, RsaTemplate, SymmetricKeyBits};
pub(crate) use self::tpm::{
    CapabilityData, Tpm2bAuth, Tpm2bDigest, TpmAlgId, TpmCap, TpmCc, TpmEccCurve, TpmHandle,
    TpmKeyBits, TpmPt, TpmPtPcr, TpmaAlgorithm, TpmaCc, TpmaObject, TpmaSession, TpmiAlgEccScheme,
    TpmiAlgHash, TpmiAlgKdf, TpmiAlgPublic, TpmiAlgRsaScheme, TpmiAlgSymMode, TpmiAlgSymObject,
    TpmiDhObject, TpmiDhPersistent, TpmiEccCurve, TpmiRhProvision, TpmiRsaKeyBits, TpmlAlgProperty,
    TpmlCc, TpmlCca, TpmlEccCurve, TpmlHandle, TpmlPcrSelection, TpmlTaggedPcrProperty,
    TpmlTaggedTpmProperty, TpmsAlgProperty, TpmsEccParms, TpmsEmpty, TpmsKeyedHashParms,
    TpmsPcrSelection, TpmsRsaParms, TpmsSchemeEcdaa, TpmsSchemeHash, TpmsSchemeXor, TpmsEccPoint,
    TpmsTaggedPcrSelect, TpmsTaggedProperty, TpmtEccScheme, TpmtKdfScheme, TpmtKeyedHashScheme,
    TpmtPublic, TpmtRsaScheme, TpmtSigScheme, TpmtSymDefObject, TpmuEccScheme, TpmuKdfScheme,
    TpmuPublicId, TpmuPublicParms, TpmuRsaScheme, TpmuSchemeKeyedHash, TpmuSigScheme, TpmsSymCipherParms,
    TpmiAlgKeyedHashScheme, Tpm2bPublic, Tpm2bPrivate, Tpm2bName, TpmMarshal, TpmUnmarshal, 
    Tpm2bPublicKeyRsa, Tpm2bEccParameter, TpmiRhHierarchy, TpmlDigest,
    marshal_tpm2b, read_tpm2b, read_u16, read_u32, read_vec,
};
#[cfg(target_os = "windows")]
pub(crate) use self::tpm::{marshal_list, unmarshal_list};
