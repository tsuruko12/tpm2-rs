mod capability;
mod random;
mod tbs;

use std::ffi::c_void;

use super::{
    codec::marshal_be,
    codec::{require_len, unmarshal_tpm2b},
    commands::{Command, CommandHeader, TPM_CC_GET_CAPABILITY, TPM_CC_GET_RANDOM, TPM_HEADER_SIZE},
    types::{CapabilityData, TPM_RC_SUCCESS, TpmRc, TpmSt},
};

type ContextHandle = *mut c_void;

pub struct Context {
    handle: ContextHandle,
}
