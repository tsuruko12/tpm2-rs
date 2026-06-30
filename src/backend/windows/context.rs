mod random;
mod tbs;

use std::{ffi::c_void};

use super::{
    commands::{Command, CommandHeader, TPM_CC_GET_RANDOM, TPM_HEADER_SIZE},
    types::{Digest, TpmRc, TpmSt, Uint32, TPM_RC_SUCCESS},
};

type ContextHandle = *mut c_void;

pub struct Context {
    handle: ContextHandle,
}