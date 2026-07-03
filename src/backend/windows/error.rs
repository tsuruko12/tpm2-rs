use std::{error::Error as StdError, fmt};

use windows_sys::Win32::Foundation::{
    TBS_E_BAD_PARAMETER, TBS_E_INTERNAL_ERROR, TBS_E_IOERROR, TBS_E_SERVICE_DISABLED,
    TBS_E_SERVICE_NOT_RUNNING, TBS_E_SERVICE_START_PENDING, TBS_E_TPM_NOT_FOUND,
};

use super::types::*;
use crate::error::Error;

#[derive(thiserror::Error, Debug)]
pub(crate) enum TbsError {
    #[error("TBS service is disabled")]
    ServiceDisabled,
    #[error("TBS service is not running and could not be started")]
    ServiceNotRunning,
    #[error("TBS service has been started but is not yet running")]
    ServiceStartPending,
    #[error("TPM was not found on this computer")]
    TpmNotFound,
    #[error("TBS communication with the TPM failed")]
    IoError,
    #[error("TBS internal software error occurred")]
    Internal,
}

impl TbsError {
    fn connect(code: u32) -> Self {
        match code as i32 {
            TBS_E_SERVICE_DISABLED => Self::ServiceDisabled,
            TBS_E_SERVICE_NOT_RUNNING => Self::ServiceNotRunning,
            TBS_E_SERVICE_START_PENDING => Self::ServiceStartPending,
            TBS_E_TPM_NOT_FOUND => Self::TpmNotFound,
            _ => unimplemented!(""),
        }
    }

    fn failure(code: u32) -> Self {
        match code as i32 {
            TBS_E_IOERROR => Self::IoError,
            _ => unimplemented!(""),
        }
    }
}

impl Error {
    pub(super) fn from_tbs_rc(code: u32) -> Self {
        match code as i32 {
            TBS_E_SERVICE_DISABLED
            | TBS_E_SERVICE_NOT_RUNNING
            | TBS_E_SERVICE_START_PENDING
            | TBS_E_TPM_NOT_FOUND => Self::connect(TbsError::connect(code)),
            TBS_E_BAD_PARAMETER => Self::invalid_param("invaid parameters"),
            TBS_E_IOERROR => Self::failure(TbsError::failure(code)),
            TBS_E_INTERNAL_ERROR => Self::failure(TbsError::Internal),
            _ => {
                tracing::error!(code, "internal error");
                Self::Internal("unexpected error occured")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TpmError {
    ResponseCode(TpmRc),
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResponseCode(rc) => {
                write!(f, "TPM returned response code {:#05X}", rc.raw())
            }
        }
    }
}

impl StdError for TpmError {}

impl Error {
    pub(crate) fn from_rc(rc: TpmRc) -> Self {
        let source = TpmError::ResponseCode(rc);
        let base = rc.base();

        match base {
            TPM_RC_BINDING | TPM_RC_KEY | TPM_RC_SIGN_CONTEXT_KEY => {
                Self::invalid_key_with_source("selected key is not valid for the operation", source)
            }
            TPM_RC_AUTH_FAIL
            | TPM_RC_BAD_AUTH
            | TPM_RC_PP
            | TPM_RC_CHANNEL
            | TPM_RC_CHANNEL_KEY
            | TPM_RC_POLICY_FAIL
            | TPM_RC_POLICY_CC
            | TPM_RC_EXPIRED
            | TPM_RC_AUTH_MISSING
            | TPM_RC_AUTH_UNAVAILABLE
            | TPM_RC_NV_AUTHORIZATION
            | TPM_RC_LOCKOUT
            | TPM_RC_POLICY
            | TPM_RC_PCR
            | TPM_RC_PCR_CHANGED => Self::authorization_failed(source),
            TPM_RC_SIGNATURE => Self::invalid_signature(source),
            TPM_RC_NV_SPACE
            | TPM_RC_OBJECT_MEMORY
            | TPM_RC_SESSION_MEMORY
            | TPM_RC_MEMORY
            | TPM_RC_SESSION_HANDLES
            | TPM_RC_OBJECT_HANDLES
            | TPM_RC_TOO_MANY_CONTEXTS => {
                Self::resource_exhausted_with_source("TPM resource exhausted", source)
            }
            TPM_RC_YIELDED
            | TPM_RC_TESTING
            | TPM_RC_NEEDS_TEST
            | TPM_RC_NV_RATE
            | TPM_RC_RETRY
            | TPM_RC_NV_UNAVAILABLE => Self::busy(source),
            TPM_RC_DISABLED | TPM_RC_COMMAND_CODE | TPM_RC_UPGRADE | TPM_RC_READ_ONLY => {
                Self::unsupported_with_source(
                    "TPM does not support the requested operation",
                    source,
                )
            }
            TPM_RC_ASYMMETRIC
            | TPM_RC_HASH
            | TPM_RC_KEY_SIZE
            | TPM_RC_MGF
            | TPM_RC_MODE
            | TPM_RC_KDF
            | TPM_RC_SCHEME
            | TPM_RC_SYMMETRIC
            | TPM_RC_CURVE
            | TPM_RC_FW_LIMITED
            | TPM_RC_SVN_LIMITED
            | TPM_RC_PARMS
            | TPM_RC_EXT_MU
            | TPM_RC_ONE_SHOT_SIGNATURE => {
                Self::unsupported_with_source("TPM does not support the requested value", source)
            }
            TPM_RC_AUTH_TYPE
            | TPM_RC_BAD_TAG
            | TPM_RC_SEQUENCE
            | TPM_RC_UNBALANCED
            | TPM_RC_COMMAND_SIZE
            | TPM_RC_AUTHSIZE
            | TPM_RC_AUTH_CONTEXT
            | TPM_RC_NV_RANGE
            | TPM_RC_NV_SIZE
            | TPM_RC_BAD_CONTEXT
            | TPM_RC_CPHASH
            | TPM_RC_PARENT
            | TPM_RC_CONTEXT_GAP
            | TPM_RC_LOCALITY
            | TPM_RC_REFERENCE_H0..=TPM_RC_REFERENCE_H6
            | TPM_RC_REFERENCE_S0..=TPM_RC_REFERENCE_S6 => {
                tracing::error!(
                    rc = format_args!("{:#05X}", rc.raw()),
                    "unexpected TPM response code"
                );
                Self::Internal("unexpected error occurred")
            }
            _ => Self::failure(source),
        }
    }
}
