use std::{error::Error as StdError, fmt};

use windows_sys::Win32::Foundation::{
    TBS_E_BAD_PARAMETER, TBS_E_INTERNAL_ERROR, TBS_E_IOERROR, TBS_E_SERVICE_DISABLED,
    TBS_E_SERVICE_NOT_RUNNING, TBS_E_SERVICE_START_PENDING, TBS_E_TPM_NOT_FOUND,
};

use super::types::*;
use crate::error::{Error, InternalError};

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
            _ => Self::internal(InternalError::Tbs(code)),
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

impl TpmError {
    pub(crate) fn rc(&self) -> TpmRc {
        match self {
            Self::ResponseCode(rc) => *rc,
        }
    }
}

impl Error {
    pub(crate) fn from_rc(rc: TpmRc) -> Self {
        let source = TpmError::ResponseCode(rc);
        let base = rc.base();

        match base {
            TpmRc::BINDING | TpmRc::KEY | TpmRc::SIGN_CONTEXT_KEY => {
                Self::invalid_key_with_source("selected key is not valid for the operation", source)
            }
            TpmRc::AUTH_FAIL
            | TpmRc::BAD_AUTH
            | TpmRc::PP
            | TpmRc::CHANNEL
            | TpmRc::CHANNEL_KEY
            | TpmRc::POLICY_FAIL
            | TpmRc::POLICY_CC
            | TpmRc::EXPIRED
            | TpmRc::AUTH_MISSING
            | TpmRc::AUTH_UNAVAILABLE
            | TpmRc::NV_AUTHORIZATION
            | TpmRc::LOCKOUT
            | TpmRc::POLICY
            | TpmRc::PCR
            | TpmRc::PCR_CHANGED => Self::authorization_failed(source),
            TpmRc::SIGNATURE => Self::invalid_signature(source),
            TpmRc::NV_SPACE
            | TpmRc::OBJECT_MEMORY
            | TpmRc::SESSION_MEMORY
            | TpmRc::MEMORY
            | TpmRc::SESSION_HANDLES
            | TpmRc::OBJECT_HANDLES
            | TpmRc::TOO_MANY_CONTEXTS => {
                Self::resource_exhausted_with_source("TPM resource exhausted", source)
            }
            TpmRc::YIELDED
            | TpmRc::TESTING
            | TpmRc::NEEDS_TEST
            | TpmRc::NV_RATE
            | TpmRc::RETRY
            | TpmRc::NV_UNAVAILABLE => Self::busy(source),
            TpmRc::DISABLED | TpmRc::COMMAND_CODE | TpmRc::UPGRADE | TpmRc::READ_ONLY => {
                Self::unsupported_with_source(
                    "TPM does not support the requested operation",
                    source,
                )
            }
            TpmRc::ASYMMETRIC
            | TpmRc::HASH
            | TpmRc::KEY_SIZE
            | TpmRc::MGF
            | TpmRc::MODE
            | TpmRc::KDF
            | TpmRc::SCHEME
            | TpmRc::SYMMETRIC
            | TpmRc::CURVE
            | TpmRc::FW_LIMITED
            | TpmRc::SVN_LIMITED
            | TpmRc::PARMS
            | TpmRc::EXT_MU
            | TpmRc::ONE_SHOT_SIGNATURE => {
                Self::unsupported_with_source("TPM does not support the requested value", source)
            }
            TpmRc::AUTH_TYPE
            | TpmRc::BAD_TAG
            | TpmRc::SEQUENCE
            | TpmRc::UNBALANCED
            | TpmRc::COMMAND_SIZE
            | TpmRc::AUTHSIZE
            | TpmRc::AUTH_CONTEXT
            | TpmRc::NV_RANGE
            | TpmRc::NV_SIZE
            | TpmRc::BAD_CONTEXT
            | TpmRc::CPHASH
            | TpmRc::PARENT
            | TpmRc::CONTEXT_GAP
            | TpmRc::LOCALITY
            | TpmRc::REFERENCE_H0
            | TpmRc::REFERENCE_H1
            | TpmRc::REFERENCE_H2
            | TpmRc::REFERENCE_H3
            | TpmRc::REFERENCE_H4
            | TpmRc::REFERENCE_H5
            | TpmRc::REFERENCE_H6
            | TpmRc::REFERENCE_S0
            | TpmRc::REFERENCE_S1
            | TpmRc::REFERENCE_S2
            | TpmRc::REFERENCE_S3
            | TpmRc::REFERENCE_S4
            | TpmRc::REFERENCE_S5
            | TpmRc::REFERENCE_S6 => Self::internal(InternalError::InvalidTpmCommand(rc.raw())),
            _ => Self::failure(source),
        }
    }

    pub(super) fn tpm_rc(&self) -> Option<TpmRc> {
        StdError::source(self)?
            .downcast_ref::<TpmError>()
            .map(TpmError::rc)
    }
}
