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
            _ => unimplemented!(""), // memo: change this later
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
    FormatOne {
        rc: TpmRc,
        kind: FormatOneError,
        target: ErrorTarget,
    },
    FormatZero {
        rc: TpmRc,
        kind: FormatZeroError,
    },
    Warning {
        rc: TpmRc,
        kind: TpmWarning,
    },
    Unknown(TpmRc),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorTarget {
    Unspecified,
    Parameter(u8),
    Handle(u8),
    Session(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormatOneError {
    Asymmetric,
    Attributes,
    Hash,
    Value,
    Hierarchy,
    KeySize,
    Mgf,
    Mode,
    Type,
    Handle,
    Kdf,
    Range,
    AuthFail,
    Nonce,
    Pp,
    Scheme,
    Size,
    Symmetric,
    Tag,
    Selector,
    Insufficient,
    Signature,
    Key,
    PolicyFail,
    Integrity,
    Ticket,
    ReservedBits,
    BadAuth,
    Expired,
    PolicyCc,
    Binding,
    Curve,
    EccPoint,
    FwLimited,
    SvnLimited,
    Parms,
    ExtMu,
    OneShotSignature,
    SignContextKey,
    Channel,
    ChannelKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormatZeroError {
    Initialize,
    Failure,
    Sequence,
    Private,
    Hmac,
    Disabled,
    Exclusive,
    AuthType,
    AuthMissing,
    Policy,
    Pcr,
    PcrChanged,
    Upgrade,
    TooManyContexts,
    AuthUnavailable,
    Reboot,
    Unbalanced,
    CommandSize,
    CommandCode,
    AuthSize,
    AuthContext,
    NvRange,
    NvSize,
    NvLocked,
    NvAuthorization,
    NvUninitialized,
    NvSpace,
    NvDefined,
    BadContext,
    CpHash,
    Parent,
    NeedsTest,
    NoResult,
    Sensitive,
    ReadOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TpmWarning {
    ContextGap,
    ObjectMemory,
    SessionMemory,
    Memory,
    SessionHandles,
    ObjectHandles,
    Locality,
    Yielded,
    Canceled,
    Testing,
    ReferenceHandle(u8),
    ReferenceSession(u8),
    NvRate,
    Lockout,
    Retry,
    NvUnavailable,
}

impl From<TpmRc> for TpmError {
    fn from(rc: TpmRc) -> Self {
        let raw = rc.raw();

        if raw & TpmRc::FMT1 != 0 {
            return Self::format_one(rc).unwrap_or(Self::Unknown(rc));
        }

        if (raw & TpmRc::WARN) == TpmRc::WARN {
            return Self::warning(rc).unwrap_or(Self::Unknown(rc));
        }

        Self::format_zero(rc).unwrap_or(Self::Unknown(rc))
    }
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TPM returned response code {self:?}")
    }
}

impl StdError for TpmError {}

impl TpmError {
    fn format_one(rc: TpmRc) -> Option<Self> {
        let kind = match rc.base() {
            TpmRc::ASYMMETRIC => FormatOneError::Asymmetric,
            TpmRc::ATTRIBUTES => FormatOneError::Attributes,
            TpmRc::HASH => FormatOneError::Hash,
            TpmRc::VALUE => FormatOneError::Value,
            TpmRc::HIERARCHY => FormatOneError::Hierarchy,
            TpmRc::KEY_SIZE => FormatOneError::KeySize,
            TpmRc::MGF => FormatOneError::Mgf,
            TpmRc::MODE => FormatOneError::Mode,
            TpmRc::TYPE => FormatOneError::Type,
            TpmRc::HANDLE => FormatOneError::Handle,
            TpmRc::KDF => FormatOneError::Kdf,
            TpmRc::RANGE => FormatOneError::Range,
            TpmRc::AUTH_FAIL => FormatOneError::AuthFail,
            TpmRc::NONCE => FormatOneError::Nonce,
            TpmRc::PP => FormatOneError::Pp,
            TpmRc::SCHEME => FormatOneError::Scheme,
            TpmRc::SIZE => FormatOneError::Size,
            TpmRc::SYMMETRIC => FormatOneError::Symmetric,
            TpmRc::TAG => FormatOneError::Tag,
            TpmRc::SELECTOR => FormatOneError::Selector,
            TpmRc::INSUFFICIENT => FormatOneError::Insufficient,
            TpmRc::SIGNATURE => FormatOneError::Signature,
            TpmRc::KEY => FormatOneError::Key,
            TpmRc::POLICY_FAIL => FormatOneError::PolicyFail,
            TpmRc::INTEGRITY => FormatOneError::Integrity,
            TpmRc::TICKET => FormatOneError::Ticket,
            TpmRc::RESERVED_BITS => FormatOneError::ReservedBits,
            TpmRc::BAD_AUTH => FormatOneError::BadAuth,
            TpmRc::EXPIRED => FormatOneError::Expired,
            TpmRc::POLICY_CC => FormatOneError::PolicyCc,
            TpmRc::BINDING => FormatOneError::Binding,
            TpmRc::CURVE => FormatOneError::Curve,
            TpmRc::ECC_POINT => FormatOneError::EccPoint,
            TpmRc::FW_LIMITED => FormatOneError::FwLimited,
            TpmRc::SVN_LIMITED => FormatOneError::SvnLimited,
            TpmRc::PARMS => FormatOneError::Parms,
            TpmRc::EXT_MU => FormatOneError::ExtMu,
            TpmRc::ONE_SHOT_SIGNATURE => FormatOneError::OneShotSignature,
            TpmRc::SIGN_CONTEXT_KEY => FormatOneError::SignContextKey,
            TpmRc::CHANNEL => FormatOneError::Channel,
            TpmRc::CHANNEL_KEY => FormatOneError::ChannelKey,
            _ => return None,
        };

        let raw = rc.raw();

        let idx = ((raw & TpmRc::N_MASK) >> 8) as u8;
        let target = if raw & TpmRc::P != 0 {
            (idx != 0).then_some(ErrorTarget::Parameter(idx))
        } else {
            match idx {
                0 => Some(ErrorTarget::Unspecified),
                1..=7 => Some(ErrorTarget::Handle(idx)),
                9..=15 => Some(ErrorTarget::Session(idx - 8)),
                _ => None, // 8
            }
        }?;

        Some(Self::FormatOne { rc, kind, target })
    }

    fn format_zero(rc: TpmRc) -> Option<Self> {
        let kind = match rc {
            TpmRc::INITIALIZE => FormatZeroError::Initialize,
            TpmRc::FAILURE => FormatZeroError::Failure,
            TpmRc::SEQUENCE => FormatZeroError::Sequence,
            TpmRc::PRIVATE => FormatZeroError::Private,
            TpmRc::HMAC => FormatZeroError::Hmac,
            TpmRc::DISABLED => FormatZeroError::Disabled,
            TpmRc::EXCLUSIVE => FormatZeroError::Exclusive,
            TpmRc::AUTH_TYPE => FormatZeroError::AuthType,
            TpmRc::AUTH_MISSING => FormatZeroError::AuthMissing,
            TpmRc::POLICY => FormatZeroError::Policy,
            TpmRc::PCR => FormatZeroError::Pcr,
            TpmRc::PCR_CHANGED => FormatZeroError::PcrChanged,
            TpmRc::UPGRADE => FormatZeroError::Upgrade,
            TpmRc::TOO_MANY_CONTEXTS => FormatZeroError::TooManyContexts,
            TpmRc::AUTH_UNAVAILABLE => FormatZeroError::AuthUnavailable,
            TpmRc::REBOOT => FormatZeroError::Reboot,
            TpmRc::UNBALANCED => FormatZeroError::Unbalanced,
            TpmRc::COMMAND_SIZE => FormatZeroError::CommandSize,
            TpmRc::COMMAND_CODE => FormatZeroError::CommandCode,
            TpmRc::AUTHSIZE => FormatZeroError::AuthSize,
            TpmRc::AUTH_CONTEXT => FormatZeroError::AuthContext,
            TpmRc::NV_RANGE => FormatZeroError::NvRange,
            TpmRc::NV_SIZE => FormatZeroError::NvSize,
            TpmRc::NV_LOCKED => FormatZeroError::NvLocked,
            TpmRc::NV_AUTHORIZATION => FormatZeroError::NvAuthorization,
            TpmRc::NV_UNINITIALIZED => FormatZeroError::NvUninitialized,
            TpmRc::NV_SPACE => FormatZeroError::NvSpace,
            TpmRc::NV_DEFINED => FormatZeroError::NvDefined,
            TpmRc::BAD_CONTEXT => FormatZeroError::BadContext,
            TpmRc::CPHASH => FormatZeroError::CpHash,
            TpmRc::PARENT => FormatZeroError::Parent,
            TpmRc::NEEDS_TEST => FormatZeroError::NeedsTest,
            TpmRc::NO_RESULT => FormatZeroError::NoResult,
            TpmRc::SENSITIVE => FormatZeroError::Sensitive,
            TpmRc::READ_ONLY => FormatZeroError::ReadOnly,
            _ => return None,
        };

        Some(Self::FormatZero { rc, kind })
    }

    fn warning(rc: TpmRc) -> Option<Self> {
        let kind = match rc {
            TpmRc::CONTEXT_GAP => TpmWarning::ContextGap,
            TpmRc::OBJECT_MEMORY => TpmWarning::ObjectMemory,
            TpmRc::SESSION_MEMORY => TpmWarning::SessionMemory,
            TpmRc::MEMORY => TpmWarning::Memory,
            TpmRc::SESSION_HANDLES => TpmWarning::SessionHandles,
            TpmRc::OBJECT_HANDLES => TpmWarning::ObjectHandles,
            TpmRc::LOCALITY => TpmWarning::Locality,
            TpmRc::YIELDED => TpmWarning::Yielded,
            TpmRc::CANCELED => TpmWarning::Canceled,
            TpmRc::TESTING => TpmWarning::Testing,
            TpmRc::REFERENCE_H0 => TpmWarning::ReferenceHandle(0),
            TpmRc::REFERENCE_H1 => TpmWarning::ReferenceHandle(1),
            TpmRc::REFERENCE_H2 => TpmWarning::ReferenceHandle(2),
            TpmRc::REFERENCE_H3 => TpmWarning::ReferenceHandle(3),
            TpmRc::REFERENCE_H4 => TpmWarning::ReferenceHandle(4),
            TpmRc::REFERENCE_H5 => TpmWarning::ReferenceHandle(5),
            TpmRc::REFERENCE_H6 => TpmWarning::ReferenceHandle(6),
            TpmRc::REFERENCE_S0 => TpmWarning::ReferenceSession(0),
            TpmRc::REFERENCE_S1 => TpmWarning::ReferenceSession(1),
            TpmRc::REFERENCE_S2 => TpmWarning::ReferenceSession(2),
            TpmRc::REFERENCE_S3 => TpmWarning::ReferenceSession(3),
            TpmRc::REFERENCE_S4 => TpmWarning::ReferenceSession(4),
            TpmRc::REFERENCE_S5 => TpmWarning::ReferenceSession(5),
            TpmRc::REFERENCE_S6 => TpmWarning::ReferenceSession(6),
            TpmRc::NV_RATE => TpmWarning::NvRate,
            TpmRc::LOCKOUT => TpmWarning::Lockout,
            TpmRc::RETRY => TpmWarning::Retry,
            TpmRc::NV_UNAVAILABLE => TpmWarning::NvUnavailable,
            _ => return None,
        };

        Some(Self::Warning { rc, kind })
    }

    pub(crate) fn rc(&self) -> TpmRc {
        match self {
            Self::FormatOne { rc, .. }
            | Self::FormatZero { rc, .. }
            | Self::Warning { rc, .. }
            | Self::Unknown(rc) => *rc,
        }
    }
}

impl Error {
    pub(crate) fn from_rc(rc: TpmRc) -> Self {
        let source = TpmError::from(rc);
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
