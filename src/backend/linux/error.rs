use tss_esapi::{WrapperErrorKind, constants::Tss2ResponseCodeKind};

use crate::error::{BoxError, Error};

impl Error {
    pub(crate) fn from_tss_err(err: tss_esapi::Error) -> Self {
        match err {
            tss_esapi::Error::Tss2Error(code) => match code.kind() {
                Some(kind) if is_internal_err(kind) => Error::Internal(internal_err_context(kind)),
                Some(kind) if is_authorization_err(kind) => Error::AuthorizationFailed {
                    context: authorization_err_context(kind),
                    source: err.into(),
                },
                Some(kind) if is_resource_exhausted(kind) => Error::ResourceExhausted {
                    context: resource_exhausted_context(kind),
                    source: Some(err.into()),
                },
                Some(Tss2ResponseCodeKind::Unbalanced) => Error::invalid_param(
                    "TPM protection algorithms are not balanced for this key template",
                ),
                Some(Tss2ResponseCodeKind::Signature) => Error::InvalidSignature(err.into()),
                Some(Tss2ResponseCodeKind::Key) => {
                    Error::InvalidKey("the selected key cannot be used for this operation")
                }
                Some(kind) if is_key_data_integrity_error(kind) => {
                    Error::Internal(key_data_integrity_error_context(kind))
                }
                Some(kind) if is_unsupported_err(kind) => Error::Unsupported {
                    context: unsupported_err_context(kind).into(),
                    source: Some(err.into()),
                },
                Some(kind) if is_tpm_busy_err(kind) => Error::Busy(err.into()),
                _ => Error::Failure(err.into()),
            },
            tss_esapi::Error::WrapperError(kind) => Error::Internal(wrapper_err_context(kind)),
        }
    }

    pub fn detail_message(&self) -> Option<&str> {
        match self {
            Error::AuthorizationFailed { context, .. }
            | Error::ResourceExhausted { context, .. } => Some(context),
            Error::Unsupported { context, .. } => Some(context.as_str()),
            Error::Internal(context) => Some(context),
            Error::Failure(source)
            | Error::Connect(source)
            | Error::Busy(source)
            | Error::InvalidSignature(source) => tss_err_detail_from_source(source),
            Error::CorruptedStore(source) => tss_err_detail_from_box(source),
            _ => None,
        }
    }
}

fn tss_err_detail_from_source(source: &BoxError) -> Option<&'static str> {
    source
        .as_ref()
        .downcast_ref::<tss_esapi::Error>()
        .and_then(tss_err_detail)
}

fn tss_err_detail_from_box(source: &Option<BoxError>) -> Option<&'static str> {
    source.as_ref().and_then(tss_err_detail_from_source)
}

fn is_internal_err(kind: Tss2ResponseCodeKind) -> bool {
    matches!(
        kind,
        Tss2ResponseCodeKind::Sequence
            | Tss2ResponseCodeKind::AuthType
            | Tss2ResponseCodeKind::AuthMissing
            | Tss2ResponseCodeKind::AuthContext
            | Tss2ResponseCodeKind::Parent
            | Tss2ResponseCodeKind::ReferenceH0
            | Tss2ResponseCodeKind::ReferenceH1
            | Tss2ResponseCodeKind::ReferenceH2
            | Tss2ResponseCodeKind::ReferenceH3
            | Tss2ResponseCodeKind::ReferenceH4
            | Tss2ResponseCodeKind::ReferenceH5
            | Tss2ResponseCodeKind::ReferenceH6
            | Tss2ResponseCodeKind::ReferenceS0
            | Tss2ResponseCodeKind::ReferenceS1
            | Tss2ResponseCodeKind::ReferenceS2
            | Tss2ResponseCodeKind::ReferenceS3
            | Tss2ResponseCodeKind::ReferenceS4
            | Tss2ResponseCodeKind::ReferenceS5
            | Tss2ResponseCodeKind::ReferenceS6
            | Tss2ResponseCodeKind::Attributes
            | Tss2ResponseCodeKind::Type
            | Tss2ResponseCodeKind::Handle
            | Tss2ResponseCodeKind::Range
            | Tss2ResponseCodeKind::Nonce
            | Tss2ResponseCodeKind::Size
            | Tss2ResponseCodeKind::Tag
            | Tss2ResponseCodeKind::Selector
            | Tss2ResponseCodeKind::Insufficient
            | Tss2ResponseCodeKind::ReservedBits
    )
}

fn internal_err_context(kind: Tss2ResponseCodeKind) -> &'static str {
    match kind {
        Tss2ResponseCodeKind::Sequence => "TPM sequence handle was used incorrectly",
        Tss2ResponseCodeKind::AuthType => {
            "authorization handle type is not valid for this TPM command"
        }
        Tss2ResponseCodeKind::AuthMissing => {
            "TPM command required an authorization session, but none was provided"
        }
        Tss2ResponseCodeKind::AuthContext => {
            "authorization session cannot be used with this TPM command context"
        }
        Tss2ResponseCodeKind::Parent => "parent handle is not valid for this TPM operation",
        Tss2ResponseCodeKind::ReferenceH0
        | Tss2ResponseCodeKind::ReferenceH1
        | Tss2ResponseCodeKind::ReferenceH2
        | Tss2ResponseCodeKind::ReferenceH3
        | Tss2ResponseCodeKind::ReferenceH4
        | Tss2ResponseCodeKind::ReferenceH5
        | Tss2ResponseCodeKind::ReferenceH6 => {
            "TPM command referenced a transient object handle that is not loaded"
        }
        Tss2ResponseCodeKind::ReferenceS0
        | Tss2ResponseCodeKind::ReferenceS1
        | Tss2ResponseCodeKind::ReferenceS2
        | Tss2ResponseCodeKind::ReferenceS3
        | Tss2ResponseCodeKind::ReferenceS4
        | Tss2ResponseCodeKind::ReferenceS5
        | Tss2ResponseCodeKind::ReferenceS6 => {
            "TPM command referenced an authorization session that is not loaded"
        }
        Tss2ResponseCodeKind::Attributes => {
            "TPM object attributes are inconsistent with the requested operation"
        }
        Tss2ResponseCodeKind::Type => "TPM parameter type is not valid for this operation",
        Tss2ResponseCodeKind::Handle => "TPM handle is not valid for this operation",
        Tss2ResponseCodeKind::Range => "TPM parameter value is outside the valid range",
        Tss2ResponseCodeKind::Nonce => "TPM authorization nonce is invalid",
        Tss2ResponseCodeKind::Size => "TPM parameter size is invalid",
        Tss2ResponseCodeKind::Tag => "TPM structure tag is invalid",
        Tss2ResponseCodeKind::Selector => "TPM selector value is invalid",
        Tss2ResponseCodeKind::Insufficient => "TPM parameter value is insufficient",
        Tss2ResponseCodeKind::ReservedBits => "TPM request contains reserved bits",
        _ => "the TPM command could not be prepared correctly",
    }
}

fn is_authorization_err(kind: Tss2ResponseCodeKind) -> bool {
    matches!(
        kind,
        Tss2ResponseCodeKind::Policy
            | Tss2ResponseCodeKind::Pcr
            | Tss2ResponseCodeKind::PcrChanged
            | Tss2ResponseCodeKind::AuthUnavailable
            | Tss2ResponseCodeKind::NvAuthorization
            | Tss2ResponseCodeKind::Lockout
            | Tss2ResponseCodeKind::AuthFail
            | Tss2ResponseCodeKind::PolicyFail
            | Tss2ResponseCodeKind::Ticket
            | Tss2ResponseCodeKind::BadAuth
            | Tss2ResponseCodeKind::Expired
            | Tss2ResponseCodeKind::PolicyCc
    )
}

fn authorization_err_context(kind: Tss2ResponseCodeKind) -> &'static str {
    match kind {
        Tss2ResponseCodeKind::Policy => {
            "TPM policy authorization failed or the key policy digest is invalid"
        }
        Tss2ResponseCodeKind::Pcr => "PCR policy check failed for the current device state",
        Tss2ResponseCodeKind::PcrChanged => {
            "PCR values changed after the policy session was checked"
        }
        Tss2ResponseCodeKind::AuthUnavailable => {
            "authorization value or policy is unavailable for this TPM object or hierarchy"
        }
        Tss2ResponseCodeKind::NvAuthorization => "NV index authorization failed",
        Tss2ResponseCodeKind::Lockout => {
            "TPM is in dictionary-attack lockout mode and authorization is blocked"
        }
        Tss2ResponseCodeKind::AuthFail | Tss2ResponseCodeKind::BadAuth => {
            "the provided authorization value is incorrect"
        }
        Tss2ResponseCodeKind::PolicyFail => "TPM policy requirements were not satisfied",
        Tss2ResponseCodeKind::Ticket => "TPM authorization ticket is invalid",
        Tss2ResponseCodeKind::Expired => "TPM policy session has expired",
        Tss2ResponseCodeKind::PolicyCc => "TPM policy does not allow this command code",
        _ => "authorization failed",
    }
}

fn is_resource_exhausted(kind: Tss2ResponseCodeKind) -> bool {
    matches!(
        kind,
        Tss2ResponseCodeKind::TooManyContexts
            | Tss2ResponseCodeKind::NvSpace
            | Tss2ResponseCodeKind::NvDefined
            | Tss2ResponseCodeKind::ObjectMemory
            | Tss2ResponseCodeKind::SessionMemory
            | Tss2ResponseCodeKind::Memory
            | Tss2ResponseCodeKind::SessionHandles
            | Tss2ResponseCodeKind::ObjectHandles
    )
}

fn resource_exhausted_context(kind: Tss2ResponseCodeKind) -> &'static str {
    match kind {
        Tss2ResponseCodeKind::TooManyContexts => "TPM context counter is exhausted",
        Tss2ResponseCodeKind::NvSpace => "TPM NV storage does not have enough free space",
        Tss2ResponseCodeKind::NvDefined => "TPM NV index or persistent object already exists",
        Tss2ResponseCodeKind::ObjectMemory => "TPM does not have enough memory for another object",
        Tss2ResponseCodeKind::SessionMemory => {
            "TPM does not have enough memory for another session"
        }
        Tss2ResponseCodeKind::Memory => "TPM shared object/session memory is exhausted",
        Tss2ResponseCodeKind::SessionHandles => {
            "TPM has no free session handles; flush a session and try again"
        }
        Tss2ResponseCodeKind::ObjectHandles => {
            "TPM has no free object handles; flush an object and try again"
        }
        _ => "TPM resource exhausted",
    }
}

fn is_key_data_integrity_error(kind: Tss2ResponseCodeKind) -> bool {
    matches!(
        kind,
        Tss2ResponseCodeKind::Binding
            | Tss2ResponseCodeKind::Integrity
            | Tss2ResponseCodeKind::EccPoint
    )
}

fn key_data_integrity_error_context(kind: Tss2ResponseCodeKind) -> &'static str {
    match kind {
        Tss2ResponseCodeKind::Binding => {
            "TPM key data is not bound to the expected parent or context"
        }
        Tss2ResponseCodeKind::Integrity => "TPM key data failed integrity validation",
        Tss2ResponseCodeKind::EccPoint => "ECC public key point is invalid for the selected curve",
        _ => "TPM key data failed integrity checks",
    }
}

fn is_unsupported_err(kind: Tss2ResponseCodeKind) -> bool {
    matches!(
        kind,
        Tss2ResponseCodeKind::CommandCode
            | Tss2ResponseCodeKind::Hash
            | Tss2ResponseCodeKind::KeySize
            | Tss2ResponseCodeKind::Mgf
            | Tss2ResponseCodeKind::Mode
            | Tss2ResponseCodeKind::Kdf
            | Tss2ResponseCodeKind::Scheme
            | Tss2ResponseCodeKind::Asymmetric
            | Tss2ResponseCodeKind::Symmetric
            | Tss2ResponseCodeKind::Curve
    )
}

fn unsupported_err_context(kind: Tss2ResponseCodeKind) -> &'static str {
    match kind {
        Tss2ResponseCodeKind::CommandCode => "TPM does not support this command",
        Tss2ResponseCodeKind::Hash => {
            "TPM does not support the selected hash algorithm for this operation"
        }
        Tss2ResponseCodeKind::KeySize => "TPM does not support the selected key size",
        Tss2ResponseCodeKind::Mgf => "TPM does not support the selected mask generation function",
        Tss2ResponseCodeKind::Mode => "TPM does not support the selected symmetric mode",
        Tss2ResponseCodeKind::Kdf => "TPM does not support the selected key derivation function",
        Tss2ResponseCodeKind::Scheme => {
            "TPM does not support the selected cryptographic scheme for this key"
        }
        Tss2ResponseCodeKind::Asymmetric => {
            "TPM does not support the selected asymmetric algorithm"
        }
        Tss2ResponseCodeKind::Symmetric => "TPM does not support the selected symmetric algorithm",
        Tss2ResponseCodeKind::Curve => "TPM does not support the selected ECC curve",
        _ => "unsupported TPM command or algorithm",
    }
}

fn is_tpm_busy_err(kind: Tss2ResponseCodeKind) -> bool {
    matches!(
        kind,
        Tss2ResponseCodeKind::Yielded
            | Tss2ResponseCodeKind::Testing
            | Tss2ResponseCodeKind::NvRate
            | Tss2ResponseCodeKind::Retry
    )
}

fn wrapper_err_context(kind: WrapperErrorKind) -> &'static str {
    match kind {
        WrapperErrorKind::WrongParamSize => "TPM wrapper rejected a parameter with the wrong size",
        WrapperErrorKind::ParamsMissing => "TPM wrapper is missing required command parameters",
        WrapperErrorKind::InconsistentParams => "TPM wrapper found inconsistent command parameters",
        WrapperErrorKind::UnsupportedParam => {
            "TPM wrapper does not support one of the selected parameters"
        }
        WrapperErrorKind::InvalidParam => "TPM wrapper rejected an invalid parameter",
        WrapperErrorKind::WrongValueFromTpm => {
            "TPM returned a value that the wrapper could not validate"
        }
        WrapperErrorKind::MissingAuthSession => {
            "TPM wrapper required an authorization session before executing the command"
        }
        WrapperErrorKind::InvalidHandleState => {
            "TPM wrapper found a handle in the wrong state for this operation"
        }
        WrapperErrorKind::InternalError => "TPM wrapper reported an internal error",
    }
}

fn tss_err_detail(err: &tss_esapi::Error) -> Option<&'static str> {
    match err {
        tss_esapi::Error::Tss2Error(code) => match code.kind() {
            Some(Tss2ResponseCodeKind::Success) => None,
            Some(kind) if is_internal_err(kind) => Some(internal_err_context(kind)),
            Some(kind) if is_authorization_err(kind) => Some(authorization_err_context(kind)),
            Some(kind) if is_resource_exhausted(kind) => Some(resource_exhausted_context(kind)),
            Some(Tss2ResponseCodeKind::Unbalanced) => {
                Some("TPM protection algorithms are not balanced for this key template")
            }
            Some(Tss2ResponseCodeKind::Signature) => {
                Some("signature is invalid for the digest, key, or signing scheme")
            }
            Some(Tss2ResponseCodeKind::Key) => Some("TPM key is not valid for this operation"),
            Some(kind) if is_key_data_integrity_error(kind) => {
                Some(key_data_integrity_error_context(kind))
            }
            Some(kind) if is_unsupported_err(kind) => Some(unsupported_err_context(kind)),
            Some(kind) if is_tpm_busy_err(kind) => Some("TPM is temporarily busy"),
            _ => Some("the TPM could not complete the operation"),
        },
        tss_esapi::Error::WrapperError(_) => {
            Some("the TPM command could not be prepared correctly")
        }
    }
}

// Internal => Sequence, AuthType, AuthMissing, AuthContext, Parent, ReferenceH0〜ReferenceH6, ReferenceS0〜ReferenceS6, Attributes, Type, Handle, Range, Nonce, Size, Tag, Selector, Insufficient, ReservedBits, all-WrapperErrorKind
// AuthorizationFailed => Policy, PCR, PcrChanged, AuthUnavailable, NvAuthorization, Lockout, AuthFail, PolicyFail, Ticket, BadAuth, Expired, PolicyCc
// ResourceExhausted => TooManyContext, NvSpace, NvDefined, ObjectMemory, SessionMemory, Memory, SessionHandles, ObjectHandles
// InvalidParameter => Unbalanced
// InvalidSignature => Signature
// InvalidKey => Key
// CorruptedStorage > Binding, Integrity, EccPoint
// Unsupported => CommandCode, Hash, KeySize, Mgf, Mode, Kdf, Scheme, Asymmetric, Symmetric, Curve
// TpmBusy => Yielded, Testing, NvRate, Retry
// TpmFailure => others

// アルゴリズムなど対応してない場合、互換性あるものでフォールバック
// Binding, Integrity, EccPointはimport時はInvalidparameterにする
