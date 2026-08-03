use tracing::debug;
use tss_esapi::{Error as EsapiError, WrapperErrorKind, constants::Tss2ResponseCodeKind};

use crate::error::Error;

impl Error {
    pub(crate) fn internal_from_tss2_rc(err: Tss2ResponseCodeKind) -> Self {
        debug!("{err:?}");
        Self::Internal
    }

    pub(crate) fn internal_from_wrapper_err(err: WrapperErrorKind) -> Self {
        debug!("{err}");
        Self::Internal
    }

    pub(crate) fn from_tss_err(err: tss_esapi::Error) -> Self {
        match err {
            EsapiError::Tss2Error(code) => {
                if let Some(kind) = code.kind() {
                    match kind {
                        Tss2ResponseCodeKind::Initialize => Self::connect(err),
                        Tss2ResponseCodeKind::Failure
                        | Tss2ResponseCodeKind::Disabled
                        | Tss2ResponseCodeKind::PcrChanged
                        | Tss2ResponseCodeKind::Pcr
                        | Tss2ResponseCodeKind::Upgrade
                        | Tss2ResponseCodeKind::Reboot
                        | Tss2ResponseCodeKind::CommandCode
                        | Tss2ResponseCodeKind::Yielded
                        | Tss2ResponseCodeKind::Canceled
                        | Tss2ResponseCodeKind::Retry
                        | Tss2ResponseCodeKind::Testing
                        | Tss2ResponseCodeKind::NvRate
                        | Tss2ResponseCodeKind::Lockout => Self::failure(err),
                        Tss2ResponseCodeKind::Policy
                        | Tss2ResponseCodeKind::PolicyFail
                        | Tss2ResponseCodeKind::PolicyCc
                        | Tss2ResponseCodeKind::Expired
                        | Tss2ResponseCodeKind::AuthUnavailable
                        | Tss2ResponseCodeKind::BadAuth => Self::authorization_failed(err),
                        Tss2ResponseCodeKind::Parent | Tss2ResponseCodeKind::Key => {
                            Self::invalid_key("invalid key for this operation")
                        }
                        Tss2ResponseCodeKind::KeySize | Tss2ResponseCodeKind::Curve => {
                            Self::unsupported_with_source("unsupported key size or curve", err)
                        }
                        _ => Self::internal_from_tss2_rc(kind),
                    }
                } else {
                    Self::Internal
                }
            }
            EsapiError::WrapperError(kind) => Error::internal_from_wrapper_err(kind),
        }
    }
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
