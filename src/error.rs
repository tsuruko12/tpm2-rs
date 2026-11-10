use std::any::type_name;

/// A result returned by this library, with [`Error`] as the error type.
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Errors returned by TPM operations, key management, and the local metadata store.
///
/// Match on the variants to handle specific failures, such as a missing key or an
/// unprovisioned store. Variants with a source retain the underlying backend or
/// storage error, accessible through [`std::error::Error::source`]. Their display
/// messages describe the failure at the library level.
///
/// This enum is non-exhaustive: downstream matches must include a wildcard arm
/// to accommodate additional error variants in future versions.
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// A TPM or backend operation failed without a more specific classification.
    #[error("TPM operation failed")]
    Failure(#[source] BoxError),
    /// A connection to the TPM could not be established.
    #[error("failed to connect to TPM")]
    Connect(#[source] BoxError),
    /// The TPM is temporarily unable to complete the operation.
    #[error("TPM is temporarily busy")]
    Busy(#[source] BoxError),
    /// The supplied authorization or policy did not satisfy the TPM's requirements.
    #[error("TPM authorization failed")]
    AuthorizationFailed(#[source] BoxError),
    /// A policy is invalid or lacks a required branch selection.
    ///
    /// Contains a description of the policy error.
    #[error("{0}")]
    InvalidPolicy(&'static str),
    /// An input exceeds its permitted length in bytes.
    #[error("{name} exceeds the maximum size of {max} bytes")]
    TooLong {
        /// The name of the input that is too long.
        name: &'static str,
        /// The maximum permitted length in bytes.
        max: usize,
    },
    /// A signature is malformed or incompatible with the selected key or algorithm.
    #[error("invalid signature")]
    InvalidSignature,
    /// A signature could not be verified.
    #[error("signature verification failed")]
    VerificationFailed(#[source] BoxError),
    /// The selected key is invalid or unsuitable for the requested operation.
    #[error("{context}")]
    InvalidKey {
        /// A description of why the key cannot be used.
        context: &'static str,
        /// The underlying error, when available.
        #[source]
        source: Option<BoxError>,
    },
    /// An argument is invalid for the requested operation.
    ///
    /// Contains a description of the invalid argument.
    #[error("{0}")]
    InvalidParameter(String),
    /// The requested persistent TPM handle is already occupied.
    ///
    /// Contains the conflicting handle value.
    #[error("selected persistent handle is already in use")]
    PersistentHandleInUse(u32),
    /// The TPM returned a malformed or unexpected response.
    #[error("invalid response returned by TPM")]
    InvalidResponse,
    /// Stored metadata is malformed or inconsistent.
    ///
    /// Contains the underlying error when available.
    #[error("key store data is corrupted")]
    CorruptedStore(#[source] Option<BoxError>),
    /// No stored key exists with the requested name.
    #[error("key not found")]
    KeyNotFound,
    /// A stored key already uses the requested name.
    ///
    /// Contains the duplicate key name.
    #[error("key already exists: {0}")]
    KeyAlreadyExists(String),
    /// A path for the local metadata store could not be determined.
    #[error("storage path is unavailable")]
    StorePathUnavailable,
    /// A resource required by the operation is exhausted.
    #[error("{context}")]
    ResourceExhausted {
        /// A description of the exhausted resource.
        context: &'static str,
        /// The underlying error, when available.
        #[source]
        source: Option<BoxError>,
    },
    /// A filesystem operation for the local metadata store failed.
    #[error("store I/O operation failed")]
    StoreIo(#[from] std::io::Error),
    /// A database operation for the local metadata store failed.
    #[error("store operation failed")]
    Store(#[from] rusqlite::Error),
    /// Provisioning was requested for a store that is already initialized.
    #[error("store is already provisioned")]
    AlreadyProvisioned,
    /// The operation requires internal keys from a provisioned store.
    #[error("store is not provisioned")]
    NotProvisioned,
    /// The requested operation or configuration is unsupported.
    #[error("{context}")]
    Unsupported {
        /// A description of the unsupported operation or configuration.
        context: String,
        /// The underlying error, when available.
        #[source]
        source: Option<BoxError>,
    },
    /// An internal operation failed or an unexpected state was encountered.
    ///
    /// Additional details are emitted through `tracing` at the debug level.
    #[error("internal error")]
    Internal,
}

#[expect(dead_code)]
impl Error {
    pub(crate) fn connect(source: impl Into<BoxError>) -> Self {
        Self::Connect(source.into())
    }

    pub(crate) fn failure(source: impl Into<BoxError>) -> Self {
        Self::Failure(source.into())
    }

    pub(crate) fn authorization_failed(source: impl Into<BoxError>) -> Self {
        Self::AuthorizationFailed(source.into())
    }

    pub(crate) fn invalid_key_with_source(
        context: &'static str,
        source: impl Into<BoxError>,
    ) -> Self {
        Self::InvalidKey {
            context,
            source: Some(source.into()),
        }
    }

    pub(crate) fn invalid_key(context: &'static str) -> Self {
        Self::InvalidKey {
            context,
            source: None,
        }
    }

    pub(crate) fn invalid_param(context: impl Into<String>) -> Self {
        Self::InvalidParameter(context.into())
    }

    pub(crate) fn invalid_response(source: impl Into<BoxError>) -> Self {
        tracing::debug!(source = ?source.into());
        Self::InvalidResponse
    }

    pub(crate) fn corrupted_store() -> Self {
        Self::CorruptedStore(None)
    }

    pub(crate) fn corrupted_store_with_source(source: impl Into<BoxError>) -> Self {
        Self::CorruptedStore(Some(source.into()))
    }

    pub(crate) fn unsupported(context: impl Into<String>) -> Self {
        Self::Unsupported {
            context: context.into(),
            source: None,
        }
    }

    pub(crate) fn unsupported_with_source(
        context: impl Into<String>,
        source: impl Into<BoxError>,
    ) -> Self {
        Self::Unsupported {
            context: context.into(),
            source: Some(source.into()),
        }
    }

    pub(crate) fn resource_exhausted(context: &'static str) -> Self {
        Self::ResourceExhausted {
            context,
            source: None,
        }
    }

    pub(crate) fn resource_exhausted_with_source(
        context: &'static str,
        source: impl Into<BoxError>,
    ) -> Self {
        Self::ResourceExhausted {
            context,
            source: Some(source.into()),
        }
    }

    pub(crate) fn busy(source: impl Into<BoxError>) -> Self {
        Self::Busy(source.into())
    }

    pub(crate) fn internal(source: InternalError) -> Self {
        tracing::debug!("{source}");
        Self::Internal
    }

    pub(crate) fn conversion<From: ?Sized, To: ?Sized>(
        value: Option<&dyn std::fmt::Debug>,
    ) -> Self {
        let from = match value {
            Some(v) => {
                let ty = type_name::<From>().rsplit("::").next().unwrap();
                format!("{ty} ({v:?})")
            }
            None => type_name::<From>().rsplit("::").next().unwrap().into(),
        };

        Self::internal(InternalError::Conversion {
            from,
            to: type_name::<To>().rsplit("::").next().unwrap(),
        })
    }

    pub(crate) fn random_generation(source: rand::Error) -> Self {
        Self::internal(InternalError::RandomGeneration(source))
    }

    pub(crate) fn invalid_state(context: impl Into<String>) -> Self {
        Self::internal(InternalError::InvalidState(context.into()))
    }

    pub(crate) fn invalid_value(context: impl Into<String>) -> Self {
        Self::internal(InternalError::InvalidValue(context.into()))
    }

    pub(crate) fn encryption(source: impl Into<BoxError>) -> Self {
        Self::internal(InternalError::Encryption(source.into()))
    }

    pub(crate) fn invalid_tpm_command(rc: u32) -> Self {
        Self::internal(InternalError::InvalidTpmCommand(rc))
    }

    pub(crate) fn esapi(source: impl Into<BoxError>) -> Self {
        Self::internal(InternalError::Esapi(source.into()))
    }

    pub(crate) fn from_store_err(source: rusqlite::Error) -> Self {
        if matches!(
            source,
            rusqlite::Error::FromSqlConversionFailure(_, _, _)
                | rusqlite::Error::IntegralValueOutOfRange(_, _)
                | rusqlite::Error::Utf8Error(_, _)
                | rusqlite::Error::InvalidColumnType(_, _, _)
        ) {
            Self::corrupted_store_with_source(source)
        } else {
            Self::Store(source)
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum InternalError {
    #[error("failed to convert {from} to {to}")]
    Conversion { from: String, to: &'static str },
    #[error("{0:?}")]
    RandomGeneration(#[from] rand::Error),
    #[error("{0}")]
    InvalidState(String),
    #[error("{0}")]
    InvalidValue(String),
    #[error("TPM responce code: {0:#010x}")]
    InvalidTpmCommand(u32),
    #[cfg(windows)]
    #[error("TBS response code: {0:#010x}")]
    Tbs(u32),
    #[error("ESAPI operation failed: {0:#}")]
    Esapi(#[source] BoxError),
    #[error("{0:?}")]
    Encryption(#[source] BoxError),
}
