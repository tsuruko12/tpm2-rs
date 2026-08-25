use std::any::type_name;

pub type Result<T> = std::result::Result<T, Error>;
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("TPM operation failed")]
    Failure(#[source] BoxError),
    #[error("failed to connect to TPM")]
    Connect(#[source] BoxError),
    #[error("TPM is temporarily busy")]
    Busy(#[source] BoxError),
    #[error("TPM authorization failed")]
    AuthorizationFailed(#[source] BoxError),
    #[error("{0}")]
    InvalidPolicy(&'static str),
    #[error("{name} exceeds the maximum size of {max} bytes")]
    TooLong { name: &'static str, max: usize },
    #[error("signature verification failed")]
    InvalidSignature(#[source] BoxError),
    #[error("{context}")]
    InvalidKey {
        context: &'static str,
        #[source]
        source: Option<BoxError>,
    },
    #[error("{0}")]
    InvalidParameter(String),
    #[error("selected persistent handle is already in use")]
    PersistentHandleInUse(u32),
    #[error("invalid data returned by TPM")]
    InvalidData,
    #[error("key store data is corrupted")]
    CorruptedStore(#[source] Option<BoxError>),
    #[error("key not found")]
    KeyNotFound,
    #[error("key already exists: {0}")]
    KeyAlreadyExists(String),
    #[error("storage path is unavailable")]
    StorePathUnavailable,
    #[error("{context}")]
    ResourceExhausted {
        context: &'static str,
        #[source]
        source: Option<BoxError>,
    },
    #[error("store I/O operation failed")]
    StoreIo(#[from] std::io::Error),
    #[error("store operation failed")]
    Store(#[from] rusqlite::Error),
    #[error("store already exists")]
    StoreAlreadyExists,
    #[error("provisioning is required")]
    NotProvisioned,
    #[error("{context}")]
    Unsupported {
        context: String,
        #[source]
        source: Option<BoxError>,
    },
    #[error("internal error")]
    Internal,
}

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

    pub(crate) fn invalid_signature(source: impl Into<BoxError>) -> Self {
        Self::InvalidSignature(source.into())
    }

    pub(crate) fn invalid_param(context: impl Into<String>) -> Self {
        Self::InvalidParameter(context.into())
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
            },
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

    pub(crate) fn encryption(source: impl Into<BoxError>) -> Self {
        Self::internal(InternalError::Encryption(source.into()))
    }

    pub(crate) fn invalid_tpm_command(rc: u32) -> Self {
        Self::internal(InternalError::InvalidTpmCommand(rc))
    }

    pub(crate) fn esapi(source: impl Into<BoxError>) -> Self {
        Self::internal(InternalError::Esapi(source.into()))
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
    #[error("TPM responce code: {0:#010x}")]
    InvalidTpmCommand(u32),
    #[error("TBS response code: {0:#010x}")]
    Tbs(u32),
    #[error("ESAPI operation failed: {0:#}")]
    Esapi(#[source] BoxError),
    #[error("{0:?}")]
    Encryption(#[source] BoxError),
}
