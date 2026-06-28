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
    #[error("missing auth value")]
    MissingAuthValue,
    #[error("{context}")]
    AuthorizationFailed {
        context: &'static str,
        #[source]
        source: BoxError,
    },
    #[error("{0}")]
    InvalidPolicy(&'static str),
    #[error("{name} exceeds the maximum size of {max} bytes")]
    TooLong { name: &'static str, max: usize },
    #[error("signature verification failed")]
    InvalidSignature(#[source] BoxError),
    #[error("{0}")]
    InvalidKey(&'static str),
    #[error("{0}")]
    InvalidParameter(String),
    #[error("key store data is corrupted")]
    CorruptedStore(#[source] Option<BoxError>),
    #[error("key not found")]
    KeyNotFound,
    #[error("key already exists")]
    KeyAlreadyExists(String),
    #[error("storage path is unavailable")]
    StorePathUnavailable,
    #[error("{context}")]
    ResourceExhausted {
        context: &'static str,
        #[source]
        source: Option<BoxError>,
    },
    #[error("store operation failed")]
    Store(#[from] rusqlite::Error),
    #[error("{context}")]
    Unsupported {
        context: String,
        #[source]
        source: Option<BoxError>,
    },
    #[error("{0}")]
    Internal(&'static str),
}

impl Error {
    pub(crate) fn connect(err: impl Into<BoxError>) -> Self {
        Self::Connect(err.into())
    }

    pub(crate) fn failure(err: impl Into<BoxError>) -> Self {
        Self::Failure(err.into())
    }

    pub(crate) fn invalid_param(context: impl Into<String>) -> Self {
        Self::InvalidParameter(context.into())
    }

    pub(crate) fn corrupted_store() -> Self {
        Self::CorruptedStore(None)
    }

    pub(crate) fn unsupported(context: impl Into<String>) -> Self {
        Self::Unsupported {
            context: context.into(),
            source: None,
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
}
