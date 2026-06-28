use directories::ProjectDirs;
use std::{
    io::{self, ErrorKind},
    path::{Path, PathBuf},
};

use crate::{
    error::{BoxError, Error, Result},
    generate_random_bytes,
};

mod db;

pub(super) use db::{
    ChildKeyMeta, InternalKeyMeta, PersistentHandle, PrimaryKeyMeta, SymmetricKeyMeta,
};

const DATABASE_FILE: &str = "store.db";
const STORE_PATH_ENV: &str = "TPM_STORE_PATH";
const PROJECT_APPLICATION: &str = "tpm-tool";
pub(super) const FILE_VERSION: u8 = 1;

pub(super) struct MetadataStore {
    pub(super) database_path: PathBuf,
}

impl MetadataStore {
    pub(super) fn new() -> Result<Self> {
        let dir_path = store_path_from_env().map_or_else(default_dir_path, Ok)?;
        Ok(Self {
            database_path: dir_path.join(DATABASE_FILE),
        })
    }

    pub(super) fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub(super) fn store_dir_path(&self) -> Result<&Path> {
        self.database_path
            .parent()
            .ok_or(Error::StorePathUnavailable)
    }
}

pub(super) fn generate_id() -> Result<String> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let bytes = generate_random_bytes(16)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn store_path_from_env() -> Option<PathBuf> {
    std::env::var_os(STORE_PATH_ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn default_dir_path() -> Result<PathBuf> {
    ProjectDirs::from("", "", PROJECT_APPLICATION)
        .map(|dirs| dirs.data_local_dir().to_path_buf())
        .ok_or(Error::StorePathUnavailable)
}

pub(super) fn corrupted_store(source: impl Into<BoxError>) -> Error {
    Error::CorruptedStore(Some(source.into()))
}

pub(super) fn init_io_err(err: io::Error) -> Error {
    match err.kind() {
        ErrorKind::AlreadyExists => Error::Io(io::Error::new(
            ErrorKind::AlreadyExists,
            "key store is already initialized",
        )),
        _ => Error::Io(err),
    }
}
