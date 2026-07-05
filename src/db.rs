use std::path::{Path, PathBuf};

use directories::ProjectDirs;

use crate::{Error, Result, error::BoxError, generate_random_bytes};

const DATABASE_FILE: &str = "store.db";
const STORE_PATH_ENV: &str = "TPM_STORE_PATH";
const PROJECT_APPLICATION: &str = "tpm-tool";
const FILE_VERSION: u8 = 1;

const HANDLE_SRK: &str = "srk";
const HANDLE_SESSION_SALT_KEY: &str = "session_salt_key";
const HANDLE_SHARED_WRAPPING_KEY: &str = "shared_wrapping_key";

const CREATE_SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE store_state (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    initialized INTEGER NOT NULL CHECK (initialized IN (0, 1))
);

CREATE TABLE keys (
    id       TEXT PRIMARY KEY,
    key_name TEXT NOT NULL UNIQUE,
    kind     TEXT NOT NULL CHECK (kind IN ('primary', 'child', 'symmetric')),
    UNIQUE (id, kind)
);

CREATE TABLE policies (
    id                 TEXT PRIMARY KEY,
    kind               TEXT NOT NULL CHECK (
        kind IN ('auth_value', 'pcr', 'command', 'sequence', 'or')
    ),
    pcr_hash_alg TEXT CHECK (
        pcr_hash_alg IN (
            'sha1',
            'sha256',
            'sha384',
            'sha512',
            'sm3_256',
            'sha3_256',
            'sha3_384',
            'sha3_512'
        )
    ),
    pcr_slots_mask          INTEGER CHECK (
        pcr_slots_mask IS NULL OR
        pcr_slots_mask > 0 AND pcr_slots_mask <= 16777215
    ),
    command            TEXT CHECK (
        command IN (
            'create_primary',
            'create',
            'load',
            'import',
            'duplicate',
            'sign',
            'decrypt',
            'unseal'
        )
    ),

    UNIQUE (id, kind),

    CHECK (
        (
            kind = 'auth_value' AND
            pcr_hash_alg IS NULL AND
            pcr_slots_mask IS NULL AND
            command IS NULL
        ) OR (
            kind = 'pcr' AND
            pcr_hash_alg IS NOT NULL AND
            pcr_slots_mask IS NOT NULL AND
            command IS NULL
        ) OR (
            kind = 'command' AND
            pcr_hash_alg IS NULL AND
            pcr_slots_mask IS NULL AND
            command IS NOT NULL
        ) OR (
            kind IN ('sequence', 'or') AND
            pcr_hash_alg IS NULL AND
            pcr_slots_mask IS NULL AND
            command IS NULL
        )
    )
);

CREATE TABLE policy_branches (
    parent_id   TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    child_index INTEGER NOT NULL CHECK (child_index >= 0),
    child_id    TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,

    PRIMARY KEY (parent_id, child_index),
    UNIQUE (child_id),
    CHECK (parent_id <> child_id)
);

CREATE TABLE tpm_keys (
    id                TEXT PRIMARY KEY,
    kind              TEXT NOT NULL CHECK (kind IN ('primary', 'child')),
    hierarchy         TEXT CHECK (
        hierarchy IN ('owner', 'endorsement', 'platform')
    ),
    public            BLOB NOT NULL,
    tpm_name          BLOB NOT NULL,
    private           BLOB,
    parent_id         TEXT REFERENCES tpm_keys(id) ON DELETE RESTRICT,
    load_source       TEXT NOT NULL CHECK (
        load_source IN ('recreate', 'stored_blob', 'persistent')
    ),
    persistent_handle INTEGER UNIQUE,
    policy_id         TEXT REFERENCES policies(id) ON DELETE RESTRICT,

    FOREIGN KEY (id, kind) REFERENCES keys(id, kind) ON DELETE CASCADE,

    CHECK (
        (load_source IN ('recreate', 'stored_blob') AND persistent_handle IS NULL) OR
        (load_source = 'persistent' AND persistent_handle IS NOT NULL)
    ),

    CHECK (
        (
            kind = 'primary' AND
            hierarchy IS NOT NULL AND
            private IS NULL AND
            parent_id IS NULL AND
            load_source IN ('recreate', 'persistent')
        ) OR (
            kind = 'child' AND
            hierarchy IS NULL AND
            private IS NOT NULL AND
            parent_id IS NOT NULL AND
            load_source IN ('stored_blob', 'persistent')
        )
    )
);

CREATE TABLE wrapping_keys (
    id        TEXT PRIMARY KEY,
    public    BLOB NOT NULL,
    private   BLOB NOT NULL,
);

CREATE TABLE symmetric_keys (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL DEFAULT 'symmetric' CHECK (kind = 'symmetric'),
    block_cipher    TEXT NOT NULL,
    key_bits        INTEGER NOT NULL,
    mode            TEXT NOT NULL,
    wrapped_key     BLOB NOT NULL,
    wrapping_key_id TEXT NOT NULL REFERENCES wrapping_keys(id),

    FOREIGN KEY (id, kind) REFERENCES keys(id, kind) ON DELETE CASCADE
);

CREATE TABLE hierarchy_policies (
    hierarchy TEXT PRIMARY KEY CHECK (
        hierarchy IN ('owner', 'endorsement', 'platform')
    ),
    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE RESTRICT
);

CREATE TABLE internal_persistent_objects (
    kind     TEXT PRIMARY KEY CHECK (
        kind IN ('srk', 'session_salt_key', 'shared_wrapping_key')
    ),
    handle   INTEGER NOT NULL UNIQUE CHECK (
        handle BETWEEN 2164391936 AND 2164457471
    ),
    tpm_name BLOB NOT NULL
);

INSERT INTO store_state (id, initialized) VALUES (1, 0);
PRAGMA user_version = 1;
"#;

pub(super) struct MetadataStore {
    pub(super) db_path: PathBuf,
}

impl MetadataStore {
    pub(super) fn new() -> Result<Self> {
        let dir_path = store_path_from_env().map_or_else(default_dir_path, Ok)?;
        Ok(Self {
            db_path: dir_path.join(DATABASE_FILE),
        })
    }

    pub(super) fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub(super) fn store_dir_path(&self) -> Result<&Path> {
        self.db_path.parent().ok_or(Error::StorePathUnavailable)
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
