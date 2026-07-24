use std::{
    fs,
    path::{Path, PathBuf},
};

use directories::ProjectDirs;
use rusqlite::{Connection, OptionalExtension};

use crate::{
    Error, Result, generate_random_bytes, policy::{Policy, PolicyCommand}, types::TpmiDhPersistent,
};

const DB_FILE: &str = "store.db"; // will change later
const STORE_PATH_ENV: &str = "TPM_STORE_PATH"; // will change later
const PROJECT_APPLICATION: &str = "tpm-tool"; // will change later
const FILE_VERSION: u8 = 1;

const HANDLE_SRK: &str = "srk";
const HANDLE_SESSION_SALT_KEY: &str = "session_salt_key";
const HANDLE_SHARED_WRAPPING_KEY: &str = "shared_wrapping_key";

const CREATE_SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE user_keys (
    id       TEXT PRIMARY KEY,
    key_name TEXT NOT NULL UNIQUE,
    kind     TEXT NOT NULL CHECK (kind IN ('primary', 'child', 'symmetric'))
);

CREATE TABLE policies (
    id                 TEXT PRIMARY KEY,
    kind               TEXT NOT NULL CHECK (
        kind IN ('auth_value', 'password', 'pcr', 'command', 'sequence', 'or')
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
            kind IN ('auth_value', 'password') AND
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
    object_name          BLOB NOT NULL,
    private           BLOB,
    parent_id         TEXT REFERENCES tpm_keys(id) ON DELETE RESTRICT,
    load_source       TEXT NOT NULL CHECK (
        load_source IN ('recreate', 'stored_blob', 'persistent')
    ),
    persistent_handle INTEGER UNIQUE,
    policy_id         TEXT REFERENCES policies(id) ON DELETE RESTRICT,

    FOREIGN KEY (id) REFERENCES user_keys(id) ON DELETE CASCADE,

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
    private   BLOB NOT NULL
);

CREATE TABLE symmetric_keys (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL DEFAULT 'symmetric' CHECK (kind = 'symmetric'),
    block_cipher    TEXT NOT NULL,
    key_bits        INTEGER NOT NULL,
    mode            TEXT NOT NULL,
    wrapped_key     BLOB NOT NULL,
    wrapping_key_id TEXT NOT NULL REFERENCES wrapping_keys(id),

    FOREIGN KEY (id) REFERENCES user_keys(id) ON DELETE CASCADE
);

CREATE TABLE hierarchy_policies (
    hierarchy TEXT PRIMARY KEY CHECK (
        hierarchy IN ('owner')
    ),
    policy_id TEXT REFERENCES policies(id) ON DELETE SET NULL
);

CREATE TABLE internal_persistent_objects (
    kind     TEXT PRIMARY KEY CHECK (
        kind IN ('srk', 'session_salt_key', 'shared_wrapping_key')
    ),
    handle   INTEGER NOT NULL UNIQUE CHECK (
        handle BETWEEN 2164260864 AND 2164326399
    ),
    object_name BLOB NOT NULL
);

INSERT INTO hierarchy_policies (hierarchy, policy_id) VALUES ('owner', NULL);
PRAGMA user_version = 1;
"#;

#[derive(Debug, Clone)]
pub(crate) struct InternalKeyMeta {
    pub(crate) handle: TpmiDhPersistent,
    pub(crate) object_name: Vec<u8>,
}

pub(crate) struct MetadataStore {
    pub(crate) db_path: PathBuf,
    pub(crate) conn: Connection,
}

impl MetadataStore {
    pub(crate) fn new() -> Result<Self> {
        let dir_path = store_path_from_env().map_or_else(default_dir_path, Ok)?;
        fs::create_dir_all(&dir_path)?;
        let db_path = dir_path.join(DB_FILE);

        let conn = Connection::open(&db_path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        Ok(Self { db_path, conn })
    }

    fn store_dir_path(&mut self) -> Result<&Path> {
        self.db_path.parent().ok_or(Error::StorePathUnavailable)
    }

    pub(crate) fn init(&mut self) -> Result<()> {
        let meta = fs::metadata(&self.db_path)?;
        if meta.len() == 0 {
            return Err(Error::StoreAlreadyExists);
        }

        let tx = self.conn.transaction()?;
        tx.execute_batch(CREATE_SCHEMA)?;
        tx.commit()?;

        Ok(())
    }

    pub(crate) fn add_internal_key_meta(&mut self, key_meta: &[InternalKeyMeta]) -> Result<()> {
        let [srk, session_salt_key, shared_wrapping_key] = key_meta else {
            return Err(Error::invalid_state(
                "expected metadata for SRK, session salt key, and shared wrapping key",
            ));
        };

        let tx = self.conn.transaction()?;
        let stmt = r#"
            INSERT INTO internal_persistent_objects (kind, handle, object_name)
            VALUES (?1, ?2, ?3)
        "#;

        for (kind, meta) in [
            (HANDLE_SRK, srk),
            (HANDLE_SESSION_SALT_KEY, session_salt_key),
            (HANDLE_SHARED_WRAPPING_KEY, shared_wrapping_key),
        ] {
            tx.execute(stmt, (kind, meta.handle.raw(), &meta.object_name))?;
        }

        tx.commit()?;

        Ok(())
    }

    pub(crate) fn load_owner_policy(&self) -> Result<Option<Policy>> {
        let policy_id = self
            .conn
            .query_row(
                "SELECT policy_id FROM hierarchy_policies WHERE hierarchy = 'owner'",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .ok_or_else(Error::corrupted_store)?;

        policy_id
            .as_deref()
            .map(|policy_id| self.load_policy(policy_id))
            .transpose()
    }

    fn load_policy(&self, policy_id: &str) -> Result<Policy> {
        let (kind, command) = self
            .conn
            .query_row(
                "SELECT kind, command FROM policies WHERE id = ?1",
                [policy_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .ok_or_else(Error::corrupted_store)?;

        match kind.as_str() {
            "auth_value" => Ok(Policy::AuthValue),
            "password" => Ok(Policy::Password),
            "command" => Ok(Policy::Command(policy_command_from_str(
                command.as_deref().ok_or_else(Error::corrupted_store)?,
            )?)),
            _ => Err(Error::corrupted_store()),
        }
    }

    pub(crate) fn load_srk(&self) -> Result<InternalKeyMeta> {
        self.load_internal_key_meta(HANDLE_SRK)
    }

    pub(crate) fn load_session_salt_key(&self) -> Result<InternalKeyMeta> {
        self.load_internal_key_meta(HANDLE_SESSION_SALT_KEY)
    }

    pub(crate) fn load_shared_wrapping_key(&self) -> Result<InternalKeyMeta> {
        self.load_internal_key_meta(HANDLE_SHARED_WRAPPING_KEY)
    }

    fn load_internal_key_meta(&self, kind: &str) -> Result<InternalKeyMeta> {
        let stmt = r#"
            SELECT handle, object_name 
            FROM internal_persistent_objects 
            WHERE kind = ?1
        "#;

        let (handle, object_name) = self.conn
            .query_row(stmt, [kind], |row| {
                Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .optional()?
            .ok_or_else(Error::corrupted_store)?;

        Ok(InternalKeyMeta { handle: handle.try_into()?, object_name })
    }
}

fn policy_command_from_str(command: &str) -> Result<PolicyCommand> {
    match command {
        "create_primary" => Ok(PolicyCommand::CreatePrimary),
        "create" => Ok(PolicyCommand::Create),
        "load" => Ok(PolicyCommand::Load),
        "import" => Ok(PolicyCommand::Import),
        "duplicate" => Ok(PolicyCommand::Duplicate),
        "sign" => Ok(PolicyCommand::Sign),
        "decrypt" => Ok(PolicyCommand::Decrypt),
        "unseal" => Ok(PolicyCommand::Unseal),
        _ => Err(Error::corrupted_store()),
    }
}

pub(crate) fn generate_id() -> Result<String> {
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
