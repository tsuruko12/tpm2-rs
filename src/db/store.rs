use std::{
    fs,
    path::PathBuf,
};

use directories::ProjectDirs;
use rusqlite::{Connection, OptionalExtension, Transaction};
use tracing::debug;

use super::codec::{marshal_policy_data, unmarshal_policy_data};

use crate::{
    Error, Result, generate_key_id, hierarchy::Hierarchy, types::{
        PolicyData, SymmetricKeyBits, public::{BlockCipher, CipherMode},
        tpm::{Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmMarshal, TpmUnmarshal, TpmiDhPersistent, TpmtPublic},
    },
};

const DB_FILE: &str = "tpm2-rs.db";
const STORE_PATH_ENV: &str = "TPM2_RS_STORE_PATH";
const APP_NAME: &str = "tpm2-rs";

const SRK: &str = "srk";
const SESSION_SALT_KEY: &str = "session_salt_key";
const SHARED_WRAPPING_KEY: &str = "shared_wrapping_key";

const CREATE_SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE user_keys (
    key_name TEXT NOT NULL PRIMARY KEY,
    kind     TEXT NOT NULL CHECK (kind IN ('primary', 'child', 'symmetric'))
);

CREATE TABLE tpm_keys (
    key_name        TEXT NOT NULL PRIMARY KEY REFERENCES user_keys(key_name) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN ('primary', 'child')),
    hierarchy       TEXT CHECK (
        hierarchy IN ('owner', 'endorsement', 'platform')
    ),
    public          BLOB NOT NULL,
    object_name     BLOB NOT NULL,
    private         BLOB,
    persistent_handle INTEGER UNIQUE,
    policy          BLOB,
    parent_key_name TEXT REFERENCES tpm_keys(key_name) ON DELETE RESTRICT,

    CHECK (
        (kind = 'primary' AND hierarchy IS NOT NULL AND parent_key_name IS NULL AND private IS NULL) OR
        (kind = 'child' AND hierarchy IS NULL AND private IS NOT NULL)
    )
);

CREATE TABLE wrapping_keys (
    id          TEXT PRIMARY KEY,
    public      BLOB NOT NULL,
    private     BLOB NOT NULL,
    object_name BLOB NOT NULL,
    policy      BLOB
);

CREATE TABLE symmetric_keys (
    key_name        TEXT NOT NULL PRIMARY KEY REFERENCES user_keys(key_name) ON DELETE CASCADE,
    block_cipher    TEXT NOT NULL,
    key_bits        INTEGER NOT NULL,
    mode            TEXT NOT NULL,
    wrapped_key     BLOB NOT NULL,
    wrapping_key_id TEXT REFERENCES wrapping_keys(id)
);

CREATE TABLE hierarchy_policies (
    hierarchy TEXT PRIMARY KEY CHECK (
        hierarchy IN ('owner')
    ),
    policy BLOB
);

CREATE TABLE internal_persistent_keys (
    kind     TEXT PRIMARY KEY CHECK (
        kind IN ('srk', 'session_salt_key', 'shared_wrapping_key')
    ),
    handle   INTEGER NOT NULL UNIQUE CHECK (
        handle BETWEEN 2164260864 AND 2164326399
    ),
    object_name BLOB NOT NULL
);

INSERT INTO hierarchy_policies (hierarchy, policy) VALUES ('owner', NULL);
PRAGMA user_version = 1;
"#;

#[derive(Debug, Clone)]
pub(crate) struct InternalKeyMeta {
    pub(crate) kind: InternalKeyKind,
    pub(crate) handle: TpmiDhPersistent,
    pub(crate) obj_name: Tpm2bName,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum InternalKeyKind {
    Srk,
    SessionSaltKey,
    SharedWrappingKey,
}

impl InternalKeyKind {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Srk => SRK,
            Self::SessionSaltKey => SESSION_SALT_KEY,
            Self::SharedWrappingKey => SHARED_WRAPPING_KEY,
        }
    }
}

#[derive(Debug)]
pub(crate) enum KeyMeta {
    Tpm {
        key_name: String,
        hierarchy: Option<Hierarchy>,
        tpm_key_meta: TpmKeyMeta,
        persistent_handle: Option<TpmiDhPersistent>,
        parent_name: Option<String>,
    },
    Symmetric {
        key_name: String,
        block_cipher: BlockCipher,
        key_bits: SymmetricKeyBits,
        mode: CipherMode,
        wrapped_key: Vec<u8>,
        wrapping_key: WrappingKeyMeta,
    },
}

impl KeyMeta {
    pub(crate) fn owner_primary(
        key_name: String,
        tpm_key_meta: TpmKeyMeta,
        persistent_handle: Option<TpmiDhPersistent>,
    ) -> Self {
        Self::Tpm {
            key_name,
            hierarchy: Some(Hierarchy::Storage),
            tpm_key_meta,
            persistent_handle,
            parent_name: None,
        }
    }

    pub(crate) fn child(
        key_name: String,
        tpm_key_meta: TpmKeyMeta,
        persistent_handle: Option<TpmiDhPersistent>,
        parent_name: Option<String>,
    ) -> Self {
        Self::Tpm {
            key_name,
            hierarchy: None,
            tpm_key_meta,
            persistent_handle,
            parent_name,
        }
    }

    pub(crate) fn symmetric(
        key_name: String,
        block_cipher: BlockCipher,
        key_bits: SymmetricKeyBits,
        mode: CipherMode,
        wrapped_key: Vec<u8>,
        wrapping_key: WrappingKeyMeta,
    ) -> Self {
        Self::Symmetric {
            key_name,
            block_cipher,
            key_bits,
            mode,
            wrapped_key,
            wrapping_key,
        }
    }
}

#[derive(Debug)]
pub(crate) enum WrappingKeyMeta {
    Shared,
    Dedicated(TpmKeyMeta),
}

pub(crate) struct TpmKeyMeta {
    pub(crate) public: Tpm2bPublic,
    pub(crate) private: Option<Tpm2bPrivate>,
    pub(crate) obj_name: Tpm2bName,
    pub(crate) policy: Option<PolicyData>,
}

impl std::fmt::Debug for TpmKeyMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmKeyMeta")
            .field("public", &self.public)
            .field("private", &self.private.is_some())
            .field("obj_name", &self.obj_name)
            .field("policy", &self.policy)
            .finish()
    }
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

    pub(crate) fn ensure_uninitialized(&mut self) -> Result<()> {
        let meta = fs::metadata(&self.db_path)?;
        if meta.len() != 0 {
            return Err(Error::AlreadyProvisioned);
        }

        Ok(())
    }

    pub(crate) fn init(&mut self, key_meta: &[InternalKeyMeta]) -> Result<()> {
        let [srk, session_salt_key, shared_wrapping_key] = key_meta else {
            return Err(Error::invalid_state(
                "expected metadata for SRK, session salt key, and shared wrapping key",
            ));
        };

        let tx = self.conn.transaction()?;
        tx.execute_batch(CREATE_SCHEMA)?;

        let stmt = r#"
            INSERT INTO internal_persistent_keys (kind, handle, object_name)
            VALUES (?1, ?2, ?3)
        "#;

        for (kind, meta) in [
            (SRK, srk),
            (SESSION_SALT_KEY, session_salt_key),
            (SHARED_WRAPPING_KEY, shared_wrapping_key),
        ] {
            tx.execute(stmt, (kind, meta.handle.value(), meta.obj_name.as_bytes()))?;
        }

        tx.commit()?;

        Ok(())
    }

    pub(crate) fn ensure_unique_key_name(&self, key_name: &str) -> Result<()> {
        if self.user_key_exists(key_name)? {
            return Err(Error::KeyAlreadyExists(key_name.into()))
        }

        Ok(())
    }

    pub(crate) fn user_key_exists(&self, key_name: &str) -> Result<bool> {
        self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM user_keys WHERE key_name = ?1)", 
            [key_name], 
            |row| Ok(row.get(0)?)
        )
        .map_err(map_db_err)
    }

    pub(crate) fn load_key(&self, key_name: &str) -> Result<KeyMeta> {
        let kind = self
            .conn
            .query_row(
                "SELECT kind FROM user_keys WHERE key_name = ?1",
                [key_name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(map_db_err)?
            .ok_or(Error::KeyNotFound)?;

        match kind.as_str() {
            "primary" | "child" => self.load_tpm_key(key_name),
            "symmetric" => self.load_symmetric_key(key_name),
            _ => {
                debug!(%key_name, "stored key kind is invalid");
                Err(Error::corrupted_store())
            }
        }
    }

    pub(crate) fn load_tpm_key(&self, key_name: &str) -> Result<KeyMeta> {
        let stmt = r#"
            SELECT
                user_keys.key_name,
                user_keys.kind,
                tpm_keys.kind,
                tpm_keys.hierarchy,
                tpm_keys.public,
                tpm_keys.private,
                tpm_keys.object_name,
                tpm_keys.persistent_handle,
                tpm_keys.policy,
                tpm_keys.parent_key_name
            FROM user_keys
            JOIN tpm_keys ON tpm_keys.key_name = user_keys.key_name
            WHERE user_keys.key_name = ?1
        "#;

        let (
            key_name,
            user_key_kind,
            tpm_key_kind,
            hierarchy,
            public,
            private,
            object_name,
            persistent_handle,
            policy,
            parent_name,
        ) = self
            .conn
            .query_row(stmt, [key_name], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                ))
            })
            .optional()
            .map_err(map_db_err)?
            .ok_or(Error::KeyNotFound)?;

        if user_key_kind != tpm_key_kind {
            debug!(?user_key_kind, ?tpm_key_kind, "key kinds are inconsistent");
            return Err(Error::corrupted_store());
        }

        let hierarchy = match (
            tpm_key_kind.as_str(),
            hierarchy.as_deref(),
            parent_name.as_deref(),
        ) {
            ("primary", Some(hierarchy), None) => Some(Hierarchy::from_db(hierarchy)?),
            ("child", None, _) => None,
            _ => {
                debug!(
                    key_name,
                    ?tpm_key_kind,
                    ?hierarchy,
                    ?parent_name,
                    "TPM key metadata is inconsistent"
                );
                return Err(Error::corrupted_store());
            }
        };

        match (tpm_key_kind.as_str(), private.is_some()) {
            ("primary", false) | ("child", true) => {}
            _ => {
                debug!(
                    %key_name,
                    ?tpm_key_kind,
                    has_private = private.is_some(),
                    "TPM key private data is inconsistent"
                );
                return Err(Error::corrupted_store());
            }
        }

        let persistent_handle = persistent_handle
            .map(|value| {
                let value = u32::try_from(value).map_err(Error::corrupted_store_with_source)?;
                TpmiDhPersistent::try_from(value).map_err(Error::corrupted_store_with_source)
            })
            .transpose()?;
        let tpm_key_meta = Self::load_tpm_key_meta(public, private, object_name, policy.as_deref())?;

        Ok(KeyMeta::Tpm {
            key_name,
            hierarchy,
            tpm_key_meta,
            persistent_handle,
            parent_name,
        })
    }

    pub(crate) fn load_symmetric_key(&self, key_name: &str) -> Result<KeyMeta> {
        let stmt = r#"
            SELECT
                user_keys.key_name,
                user_keys.kind,
                symmetric_keys.block_cipher,
                symmetric_keys.key_bits,
                symmetric_keys.mode,
                symmetric_keys.wrapped_key,
                symmetric_keys.wrapping_key_id,
                wrapping_keys.public,
                wrapping_keys.private,
                wrapping_keys.object_name,
                wrapping_keys.policy
            FROM user_keys
            LEFT JOIN symmetric_keys ON symmetric_keys.key_name = user_keys.key_name
            LEFT JOIN wrapping_keys ON wrapping_keys.id = symmetric_keys.wrapping_key_id
            WHERE user_keys.key_name = ?1
        "#;

        let (
            name,
            user_key_kind,
            block_cipher,
            key_bits,
            mode,
            wrapped_key,
            wrapping_key_id,
            wrapping_public,
            wrapping_private,
            wrapping_object_name,
            wrapping_policy,
        ) = self
            .conn
            .query_row(stmt, [key_name], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<u32>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, Option<Vec<u8>>>(10)?,
                ))
            })
            .optional()
            .map_err(map_db_err)?
            .ok_or(Error::KeyNotFound)?;

        if user_key_kind != "symmetric" {
            return Err(Error::invalid_key("requested key is not symmetric"));
        }

        let (Some(block_cipher), Some(key_bits), Some(mode), Some(wrapped_key)) =
            (block_cipher, key_bits, mode, wrapped_key)
        else {
            debug!(%key_name, "symmetric key metadata is missing");
            return Err(Error::corrupted_store());
        };
        let block_cipher = BlockCipher::from_db(&block_cipher)?;
        let key_bits = SymmetricKeyBits::from_db(key_bits)?;
        let mode = CipherMode::from_db(&mode)?;

        let wrapping_key = match wrapping_key_id {
            Some(id) => {
                let (Some(public), Some(private), Some(object_name)) =
                    (wrapping_public, wrapping_private, wrapping_object_name)
                else {
                    debug!(%id, "dedicated wrapping key metadata is missing");
                    return Err(Error::corrupted_store());
                };

                WrappingKeyMeta::Dedicated(Self::load_tpm_key_meta(
                    public,
                    Some(private),
                    object_name,
                    wrapping_policy.as_deref(),
                )?)
            }
            None => WrappingKeyMeta::Shared,
        };

        Ok(KeyMeta::symmetric(
            name,
            block_cipher,
            key_bits,
            mode,
            wrapped_key,
            wrapping_key,
        ))
    }

    fn load_tpm_key_meta(
        public: Vec<u8>,
        private: Option<Vec<u8>>,
        obj_name: Vec<u8>,
        policy: Option<&[u8]>,
    ) -> Result<TpmKeyMeta> {
        let mut public_bytes = public.as_slice();
        let public =
            TpmtPublic::unmarshal(&mut public_bytes).map_err(Error::corrupted_store_with_source)?;

        if !public_bytes.is_empty() {
            debug!(
                remaining_size = public_bytes.len(),
                "stored TPM public area has trailing bytes"
            );
            return Err(Error::corrupted_store());
        }
        let private = private
            .map(|private| {
                Tpm2bPrivate::try_from(private).map_err(Error::corrupted_store_with_source)
            })
            .transpose()?;
        let obj_name = obj_name.try_into().map_err(Error::corrupted_store_with_source)?;

        Ok(TpmKeyMeta {
            public: public.into(),
            private,
            obj_name,
            policy: policy.map(unmarshal_policy_data).transpose()?,
        })
    }

    pub(crate) fn load_key_policy(&self, key_name: &str) -> Result<Option<PolicyData>> {
        match self.load_key(key_name)? {
            KeyMeta::Tpm { tpm_key_meta, .. } => Ok(tpm_key_meta.policy),
            KeyMeta::Symmetric { wrapping_key, .. } => match wrapping_key {
                WrappingKeyMeta::Shared => Ok(None),
                WrappingKeyMeta::Dedicated(tpm_key_meta) => Ok(tpm_key_meta.policy),
            },
        }
    }

    pub(crate) fn load_owner_policy(&self) -> Result<Option<PolicyData>> {
        self.load_hierarchy_policy(Hierarchy::Storage)
    }

    pub(crate) fn load_hierarchy_policy(&self, hierarchy: Hierarchy) -> Result<Option<PolicyData>> {
        let policy = self
            .conn
            .query_row(
                "SELECT policy FROM hierarchy_policies WHERE hierarchy = ?",
                [hierarchy.as_str()],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .map_err(map_db_err)?
            .flatten();

        policy.as_deref().map(unmarshal_policy_data).transpose()
    }

    pub(crate) fn load_internal_srk(&self) -> Result<InternalKeyMeta> {
        self.load_internal_key_meta(InternalKeyKind::Srk)
    }

    pub(crate) fn load_session_salt_key(&self) -> Result<InternalKeyMeta> {
        self.load_internal_key_meta(InternalKeyKind::SessionSaltKey)
    }

    pub(crate) fn load_shared_wrapping_key(&self) -> Result<InternalKeyMeta> {
        self.load_internal_key_meta(InternalKeyKind::SharedWrappingKey)
    }

    fn load_internal_key_meta(&self, kind: InternalKeyKind) -> Result<InternalKeyMeta> {
        let stmt = r#"
            SELECT handle, object_name
            FROM internal_persistent_keys 
            WHERE kind = ?1
        "#;

        let (handle, obj_name) = self
            .conn
            .query_row(stmt, [kind.as_str()], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                ))
            })
            .optional()
            .map_err(map_db_err)?
            .ok_or_else(|| {
                debug!(?kind, "required stored data is missing");
                Error::corrupted_store()
            })?;

        let persistent_handle =
            TpmiDhPersistent::try_from(handle).map_err(Error::corrupted_store_with_source)?;

        let obj_name = Tpm2bName::try_from(obj_name).map_err(Error::corrupted_store_with_source)?;

        Ok(InternalKeyMeta {
            kind,
            handle: persistent_handle,
            obj_name,
        })
    }

    pub(crate) fn save_key_meta(&mut self, key_meta: &KeyMeta) -> Result<()> {
        let tx = self.conn.transaction()?;

        match key_meta {
            KeyMeta::Tpm {
                key_name,
                hierarchy,
                tpm_key_meta,
                persistent_handle,
                parent_name,
            } => save_tpm_key_meta(
                &tx,
                key_name,
                *hierarchy,
                tpm_key_meta,
                *persistent_handle,
                parent_name.as_deref(),
            )?,
            KeyMeta::Symmetric {
                key_name,
                block_cipher,
                key_bits,
                mode,
                wrapped_key,
                wrapping_key,
            } => save_sym_key_meta(
                &tx,
                key_name,
                *block_cipher,
                *key_bits,
                *mode,
                wrapped_key,
                wrapping_key,
            )?,
        }

        tx.commit()?;
        Ok(())
    }

    pub(crate) fn update_persistent_handle(
        &self,
        key_name: &str,
        persistent_handle: u32,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE tpm_keys SET persistent_handle = ?1 WHERE key_name = ?2",
            (persistent_handle, key_name),
        )?;

        Ok(())
    }
}

fn save_tpm_key_meta(
    tx: &Transaction<'_>,
    key_name: &str,
    hierarchy: Option<Hierarchy>,
    tpm_key_meta: &TpmKeyMeta,
    persistent_handle: Option<TpmiDhPersistent>,
    parent_name: Option<&str>,
) -> Result<()> {
    let kind = if hierarchy.is_some() { "primary" } else { "child" };
    let hierarchy = hierarchy.map(|hierarchy| hierarchy.as_str());
    let private = tpm_key_meta.private.as_ref().map(Tpm2bPrivate::as_bytes);
    let policy = tpm_key_meta
        .policy
        .as_ref()
        .map(marshal_policy_data)
        .transpose()?;
    let mut public = Vec::new();
    tpm_key_meta.public.as_inner().marshal(&mut public)?;

    tx.execute(
        "INSERT INTO user_keys (key_name, kind) VALUES (?1, ?2)",
        (key_name, kind),
    )?;
    tx.execute(
        r#"
            INSERT INTO tpm_keys (
                key_name,
                kind,
                hierarchy,
                public,
                object_name,
                private,
                persistent_handle,
                policy,
                parent_key_name
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
        (
            key_name,
            kind,
            hierarchy,
            public,
            tpm_key_meta.obj_name.as_bytes(),
            private,
            persistent_handle.map(|handle| handle.value()),
            policy.as_deref(),
            parent_name,
        ),
    )?;

    Ok(())
}

fn save_sym_key_meta(
    tx: &Transaction<'_>,
    key_name: &str,
    block_cipher: BlockCipher,
    key_bits: SymmetricKeyBits,
    mode: CipherMode,
    wrapped_key: &[u8],
    wrapping_key: &WrappingKeyMeta,
) -> Result<()> {
    let wrapping_key_id = match wrapping_key {
        WrappingKeyMeta::Shared => None,
        WrappingKeyMeta::Dedicated(meta) => Some(save_dedicated_wrapping_key(tx, meta)?),
    };

    tx.execute(
        "INSERT INTO user_keys (key_name, kind) VALUES (?1, 'symmetric')",
        [key_name],
    )?;
    tx.execute(
        r#"
            INSERT INTO symmetric_keys (
                key_name,
                block_cipher,
                key_bits,
                mode,
                wrapped_key,
                wrapping_key_id
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
        (
            key_name,
            block_cipher.as_str(),
            key_bits.as_str(),
            mode.as_str(),
            wrapped_key,
            wrapping_key_id.as_deref(),
        ),
    )?;

    Ok(())
}

fn save_dedicated_wrapping_key(tx: &Transaction<'_>, key_meta: &TpmKeyMeta) -> Result<String> {
    let private = key_meta.private.as_ref().ok_or_else(|| {
        Error::invalid_state("dedicated wrapping key metadata must contain private data")
    })?;
    let policy = key_meta
        .policy
        .as_ref()
        .map(marshal_policy_data)
        .transpose()?;

    let mut public = Vec::new();
    key_meta.public.as_inner().marshal(&mut public)?;

    let id = generate_key_id()?;
    tx.execute(
        r#"
            INSERT INTO wrapping_keys (id, public, private, object_name, policy)
            VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        (
            id.as_str(),
            public,
            private.as_bytes(),
            key_meta.obj_name.as_bytes(),
            policy.as_deref(),
        ),
    )?;

    Ok(id)
}

fn map_db_err(err: rusqlite::Error) -> Error {
    if let rusqlite::Error::SqliteFailure(_, Some(msg)) = &err
        && msg.starts_with("no such table:")
    {
        Error::NotProvisioned
    } else {
        Error::Store(err)
    }
}

fn store_path_from_env() -> Option<PathBuf> {
    std::env::var_os(STORE_PATH_ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn default_dir_path() -> Result<PathBuf> {
    ProjectDirs::from("", "", APP_NAME)
        .map(|dirs| dirs.data_local_dir().to_path_buf())
        .ok_or(Error::StorePathUnavailable)
}
