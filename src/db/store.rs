use std::{
    fs,
    path::{Path, PathBuf},
};

use directories::ProjectDirs;
use rusqlite::{Connection, OptionalExtension, Transaction};
use tracing::debug;

use crate::{
    Error, Result, generate_key_id, hierarchy::Hierarchy, policy::{PcrSelection, PcrSlot, PolicyCommand}, types::{
        PolicyData, SymmetricKeyBits, algorithm::HashAlgorithm, public::{BlockCipher, CipherMode},
        tpm::{Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmMarshal, TpmUnmarshal, TpmiDhPersistent, TpmlDigest, TpmtPublic, ensure_consumed},
    },
};

const DB_FILE: &str = "tpm2-rs.db";
const STORE_PATH_ENV: &str = "TPM2_RS_STORE_PATH";
const APP_NAME: &str = "tpm2-rs";

const HANDLE_SRK: &str = "srk";
const HANDLE_SESSION_SALT_KEY: &str = "session_salt_key";
const HANDLE_SHARED_WRAPPING_KEY: &str = "shared_wrapping_key";
const MIN_POLICY_OR_BRANCHES: usize = 2;

const CREATE_SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE user_keys (
    key_name TEXT NOT NULL PRIMARY KEY,
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
            'sha512'
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
    or_branch_digests BLOB,
    
    UNIQUE (id, kind),

    CHECK (
        (
            kind IN ('auth_value', 'password') AND
            pcr_hash_alg IS NULL AND
            pcr_slots_mask IS NULL AND
            command IS NULL AND
            or_branch_digests IS NULL
        ) OR (
            kind = 'pcr' AND
            pcr_hash_alg IS NOT NULL AND
            pcr_slots_mask IS NOT NULL AND
            command IS NULL AND
            or_branch_digests IS NULL
        ) OR (
            kind = 'command' AND
            pcr_hash_alg IS NULL AND
            pcr_slots_mask IS NULL AND
            command IS NOT NULL AND
            or_branch_digests IS NULL
        ) OR (
            kind = 'sequence' AND
            pcr_hash_alg IS NULL AND
            pcr_slots_mask IS NULL AND
            command IS NULL AND
            or_branch_digests IS NULL
        ) OR (
            kind = 'or' AND
            pcr_hash_alg IS NULL AND
            pcr_slots_mask IS NULL AND
            command IS NULL AND
            or_branch_digests IS NOT NULL
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
    key_name        TEXT NOT NULL PRIMARY KEY REFERENCES user_keys(key_name) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN ('primary', 'child')),
    hierarchy       TEXT CHECK (
        hierarchy IN ('owner', 'endorsement', 'platform')
    ),
    public          BLOB NOT NULL,
    object_name     BLOB NOT NULL,
    private         BLOB,
    persistent_handle INTEGER UNIQUE,
    policy_id       TEXT REFERENCES policies(id) ON DELETE RESTRICT,
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
    policy_id   TEXT REFERENCES policies(id) ON DELETE RESTRICT
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
    policy_id TEXT REFERENCES policies(id) ON DELETE SET NULL
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

INSERT INTO hierarchy_policies (hierarchy, policy_id) VALUES ('owner', NULL);
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
            Self::Srk => HANDLE_SRK,
            Self::SessionSaltKey => HANDLE_SESSION_SALT_KEY,
            Self::SharedWrappingKey => HANDLE_SHARED_WRAPPING_KEY,
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

    fn store_dir_path(&mut self) -> Result<&Path> {
        self.db_path.parent().ok_or(Error::StorePathUnavailable)
    }

    pub(crate) fn ensure_uninitialized(&mut self) -> Result<()> {
        let meta = fs::metadata(&self.db_path)?;
        if meta.len() != 0 {
            return Err(Error::StoreAlreadyExists);
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
            (HANDLE_SRK, srk),
            (HANDLE_SESSION_SALT_KEY, session_salt_key),
            (HANDLE_SHARED_WRAPPING_KEY, shared_wrapping_key),
        ] {
            tx.execute(stmt, (kind, meta.handle.value(), meta.obj_name.as_bytes()))?;
        }

        tx.commit()?;

        Ok(())
    }

    pub(crate) fn ensure_unique_key_name(&self, key_name: &str) -> Result<()> {
        let exists = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM user_keys WHERE key_name = ?1)", 
            [key_name], 
            |row| Ok(row.get(0)?)
        )?;

        if exists {
            Err(Error::KeyAlreadyExists(key_name.into()))
        } else {
            Ok(())
        }
    }

    pub(crate) fn load_key(&self, key_name: &str) -> Result<KeyMeta> {
        let kind = self
            .conn
            .query_row(
                "SELECT kind FROM user_keys WHERE key_name = ?1",
                [key_name],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(Error::KeyNotFound)?;

        match kind.as_str() {
            "primary" | "child" => self.load_tpm_key(key_name),
            "symmetric" => self.load_symmetric_key(key_name),
            _ => {
                debug!(%key_name, %kind, "stored key kind is invalid");
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
                tpm_keys.policy_id,
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
            policy_id,
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
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                ))
            })
            .optional()?
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
        let tpm_key_meta =
            self.load_tpm_key_meta(public, private, object_name, policy_id.as_deref())?;

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
                wrapping_keys.policy_id
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
            wrapping_policy_id,
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
                    row.get::<_, Option<String>>(10)?,
                ))
            })
            .optional()?
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
        let block_cipher = block_cipher_from_db(&block_cipher)?;
        let key_bits = symmetric_key_bits_from_db(key_bits)?;
        let mode = cipher_mode_from_db(&mode)?;

        let wrapping_key = match wrapping_key_id {
            Some(id) => {
                let (Some(public), Some(private), Some(object_name)) =
                    (wrapping_public, wrapping_private, wrapping_object_name)
                else {
                    debug!(%id, "dedicated wrapping key metadata is missing");
                    return Err(Error::corrupted_store());
                };

                WrappingKeyMeta::Dedicated(self.load_tpm_key_meta(
                    public,
                    Some(private),
                    object_name,
                    wrapping_policy_id.as_deref(),
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
        &self,
        public: Vec<u8>,
        private: Option<Vec<u8>>,
        obj_name: Vec<u8>,
        policy_id: Option<&str>,
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
                Tpm2bPrivate::try_from(private).map_err(|_| {
                    debug!("invalid stored private data");
                    Error::corrupted_store()
                })
            })
            .transpose()?;
        let obj_name = obj_name.try_into().map_err(|_| {
            debug!("invalid stored object name");
            Error::corrupted_store()
        })?;

        Ok(TpmKeyMeta {
            public: public.into(),
            private,
            obj_name,
            policy: policy_id
                .map(|policy_id| self.load_policy(policy_id))
                .transpose()?,
        })
    }

    pub(crate) fn load_owner_policy(&self) -> Result<Option<PolicyData>> {
        self.load_hierarchy_policy(Hierarchy::Storage)
    }

    pub(crate) fn load_hierarchy_policy(&self, hierarchy: Hierarchy) -> Result<Option<PolicyData>> {
        let policy_id = self
            .conn
            .query_row(
                "SELECT policy_id FROM hierarchy_policies WHERE hierarchy = ?",
                [hierarchy.as_str()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();

        policy_id
            .as_deref()
            .map(|policy_id| self.load_policy(policy_id))
            .transpose()
    }

    fn load_policy(&self, policy_id: &str) -> Result<PolicyData> {
        self.load_policy_recursive(policy_id, &mut Vec::new())
    }

    fn load_policy_recursive(
        &self,
        policy_id: &str,
        ancestors: &mut Vec<String>,
    ) -> Result<PolicyData> {
        if ancestors.iter().any(|ancestor| ancestor == policy_id) {
            debug!(%policy_id, "stored policy graph contains a cycle");
            return Err(Error::corrupted_store());
        }

        ancestors.push(policy_id.to_owned());
        let result = self.load_policy_inner(policy_id, ancestors);
        ancestors.pop();

        result
    }

    fn load_policy_inner(
        &self,
        policy_id: &str,
        ancestors: &mut Vec<String>,
    ) -> Result<PolicyData> {
        let (kind, pcr_hash_alg, pcr_slots_mask, command, or_branch_digests) = self
            .conn
            .query_row(
                r#"
                    SELECT kind, pcr_hash_alg, pcr_slots_mask, command, or_branch_digests
                    FROM policies
                    WHERE id = ?1
                "#,
                [policy_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<u32>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| {
                debug!("stored policy data is missing");
                Error::corrupted_store()
            })?;

        match kind.as_str() {
            "auth_value" => Ok(PolicyData::AuthValue),
            "password" => Ok(PolicyData::Password),
            "command" => {
                let command = command.as_deref().ok_or_else(|| {
                    debug!("stored policy command is missing");
                    Error::corrupted_store()
                })?;
                Ok(PolicyData::Command(PolicyCommand::from_db(command)?))
            },
            "pcr" => {
                let hash_alg = pcr_hash_alg.as_deref().ok_or_else(|| {
                    debug!(%policy_id, "stored PCR hash algorithm is missing");
                    Error::corrupted_store()
                })?;
                let slots_mask = pcr_slots_mask.ok_or_else(|| {
                    debug!(%policy_id, "stored PCR slot mask is missing");
                    Error::corrupted_store()
                })?;
                let slots = pcr_slots_from_mask(slots_mask)?;
                let selection = PcrSelection::new(HashAlgorithm::from_db(hash_alg)?, &slots)
                    .map_err(Error::corrupted_store_with_source)?;

                Ok(PolicyData::Pcr(selection))
            },
            "sequence" => Ok(PolicyData::Sequence(
                self.load_policy_children(policy_id, ancestors)?,
            )),
            "or" => {
                let bytes = or_branch_digests.as_deref().ok_or_else(|| {
                    debug!(%policy_id, "stored PolicyOR digests are missing");
                    Error::corrupted_store()
                })?;
                let branches = self.load_policy_children(policy_id, ancestors)?;
                let branch_digests =
                    unmarshal_policy_or_digests(bytes, branches.len()).map_err(|_| {
                        debug!(%policy_id, "stored PolicyOR digests are invalid");
                        Error::corrupted_store()
                    })?;

                Ok(PolicyData::Or {
                    branches,
                    branch_digests,
                    selected_branch: None,
                })
            },
            _ => {
                debug!(%kind, "invalid stored policy kind");
                Err(Error::corrupted_store())
            }
        }
    }

    fn load_policy_children(
        &self,
        policy_id: &str,
        ancestors: &mut Vec<String>,
    ) -> Result<Vec<PolicyData>> {
        let children = {
            let mut statement = self.conn.prepare(
                r#"
                    SELECT child_index, child_id
                    FROM policy_branches
                    WHERE parent_id = ?1
                    ORDER BY child_index
                "#,
            )?;
            let rows = statement.query_map([policy_id], |row| {
                Ok((row.get::<_, usize>(0)?, row.get::<_, String>(1)?))
            })?;

            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };

        let mut policies = Vec::with_capacity(children.len());
        for (expected_index, (child_index, child_id)) in children.into_iter().enumerate() {
            if child_index != expected_index {
                debug!(
                    %policy_id, 
                    child_index, 
                    expected_index, 
                    "stored policy child indexes are non-contiguous"
                );
                return Err(Error::corrupted_store());
            }

            policies.push(self.load_policy_recursive(&child_id, ancestors)?);
        }

        Ok(policies)
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
            .optional()?
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
    let policy_id = tpm_key_meta
        .policy
        .as_ref()
        .map(|policy| save_policy(tx, policy))
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
                policy_id,
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
            policy_id.as_deref(),
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
            block_cipher_to_db(block_cipher),
            symmetric_key_bits_to_db(key_bits),
            cipher_mode_to_db(mode),
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
    let policy_id = key_meta
        .policy
        .as_ref()
        .map(|policy| save_policy(tx, policy))
        .transpose()?;

    let mut public = Vec::new();
    key_meta.public.as_inner().marshal(&mut public)?;

    let id = generate_key_id()?;
    tx.execute(
        r#"
            INSERT INTO wrapping_keys (id, public, private, object_name, policy_id)
            VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        (
            id.as_str(),
            public,
            private.as_bytes(),
            key_meta.obj_name.as_bytes(),
            policy_id.as_deref(),
        ),
    )?;

    Ok(id)
}

fn save_policy(tx: &Transaction<'_>, policy: &PolicyData) -> Result<String> {
    let id = generate_key_id()?;

    match policy {
        PolicyData::AuthValue => {
            tx.execute(
                "INSERT INTO policies (id, kind) VALUES (?1, 'auth_value')",
                [id.as_str()],
            )?;
        }
        PolicyData::Password => {
            tx.execute(
                "INSERT INTO policies (id, kind) VALUES (?1, 'password')",
                [id.as_str()],
            )?;
        }
        PolicyData::Command(command) => {
            tx.execute(
                "INSERT INTO policies (id, kind, command) VALUES (?1, 'command', ?2)",
                (id.as_str(), policy_command_to_db(*command)),
            )?;
        }
        PolicyData::Pcr(selection) => {
            tx.execute(
                r#"
                    INSERT INTO policies (id, kind, pcr_hash_alg, pcr_slots_mask)
                    VALUES (?1, 'pcr', ?2, ?3)
                "#,
                (
                    id.as_str(),
                    hash_algorithm_to_db(selection.hash_alg()),
                    pcr_slots_to_mask(selection),
                ),
            )?;
        }
        PolicyData::Sequence(steps) => {
            tx.execute(
                "INSERT INTO policies (id, kind) VALUES (?1, 'sequence')",
                [id.as_str()],
            )?;
            save_policy_children(tx, id.as_str(), steps)?;
        }
        PolicyData::Or {
            branches,
            branch_digests,
            ..
        } => {
            let digests = marshal_policy_or_digests(branch_digests, branches.len())?;
            tx.execute(
                r#"
                    INSERT INTO policies (id, kind, or_branch_digests)
                    VALUES (?1, 'or', ?2)
                "#,
                (id.as_str(), digests),
            )?;
            save_policy_children(tx, id.as_str(), branches)?;
        }
    }

    Ok(id)
}

fn save_policy_children(
    tx: &Transaction<'_>,
    parent_id: &str,
    children: &[PolicyData],
) -> Result<()> {
    for (child_index, child) in children.iter().enumerate() {
        let child_id = save_policy(tx, child)?;
        tx.execute(
            r#"
                INSERT INTO policy_branches (parent_id, child_index, child_id)
                VALUES (?1, ?2, ?3)
            "#,
            (parent_id, child_index as i64, child_id.as_str()),
        )?;
    }

    Ok(())
}

fn marshal_policy_or_digests(
    branch_digests: &TpmlDigest,
    branch_count: usize,
) -> Result<Vec<u8>> {
    if branch_count < MIN_POLICY_OR_BRANCHES {
        return Err(Error::invalid_state("PolicyOR branch count is invalid"));
    }
    if branch_digests.len() < MIN_POLICY_OR_BRANCHES {
        return Err(Error::invalid_state(
            "PolicyOR digest count is invalid",
        ));
    }

    let mut output = Vec::new();
    branch_digests.marshal(&mut output)?;

    Ok(output)
}

fn policy_command_to_db(command: PolicyCommand) -> &'static str {
    match command {
        PolicyCommand::CreatePrimary => "create_primary",
        PolicyCommand::Create => "create",
        PolicyCommand::Load => "load",
        PolicyCommand::Import => "import",
        PolicyCommand::Duplicate => "duplicate",
        PolicyCommand::Sign => "sign",
        PolicyCommand::Decrypt => "decrypt",
        PolicyCommand::Unseal => "unseal",
    }
}

fn hash_algorithm_to_db(hash_alg: HashAlgorithm) -> &'static str {
    match hash_alg {
        HashAlgorithm::Sha1 => "sha1",
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Sha384 => "sha384",
        HashAlgorithm::Sha512 => "sha512",
    }
}

fn pcr_slots_to_mask(selection: &PcrSelection) -> u32 {
    selection
        .slots()
        .iter()
        .fold(0, |mask, &slot| mask | (1 << slot as u8))
}

fn block_cipher_to_db(block_cipher: BlockCipher) -> &'static str {
    match block_cipher {
        BlockCipher::Aes => "aes",
        BlockCipher::Camellia => "camellia",
    }
}

fn block_cipher_from_db(block_cipher: &str) -> Result<BlockCipher> {
    match block_cipher {
        "aes" => Ok(BlockCipher::Aes),
        "camellia" => Ok(BlockCipher::Camellia),
        _ => {
            debug!(%block_cipher, "invalid stored symmetric block cipher");
            Err(Error::corrupted_store())
        }
    }
}

fn symmetric_key_bits_to_db(key_bits: SymmetricKeyBits) -> u32 {
    match key_bits {
        SymmetricKeyBits::Bits128 => 128,
        SymmetricKeyBits::Bits256 => 256,
    }
}

fn symmetric_key_bits_from_db(key_bits: u32) -> Result<SymmetricKeyBits> {
    match key_bits {
        128 => Ok(SymmetricKeyBits::Bits128),
        256 => Ok(SymmetricKeyBits::Bits256),
        _ => {
            debug!(%key_bits, "invalid stored symmetric key size");
            Err(Error::corrupted_store())
        }
    }
}

fn cipher_mode_to_db(mode: CipherMode) -> &'static str {
    match mode {
        CipherMode::Gcm => "gcm",
    }
}

fn cipher_mode_from_db(mode: &str) -> Result<CipherMode> {
    match mode {
        "gcm" => Ok(CipherMode::Gcm),
        _ => {
            debug!(%mode, "invalid stored symmetric cipher mode");
            Err(Error::corrupted_store())
        }
    }
}

fn pcr_slots_from_mask(mask: u32) -> Result<Vec<PcrSlot>> {
    if mask == 0 || mask > PcrSlot::MASK {
        debug!(%mask, "stored PCR slot mask is out of range");
        return Err(Error::corrupted_store());
    }

    let mut slots = Vec::new();
    for slot in 0 ..=PcrSlot::MAX {
        if mask & (1 << slot) != 0 {
            slots.push(PcrSlot::try_from(slot).map_err(Error::corrupted_store_with_source)?);
        }
    }

    Ok(slots)
}

fn unmarshal_policy_or_digests(
    input: &[u8],
    branch_count: usize,
) -> Result<TpmlDigest> {
    let mut input = input;

    if branch_count < MIN_POLICY_OR_BRANCHES {
        debug!(branch_count, "stored PolicyOR branch count is invalid");
        return Err(Error::corrupted_store());
    }

    let branch_digests = TpmlDigest::unmarshal(&mut input)?;
    if branch_digests.len() < MIN_POLICY_OR_BRANCHES {
        debug!(digest_count = branch_digests.len(), "stored PolicyOR digest count is invalid");
        return Err(Error::corrupted_store());
    }
    ensure_consumed(input)?;

    Ok(branch_digests)
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
