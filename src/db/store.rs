use std::{
    fs,
    path::{Path, PathBuf},
};

use directories::ProjectDirs;
use rusqlite::{Connection, OptionalExtension};
use tracing::debug;

use crate::{
    Error, Result, generate_random_bytes,
    hierarchy::Hierarchy,
    policy::{PcrSelection, PcrSlot, PolicyCommand},
    types::{
        PolicyData, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmUnmarshal, TpmiDhPersistent,
        TpmlDigest, TpmtPublic, algorithm::HashAlgorithm, read_u32,
    },
};

const DB_FILE: &str = "store.db"; // will change later
const STORE_PATH_ENV: &str = "TPM_STORE_PATH"; // will change later
const PROJECT_APPLICATION: &str = "tpm-tool"; // will change later
const FILE_VERSION: u8 = 1;

const HANDLE_SRK: &str = "srk";
const HANDLE_SESSION_SALT_KEY: &str = "session_salt_key";
const HANDLE_SHARED_WRAPPING_KEY: &str = "shared_wrapping_key";
const MIN_POLICY_OR_BRANCHES: usize = 2;

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
    id                TEXT PRIMARY KEY,
    kind              TEXT NOT NULL CHECK (kind IN ('primary', 'child')),
    hierarchy         TEXT CHECK (
        hierarchy IN ('owner', 'endorsement', 'platform')
    ),
    public            BLOB NOT NULL,
    object_name          BLOB NOT NULL,
    private           BLOB NOT NULL,
    persistent_handle INTEGER UNIQUE,
    policy_id         TEXT REFERENCES policies(id) ON DELETE RESTRICT,
    parent_id         TEXT REFERENCES tpm_keys(id) ON DELETE RESTRICT,

    CHECK (
        (kind = 'primary' AND hierarchy IS NOT NULL AND parent_id IS NULL) OR
        (kind = 'child' AND hierarchy IS NULL)
    )

    FOREIGN KEY (id) REFERENCES user_keys(id) ON DELETE CASCADE,
);

CREATE TABLE wrapping_keys (
    id          TEXT PRIMARY KEY,
    public      BLOB NOT NULL,
    private     BLOB NOT NULL,
    object_name BLOB NOT NULL
);

CREATE TABLE symmetric_keys (
    id              TEXT PRIMARY KEY,
    block_cipher    TEXT NOT NULL,
    key_bits        INTEGER NOT NULL,
    mode            TEXT NOT NULL,
    wrapped_key     BLOB NOT NULL,
    wrapping_key_id TEXT REFERENCES wrapping_keys(id),

    FOREIGN KEY (id) REFERENCES user_keys(id) ON DELETE CASCADE
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
        name: String,
        hierarchy: Option<Hierarchy>,
        tpm_key_meta: TpmKeyMeta,
        persistent_handle: Option<TpmiDhPersistent>,
        parent_name: Option<String>,
    },
    Symmetric {
        name: String,
        wrapped_key: Vec<u8>,
        wrapping_key: WrappingKeyMeta,
    },
}

impl KeyMeta {
    pub(crate) fn owner_primary(
        name: String,
        tpm_key_meta: TpmKeyMeta,
        persistent_handle: Option<TpmiDhPersistent>,
    ) -> Self {
        Self::Tpm {
            name,
            hierarchy: Some(Hierarchy::Storage),
            tpm_key_meta,
            persistent_handle,
            parent_name: None,
        }
    }

    pub(crate) fn child(
        name: String,
        tpm_key_meta: TpmKeyMeta,
        persistent_handle: Option<TpmiDhPersistent>,
        parent_name: Option<String>,
    ) -> Self {
        Self::Tpm {
            name,
            hierarchy: None,
            tpm_key_meta,
            persistent_handle,
            parent_name,
        }
    }

    pub(crate) fn symmetric(
        name: String,
        wrapped_key: Vec<u8>,
        wrapping_key: WrappingKeyMeta,
    ) -> Self {
        Self::Symmetric {
            name,
            wrapped_key,
            wrapping_key,
        }
    }
}

#[derive(Debug)]
enum WrappingKeyMeta {
    Shared,
    Dedicated(TpmKeyMeta),
}

#[derive(Debug)]
pub(crate) struct TpmKeyMeta {
    pub(crate) public: Tpm2bPublic,
    pub(crate) private: Tpm2bPrivate,
    pub(crate) obj_name: Tpm2bName,
    pub(crate) policy: Option<PolicyData>,
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
            tx.execute(stmt, (kind, meta.handle.raw(), meta.obj_name.as_bytes()))?;
        }

        tx.commit()?;

        Ok(())
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
                tpm_keys.parent_id,
                parent_user_keys.key_name
            FROM user_keys
            JOIN tpm_keys ON tpm_keys.id = user_keys.id
            LEFT JOIN user_keys AS parent_user_keys ON parent_user_keys.id = tpm_keys.parent_id
            WHERE user_keys.key_name = ?
        "#;

        let (
            name,
            user_key_kind,
            tpm_key_kind,
            hierarchy,
            public,
            private,
            object_name,
            persistent_handle,
            policy_id,
            parent_id,
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
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
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
            parent_id.as_deref(),
            parent_name.as_deref(),
        ) {
            ("primary", Some(hierarchy), None, None) => Some(Hierarchy::from_db(hierarchy)?),
            ("child", None, None, None) | ("child", None, Some(_), Some(_)) => None,
            _ => {
                debug!(
                    key_name,
                    ?tpm_key_kind,
                    ?hierarchy,
                    ?parent_id,
                    ?parent_name,
                    "TPM key metadata is inconsistent"
                );
                return Err(Error::corrupted_store());
            }
        };

        let persistent_handle = persistent_handle
            .map(|value| {
                let value = u32::try_from(value).map_err(Error::corrupted_store_with_source)?;
                TpmiDhPersistent::try_from(value).map_err(Error::corrupted_store_with_source)
            })
            .transpose()?;
        let tpm_key_meta =
            self.load_tpm_key_meta(public, private, object_name, policy_id.as_deref())?;

        Ok(KeyMeta::Tpm {
            name,
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
                symmetric_keys.wrapped_key,
                symmetric_keys.wrapping_key_id,
                wrapping_keys.public,
                wrapping_keys.private,
                wrapping_keys.object_name
            FROM user_keys
            LEFT JOIN symmetric_keys ON symmetric_keys.id = user_keys.id
            LEFT JOIN wrapping_keys ON wrapping_keys.id = symmetric_keys.wrapping_key_id
            WHERE user_keys.key_name = ?
        "#;

        let (
            name,
            user_key_kind,
            wrapped_key,
            wrapping_key_id,
            wrapping_public,
            wrapping_private,
            wrapping_object_name,
        ) = self
            .conn
            .query_row(stmt, [key_name], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                ))
            })
            .optional()?
            .ok_or(Error::KeyNotFound)?;

        if user_key_kind != "symmetric" {
            return Err(Error::invalid_key("requested key is not symmetric"));
        }

        let Some(wrapped_key) = wrapped_key else {
            debug!(%key_name, "symmetric key data is missing");
            return Err(Error::corrupted_store());
        };

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
                    private,
                    object_name,
                    None,
                )?)
            }
            None => WrappingKeyMeta::Shared,
        };

        Ok(KeyMeta::symmetric(name, wrapped_key, wrapping_key))
    }

    fn load_tpm_key_meta(
        &self,
        public: Vec<u8>,
        private: Vec<u8>,
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

        let private = private.try_into().map_err(|_| {
            debug!("invalid stored private data");
            Error::corrupted_store()
        })?;
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
                    WHERE id = ?
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
                    debug!(%policy_id, "stored digest lists is missing");
                    Error::corrupted_store()
                })?;
                let branches = self.load_policy_children(policy_id, ancestors)?;
                let branch_digests =
                    unmarshal_policy_branch_digest_lists(bytes, branches.len()).map_err(|_| {
                        debug!(%policy_id, "stored digest lists are invalid");
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
                    WHERE parent_id = ?
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
                Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?))
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

fn unmarshal_policy_branch_digest_lists(
    input: &[u8],
    branch_count: usize,
) -> Result<Vec<TpmlDigest>> {
    let mut input = input;

    if !(MIN_POLICY_OR_BRANCHES..=TpmlDigest::MAX_COUNT).contains(&branch_count) {
        debug!(branch_count, "stored PolicyOR branch count is invalid");
        return Err(Error::corrupted_store());
    }

    let item_count = read_u32(&mut input)? as usize;
    if item_count != branch_count {
        debug!(
            digest_count = item_count,
            branch_count,
            "stored PolicyOR digest list count does not match branch count"
        );
        return Err(Error::corrupted_store());
    }

    let mut digest_lists = Vec::with_capacity(item_count);

    for _ in 0..item_count {
        let digest_list = TpmlDigest::unmarshal(&mut input)?;
        if digest_list.len() != branch_count {
            debug!(
                digest_count = digest_list.len(),
                branch_count,
                "stored PolicyOR digest count does not match branch count"
            );
            return Err(Error::corrupted_store());
        }

        digest_lists.push(digest_list);
    }

    if !input.is_empty() {
        debug!(
            remaining = input.len(),
            "stored PolicyOR digest lists have trailing bytes"
        );
        return Err(Error::corrupted_store());
    }

    Ok(digest_lists)
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
