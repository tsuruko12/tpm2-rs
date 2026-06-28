use tss_esapi::{
    structures::{Private, Public},
    traits::{Marshall, UnMarshall},
};

use crate::{
    error::{Error, Result},
    types::{
        Authorization, BlockCipher, ChildKeyLoadSource as RuntimeChildKeyLoadSource, CipherMode,
        Hierarchy, Key, KeyData, Policy, PrimaryKeyLoadSource as RuntimePrimaryKeyLoadSource,
        SymmetricKeyBits, WrappingKeySource,
    },
};

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

fn hierarchy_to_str(hierarchy: Hierarchy) -> &'static str {
    hierarchy.as_str()
}

fn encode_public(public: &Public) -> Result<Vec<u8>> {
    public.marshall().map_err(|_| Error::corrupted_store())
}

fn decode_public(public: Vec<u8>) -> Result<Public> {
    Public::unmarshall(&public).map_err(|_| Error::corrupted_store())
}

fn decode_private(private: Vec<u8>) -> Result<Private> {
    Private::try_from(private).map_err(|_| Error::corrupted_store())
}

fn block_cipher_to_str(block_cipher: BlockCipher) -> &'static str {
    match block_cipher {
        BlockCipher::Aes => "aes",
        BlockCipher::Camellia => "camellia",
    }
}

fn parse_block_cipher(block_cipher: &str) -> Result<BlockCipher> {
    match block_cipher {
        "aes" => Ok(BlockCipher::Aes),
        "camellia" => Ok(BlockCipher::Camellia),
        _ => Err(Error::corrupted_store()),
    }
}

fn symmetric_key_bits_to_u16(key_bits: SymmetricKeyBits) -> u16 {
    match key_bits {
        SymmetricKeyBits::Bits128 => 128,
        SymmetricKeyBits::Bits256 => 256,
    }
}

fn parse_symmetric_key_bits(key_bits: u16) -> Result<SymmetricKeyBits> {
    match key_bits {
        128 => Ok(SymmetricKeyBits::Bits128),
        256 => Ok(SymmetricKeyBits::Bits256),
        _ => Err(Error::corrupted_store()),
    }
}

fn cipher_mode_to_str(mode: CipherMode) -> &'static str {
    match mode {
        CipherMode::Gcm => "gcm",
        _ => unreachable!(""),
    }
}

fn parse_cipher_mode(mode: &str) -> Result<CipherMode> {
    match mode {
        "gcm" => Ok(CipherMode::Gcm),
        _ => Err(Error::corrupted_store()),
    }
}

fn parse_policy(policy: Option<String>) -> Result<Option<Policy>> {
    policy
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|_| Error::corrupted_store())
}

#[derive(Debug)]
enum PrimaryKeyLoadSource {
    Recreate,
    PersistentHandle { handle: u32 },
}

impl PrimaryKeyLoadSource {
    fn decode(self) -> RuntimePrimaryKeyLoadSource {
        match self {
            Self::Recreate => RuntimePrimaryKeyLoadSource::Recreate,
            Self::PersistentHandle { handle } => {
                RuntimePrimaryKeyLoadSource::PersistentHandle { handle }
            }
        }
    }
}

#[derive(Debug)]
enum ChildKeyLoadSource {
    StoredBlob,
    PersistentHandle { handle: u32 },
}

impl ChildKeyLoadSource {
    fn decode(self) -> RuntimeChildKeyLoadSource {
        match self {
            Self::StoredBlob => RuntimeChildKeyLoadSource::StoredBlob,
            Self::PersistentHandle { handle } => {
                RuntimeChildKeyLoadSource::PersistentHandle { handle }
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct PersistentHandle {
    pub(crate) handle: u32,
    pub(crate) name: Vec<u8>,
}

impl PersistentHandle {
    pub(crate) fn new(handle: u32, name: &[u8]) -> Self {
        Self {
            handle,
            name: name.to_vec(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct PrimaryKeyMeta {
    id: String,
    hierarchy: String,
    public: Vec<u8>,
    name: Vec<u8>,
    source: PrimaryKeyLoadSource,
    policy: Option<String>,
}

impl PrimaryKeyMeta {
    pub(crate) fn new(
        id: impl Into<String>,
        hierarchy: Hierarchy,
        public: &Public,
        name: &[u8],
        policy: Option<&Policy>,
    ) -> Result<Self> {
        Ok(Self {
            id: id.into(),
            hierarchy: hierarchy_to_str(hierarchy).to_string(),
            public: encode_public(public)?,
            name: name.to_vec(),
            source: PrimaryKeyLoadSource::Recreate,
            policy: policy.map(ToString::to_string),
        })
    }

    fn into_key(self, cache_id: String) -> Result<Key> {
        let data = KeyData::Primary {
            public: decode_public(self.public)?,
            expected_name: self.name,
            source: self.source.decode(),
        };
        let authorization = Authorization::new(None, parse_policy(self.policy)?);

        Ok(Key::new(data, authorization, cache_id, Some(&self.id)))
    }
}

#[derive(Debug)]
pub(crate) struct ChildKeyMeta {
    id: String,
    public: Vec<u8>,
    private: Vec<u8>,
    name: Vec<u8>,
    load_source: ChildKeyLoadSource,
    policy: Option<String>,
    parent_id: Option<String>,
}

impl ChildKeyMeta {
    pub(crate) fn new(
        id: impl Into<String>,
        public: &Public,
        private: &Private,
        name: &[u8],
        policy: Option<&Policy>,
        parent_id: Option<&str>,
    ) -> Result<Self> {
        Ok(Self {
            id: id.into(),
            public: encode_public(public)?,
            private: private.value().to_vec(),
            name: name.to_vec(),
            load_source: ChildKeyLoadSource::StoredBlob,
            policy: policy.map(ToString::to_string),
            parent_id: parent_id.map(str::to_owned),
        })
    }

    fn into_key(self, cache_id: String) -> Result<Key> {
        let data = KeyData::Child {
            public: decode_public(self.public)?,
            private: decode_private(self.private)?,
            expected_name: self.name,
            source: self.load_source.decode(),
            parent_id: self.parent_id,
        };
        let authorization = Authorization::new(None, parse_policy(self.policy)?);

        Ok(Key::new(data, authorization, cache_id, Some(&self.id)))
    }
}

#[derive(Debug)]
pub(crate) struct SymmetricKeyMeta {
    id: String,
    block_cipher: String,
    key_bits: u16,
    mode: String,
    wrapped_key: Vec<u8>,
    wrapping_key_id: Option<String>,
}

impl SymmetricKeyMeta {
    pub(crate) fn new(
        id: impl Into<String>,
        block_cipher: BlockCipher,
        key_bits: SymmetricKeyBits,
        mode: CipherMode,
        wrapped_key: impl AsRef<[u8]>,
        wrapping_key_id: Option<&str>,
    ) -> Self {
        Self {
            id: id.into(),
            block_cipher: block_cipher_to_str(block_cipher).to_string(),
            key_bits: symmetric_key_bits_to_u16(key_bits),
            mode: cipher_mode_to_str(mode).to_string(),
            wrapped_key: wrapped_key.as_ref().to_vec(),
            wrapping_key_id: wrapping_key_id.map(str::to_owned),
        }
    }

    fn into_key(
        self,
        authorization: Authorization,
        wrapping_key_source: WrappingKeySource,
        cache_id: String,
    ) -> Result<Key> {
        let data = KeyData::symmetric_key(
            parse_block_cipher(&self.block_cipher)?,
            parse_symmetric_key_bits(self.key_bits)?,
            parse_cipher_mode(&self.mode)?,
            self.wrapped_key,
            wrapping_key_source,
        );

        Ok(Key::new(data, authorization, cache_id, Some(&self.id)))
    }
}

#[derive(Debug)]
pub(crate) struct InternalKeyMeta {
    id: String,
    public: Vec<u8>,
    private: Vec<u8>,
    policy: Option<String>,
}

impl InternalKeyMeta {
    pub(crate) fn new(
        id: impl Into<String>,
        public: &Public,
        private: &Private,
        policy: Option<&Policy>,
    ) -> Result<Self> {
        Ok(Self {
            id: id.into(),
            public: encode_public(public)?,
            private: private.value().to_vec(),
            policy: policy.map(ToString::to_string),
        })
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn decode(self) -> Result<(Public, Private)> {
        Ok((decode_public(self.public)?, decode_private(self.private)?))
    }

    fn authorization(&self) -> Result<Authorization> {
        Ok(Authorization::new(None, parse_policy(self.policy.clone())?))
    }
}

enum KeyMeta {
    Primary(PrimaryKeyMeta),
    Child(ChildKeyMeta),
    Symmetric(SymmetricKeyMeta),
}

impl KeyMeta {
    fn id(&self) -> &str {
        match self {
            Self::Primary(meta) => &meta.id,
            Self::Child(meta) => &meta.id,
            Self::Symmetric(meta) => &meta.id,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Primary(_) => "primary",
            Self::Child(_) => "child",
            Self::Symmetric(_) => "symmetric",
        }
    }
}

impl From<PrimaryKeyMeta> for KeyMeta {
    fn from(value: PrimaryKeyMeta) -> Self {
        Self::Primary(value)
    }
}

impl From<ChildKeyMeta> for KeyMeta {
    fn from(value: ChildKeyMeta) -> Self {
        Self::Child(value)
    }
}

impl From<SymmetricKeyMeta> for KeyMeta {
    fn from(value: SymmetricKeyMeta) -> Self {
        Self::Symmetric(value)
    }
}
