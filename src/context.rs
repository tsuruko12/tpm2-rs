use rand::{RngCore, rngs::OsRng};
use tracing::debug;
use zeroize::Zeroizing;

use crate::{
    generate_key_id, 
    backend::BackendContext, 
    cache::{AuthorizationTarget, Cache, TemporaryKey}, 
    db::{KeyMeta, MetadataStore}, error::{Error, Result}, 
    hierarchy::Hierarchy, 
    public::KeyTemplate, 
    types::{
        Authorization, CreatedObject, HandleResource, Key, KeyData, KeyId, LoadedHandle, Policy, 
        PolicyData, SymmetricKeyBits, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, 
        TpmiDhPersistent
    }
};

pub struct Context {
    backend: BackendContext,
    store: MetadataStore,
    cache: Cache,
}

enum ParentKeyData {
    Persistent {
        handle: TpmiDhPersistent,
        obj_name: Tpm2bName,
        policy: Option<PolicyData>,
    },
    Primary {
        hierarchy: Hierarchy,
        public: Tpm2bPublic,
        obj_name: Tpm2bName,
        policy: Option<PolicyData>,
    },
    Child {
        public: Tpm2bPublic,
        private: Tpm2bPrivate,
        obj_name: Tpm2bName,
        policy: Option<PolicyData>,
        parent: Option<KeyId>,
    },
}

impl Context {
    pub fn connect() -> Result<Self> {
        Ok(Self {
            backend: BackendContext::create_context()?,
            store: MetadataStore::new()?,
            cache: Cache::default(),
        })
    }

    #[cfg(target_os = "linux")]
    pub fn connect_from_env() -> Result<Self> {
        Ok(Self {
            backend: BackendContext::create_context_from_tcti_env()?,
            store: MetadataStore::new()?,
            cache: Cache::default(),
        })
    }

    pub fn create(
        &mut self,
        template: KeyTemplate,
        key_name: Option<&str>,
        auth_value: Option<&[u8]>,
        policy: Option<Policy>,
        parent: Option<&Key>,
    ) -> Result<Key> {
        if let Some(name) = key_name {
            self.store.ensure_unique_key_name(name)?;
        }

        let policy = policy.map(|policy| PolicyData::from(policy));
        let auth_policy = match &policy {
            Some(policy) => self.backend.compute_auth_policy(policy)?,
            None => Tpm2bDigest::default(),
        };
        let in_public = Tpm2bPublic::from_template(&template, auth_policy);
        let auth = match auth_value {
            Some(value) => Tpm2bAuth::normalize_sha256(value),
            None => Tpm2bAuth::default(),
        };
        let session_salt_key = self.load_session_salt_key()?;

        let created_obj = if template.is_storage_parent() {
            let owner_authorization = self.hierarchy_authorization(Hierarchy::Storage)?;

            self.backend.create_srk(
                in_public, 
                auth, 
                &owner_authorization, 
                session_salt_key.handle()
            )?
        } else {
            self.backend.create_child_key(
                in_public, 
                auth, 
                self.load_parent(parent)?, 
                session_salt_key.handle()
            )?
        };

        match key_name {
            Some(name) => Ok(Key::new(KeyId::Stored(name))),
            None => {
                let temporary_key = TemporaryKey {

                }
                Ok(Key::new(self.register_temporary_key(key)))
            }
        }
    }

    fn store_key_meta(&mut self, created_obj: CreatedObject, template: &KeyTemplate) -> Result<()> {
        let key_meta = match template {
            KeyTemplate::Symmetric(sym_template) => {
                let sym_key = generate_sym_key(sym_template.key_bits())?;
                
            }
        }
    }

    fn register_temporary_key(&mut self, key: TemporaryKey) -> Result<KeyId> {
        let id = loop {
            let id = generate_key_id()?;
            if !self.cache.contains_temporary_key(id.as_str()) {
                break KeyId::Temporary(id);
            }
        };

        self.cache.add_temporary_key(id.as_str().into(), key);

        Ok(id)
    } 

    fn load_parent(&mut self, parent: Option<&Key>) -> Result<LoadedHandle> {
        let Some(parent) = parent else {
            return self.load_internal_srk();
        };

        self.load_parent_by_id(parent.id(), &mut Vec::new())
    }

    fn load_parent_by_id(
        &mut self,
        key_id: &KeyId,
        ancestors: &mut Vec<KeyId>,
    ) -> Result<LoadedHandle> {
        if ancestors.contains(key_id) {
            debug!(?key_id, "key parent chain contains a cycle");
            return Err(Error::invalid_state("invalid key parent chain"));
        }

        ancestors.push(key_id.clone());

        let result = (|| match self.load_parent_data(key_id)? {
            ParentKeyData::Persistent {
                handle,
                obj_name,
                policy,
            } => {
                let handle = self.backend.resolve_persistent_handle(handle, &obj_name)?;
                Ok(LoadedHandle::persistent(
                    handle.into(),
                    obj_name,
                    self.key_authorization(key_id, policy),
                ))
            }
            ParentKeyData::Primary {
                hierarchy,
                public,
                obj_name,
                policy,
            } => {
                let authorization = self.key_authorization(key_id, policy);
                let hierarchy_authorization = self.hierarchy_authorization(hierarchy)?;
                let session_salt_key = self.load_session_salt_key()?;

                self.backend.load_primary_key(
                    hierarchy.into(),
                    public,
                    authorization,
                    &hierarchy_authorization,
                    session_salt_key.handle(),
                    &obj_name,
                )
            }
            ParentKeyData::Child {
                public,
                private,
                obj_name,
                policy,
                parent,
            } => {
                let parent = match parent {
                    Some(parent) => self.load_parent_by_id(&parent, ancestors)?,
                    None => self.load_internal_srk()?,
                };
                let session_salt_key = self.load_session_salt_key()?;

                self.backend.load_temporary_key(
                    private,
                    public,
                    self.key_authorization(key_id, policy),
                    parent,
                    session_salt_key.handle(),
                    &obj_name,
                )
            }
        })();

        ancestors.pop();

        result
    }

    fn load_parent_data(&self, key_id: &KeyId) -> Result<ParentKeyData> {
        match key_id {
            KeyId::Stored(key_name) => self.load_stored_parent_data(key_name),
            KeyId::Temporary(id) => self.load_temporary_parent_data(id),
        }
    }

    fn load_stored_parent_data(&self, key_name: &str) -> Result<ParentKeyData> {
        let KeyMeta::Tpm {
            hierarchy,
            tpm_key_meta,
            persistent_handle,
            parent_name,
            ..
        } = self.store.load_key(key_name)?
        else {
            return Err(Error::invalid_state("unexpected symmetric key as TPM parent"));
        };      
        let crate::db::TpmKeyMeta {
            public,
            private,
            obj_name,
            policy,
        } = tpm_key_meta;

        match persistent_handle {
            Some(handle) => Ok(ParentKeyData::Persistent {
                handle,
                obj_name,
                policy,
            }),
            None => match hierarchy {
                Some(hierarchy) => Ok(ParentKeyData::Primary {
                    hierarchy,
                    public,
                    obj_name,
                    policy,
                }),
                None => {
                    let private = private.ok_or_else(|| {
                        debug!(%key_name, "stored child key private data is missing");
                        Error::corrupted_store()
                    })?;

                    Ok(ParentKeyData::Child {
                        public,
                        private,
                        obj_name,
                        policy,
                        parent: parent_name.map(KeyId::Stored),
                    })
                }
            },
        }
    }

    fn load_temporary_parent_data(&self, id: &str) -> Result<ParentKeyData> {
        let temporary_key = self
            .cache
            .temporary_key(id)
            .ok_or_else(|| Error::invalid_state("temporary key is not registered"))?;
        let policy = temporary_key.policy.clone();

        match &temporary_key.data {
            KeyData::Srk(HandleResource::Persistent {
                handle, obj_name, ..
            })
            | KeyData::Rsa(HandleResource::Persistent {
                handle, obj_name, ..
            })
            | KeyData::Ecc(HandleResource::Persistent {
                handle, obj_name, ..
            }) => Ok(ParentKeyData::Persistent {
                handle: *handle,
                obj_name: obj_name.clone(),
                policy,
            }),
            KeyData::Srk(HandleResource::Transient {
                public, obj_name, ..
            }) => Ok(ParentKeyData::Primary {
                hierarchy: Hierarchy::Storage,
                public: public.clone(),
                obj_name: obj_name.clone(),
                policy,
            }),
            KeyData::Rsa(HandleResource::Transient {
                public,
                private,
                obj_name,
            })
            | KeyData::Ecc(HandleResource::Transient {
                public,
                private,
                obj_name,
            }) => Ok(ParentKeyData::Child {
                public: public.clone(),
                private: Tpm2bPrivate::try_from(private.as_bytes())?,
                obj_name: obj_name.clone(),
                policy,
                parent: temporary_key.parent.clone(),
            }),
            KeyData::Symmetric { .. } => {
                Err(Error::invalid_state("unexpected symmetric key as TPM parent"))
            }
        }
    }

    fn key_authorization(&self, key_id: &KeyId, policy: Option<PolicyData>) -> Authorization {
        Authorization::new(
            self.cache
                .auth(&AuthorizationTarget::Key(key_id.clone())),
            policy,
        )
    }

    fn hierarchy_authorization(&self, hierarchy: Hierarchy) -> Result<Authorization> {
        Ok(Authorization::new(
            self.cache
                .auth(&AuthorizationTarget::Hierarchy(hierarchy)),
            self.store.load_hierarchy_policy(hierarchy)?,
        ))
    }

    pub fn provision(&mut self) -> Result<()> {
        self.store.ensure_uninitialized()?;

        let owner_authorization = Authorization::default();
        let key_meta = self.backend.create_internal_keys(&owner_authorization)?;

        self.store.init(&key_meta).inspect_err(|_| {
            self.backend
                .evict_persistent_handles(&owner_authorization, &key_meta, None)
        })
    }

    pub fn get_random(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        if num_bytes == 0 {
            return Ok(Vec::new());
        }

        let sesssion_salt_key = self.load_session_salt_key()?;
        let mut buf = Vec::new();

        buf.try_reserve_exact(num_bytes)
            .map_err(|_| Error::resource_exhausted("failed to allocate random output buffer"))?;

        while buf.len() < num_bytes {
            let remaining = num_bytes - buf.len();
            let chunk_size = remaining.min(u16::MAX as usize) as u16;

            let chunk = self.backend.get_random(chunk_size, sesssion_salt_key.handle())?;

            if chunk.is_empty() {
                debug!("TPM returned no random bytes");
                return Err(Error::InvalidData);
            }

            if chunk.len() > chunk_size as usize {
                debug!("TPM returned more random bytes than requested");
                return Err(Error::InvalidData);
            }

            buf.extend_from_slice(&chunk);
        }

        buf.truncate(num_bytes);

        Ok(buf)
    }

    fn load_internal_srk(&mut self) -> Result<LoadedHandle> {
        let key_meta = self.store.load_internal_srk()?;
        self.backend.resolve_internal_key(key_meta)
    }

    fn load_session_salt_key(&mut self) -> Result<LoadedHandle> {
        let key_meta = self.store.load_session_salt_key()?;
        self.backend.resolve_internal_key(key_meta)
    }
}

fn generate_sym_key(key_bits: SymmetricKeyBits) -> Result<Zeroizing<Vec<u8>>> {
    let key_len = match key_bits {
        SymmetricKeyBits::Bits128 => 16,
        SymmetricKeyBits::Bits256 => 32,
    };

    let mut key = Zeroizing::new(vec![0u8; key_len]);
    OsRng
        .try_fill_bytes(key.as_mut_slice())
        .map_err(Error::random_generation)?;

    Ok(key)
}

