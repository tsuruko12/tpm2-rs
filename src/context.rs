use tracing::debug;

use crate::{
    backend::BackendContext, 
    cache::{AuthorizationTarget, Cache, TemporaryKey}, 
    db::{KeyMeta, MetadataStore, TpmKeyMeta, WrappingKeyMeta}, error::{Error, Result}, 
    generate_key_id, hierarchy::Hierarchy, public::KeyTemplate, 
    types::{
        Authorization, BackendObjectHandle, CreatedKeyData, HandleResource, Key, KeyData, KeyId, 
        LoadedHandle, Policy, PolicyData, Tpm2bAuth, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, 
        Tpm2bPublicKeyRsa, TpmiDhPersistent
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

enum CreatedKey {
    Tpm(CreatedKeyData),
    Symmetric {
        key: Tpm2bPublicKeyRsa,
        wrapping_key: Option<CreatedKeyData>,
    },
}

impl CreatedKey {
    fn into_temporary_key(
        self,
        template: &KeyTemplate,
        policy: Option<PolicyData>,
        parent: Option<KeyId>,
    ) -> Result<TemporaryKey> {
        match self {
            Self::Tpm(key_data) => {
                let handle_resource = HandleResource::Transient {
                    public: key_data.public,
                    private: key_data.private,
                    obj_name: key_data.name,
                };
                let data = match template {
                    KeyTemplate::Ecc(_) => KeyData::Ecc(handle_resource),
                    KeyTemplate::Rsa(_) if template.is_storage_parent() => {
                        KeyData::Srk(handle_resource)
                    }
                    KeyTemplate::Rsa(_) => KeyData::Rsa(handle_resource),
                    KeyTemplate::Symmetric(_) => {
                        return Err(Error::invalid_state(
                            "created key type does not match its template",
                        ));
                    }
                };

                Ok(TemporaryKey {
                    data,
                    policy,
                    parent,
                })
            }
            Self::Symmetric {
                key: wrapped_key,
                wrapping_key,
            } => {
                let KeyTemplate::Symmetric(template) = template else {
                    return Err(Error::invalid_state(
                        "created key type does not match its template",
                    ));
                };
                let wrapping_key = wrapping_key.map(|key| HandleResource::Transient {
                    public: key.public,
                    private: key.private,
                    obj_name: key.name,
                });

                Ok(TemporaryKey {
                    data: KeyData::Symmetric {
                        template: *template,
                        wrapping_key,
                        wrapped_key,
                    },
                    policy,
                    parent,
                })
            }
        }
    }

    fn into_key_meta(
        self,
        template: &KeyTemplate,
        key_name: String,
        policy: Option<PolicyData>,
        parent_name: Option<String>,
    ) -> Result<KeyMeta> {
        match (template, self) {
            (KeyTemplate::Rsa(_), Self::Tpm(key_data)) => {
                let tpm_key_meta = TpmKeyMeta {
                    public: key_data.public,
                    private: key_data.private,
                    obj_name: key_data.name,
                    policy,
                };

                if template.is_storage_parent() {
                    Ok(KeyMeta::owner_primary(key_name, tpm_key_meta, None))
                } else {
                    Ok(KeyMeta::child(key_name, tpm_key_meta, None, parent_name))
                }
            }
            (KeyTemplate::Ecc(_), Self::Tpm(key_data)) => Ok(KeyMeta::child(
                key_name,
                TpmKeyMeta {
                    public: key_data.public,
                    private: key_data.private,
                    obj_name: key_data.name,
                    policy,
                },
                None,
                parent_name,
            )),
            (
                KeyTemplate::Symmetric(template),
                Self::Symmetric { key, wrapping_key },
            ) => {
                let wrapping_key = match wrapping_key {
                    Some(key_data) => WrappingKeyMeta::Dedicated(TpmKeyMeta {
                        public: key_data.public,
                        private: key_data.private,
                        obj_name: key_data.name,
                        policy,
                    }),
                    None => {
                        if policy.is_some() {
                            return Err(Error::invalid_state(
                                "symmetric key policy requires a dedicated wrapping key",
                            ));
                        }

                        WrappingKeyMeta::Shared
                    }
                };

                Ok(KeyMeta::symmetric(
                    key_name,
                    template.block_cipher(),
                    template.key_bits(),
                    template.mode(),
                    key.as_bytes().to_vec(),
                    wrapping_key,
                ))
            }
            _ => Err(Error::invalid_state(
                "created key type does not match its template",
            )),
        }
    }
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

    pub fn create_key(
        &mut self,
        template: KeyTemplate,
        key_name: Option<&str>,
        auth_value: Option<&[u8]>,
        policy: Option<Policy>,
        parent: Option<&Key>,
    ) -> Result<Key> {
        self.validate_key_creation(&template, key_name, parent)?;

        let policy = policy.map(|policy| PolicyData::from(policy));
        let auth = auth_value
            .map(Tpm2bAuth::normalize_sha256)
            .unwrap_or_default();
        let parent_id = parent.map(|key| key.id().clone());

        let created_key = if template.is_storage_parent() {
            self.create_key_from_template(
                &template,
                auth.clone(),
                policy.clone(),
                None,
            )?
        } else {
            let wrapping_parent = if matches!(&template, KeyTemplate::Symmetric(_)) {
                self.load_shared_wrapping_handle()?
            } else {
                self.load_parent(parent)?
            };

            let result = self.create_key_from_template(
                &template,
                auth.clone(),
                policy.clone(),
                Some(&wrapping_parent),
            );

            match result {
                Ok(created_key) => {
                    self.backend.release_handle(wrapping_parent.handle())?;
                    created_key
                },
                Err(e) => {
                    let _ = self.backend.release_handle(wrapping_parent.handle());
                    return Err(e);
                }
            }
        };
        let key_id = self.register_created_key(
            &template,
            created_key,
            key_name,
            policy,
            parent_id,
        )?;

        self.cache.set_auth(AuthorizationTarget::Key(key_id.clone()), auth);

        Ok(Key::new(key_id))
    }

    fn validate_key_creation(
        &self, 
        template: &KeyTemplate, 
        key_name: Option<&str>,
        parent: Option<&Key>
    ) -> Result<()> {
        if let Some(name) = key_name {
            self.store.ensure_unique_key_name(name)?;

            if matches!(parent.map(|key| key.id()), Some(KeyId::Temporary(_))) {
                return Err(Error::invalid_param(
                    "parent must be a stored key for a named key",
                ));
            }
        }

        if template.is_storage_parent() && parent.is_some() {
            return Err(Error::invalid_param("storage root key cannot have a parent"));
        }
        if matches!(&template, KeyTemplate::Symmetric(_)) && parent.is_some() {
            return Err(Error::invalid_param(
                "parent cannot be specified for a symmetric key",
            ));
        }

        Ok(())
    }

    fn create_key_from_template(
        &mut self,
        template: &KeyTemplate,
        auth: Tpm2bAuth,
        policy: Option<PolicyData>,
        parent: Option<&LoadedHandle>,
    ) -> Result<CreatedKey> {
        let Some(parent) = parent else {
            let owner_authorization = self.hierarchy_authorization(Hierarchy::Storage)?;
            let session_salt_handle = self.load_session_salt_handle()?;

            return self
                .backend
                .create_srk_from_template(
                    template,
                    auth,
                    policy.as_ref(),
                    &owner_authorization,
                    session_salt_handle,
                )
                .map(CreatedKey::Tpm);
        };

        let session_salt_handle = self.load_session_salt_handle()?;

        match template {
            KeyTemplate::Ecc(_) | KeyTemplate::Rsa(_) => self
                .backend
                .create_child_key_from_template(
                    template,
                    auth,
                    policy.as_ref(),
                    parent,
                    session_salt_handle,
                )
                .map(CreatedKey::Tpm),
            KeyTemplate::Symmetric(_) => {
                let authorization = if auth.is_empty() && policy.is_none() {
                    None
                } else {
                    Some(Authorization::new(auth, policy))
                };

                self
                    .backend
                    .create_sym_key_from_template(
                        template,
                        authorization.as_ref(),
                        parent,
                        session_salt_handle,
                    )
                    .map(|(key, wrapping_key)| {
                        CreatedKey::Symmetric { key, wrapping_key }
                    })
            }
        }
    }

    fn register_created_key(
        &mut self,
        template: &KeyTemplate,
        created_key: CreatedKey,
        key_name: Option<&str>,
        policy: Option<PolicyData>,
        parent: Option<KeyId>,
    ) -> Result<KeyId> {
        let Some(key_name) = key_name else {
            return self.register_temporary_key(
                created_key.into_temporary_key(template, policy, parent)?,
            );
        };

        let parent_name = match parent {
            Some(KeyId::Stored(name)) => Some(name),
            Some(KeyId::Temporary(_)) => {
                return Err(Error::invalid_state(
                    "stored key cannot have a temporary parent",
                ));
            }
            None => None,
        };
        let key_name = key_name.to_owned();
        let key_meta = created_key.into_key_meta(
            template,
            key_name.clone(),
            policy,
            parent_name,
        )?;

        self.store.save_key_meta(&key_meta)?;

        Ok(KeyId::Stored(key_name))
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
                    handle.inner(),
                    obj_name,
                    self.key_authorization(key_id, policy),
                ))
            },
            ParentKeyData::Primary {
                hierarchy,
                public,
                obj_name,
                policy,
            } => {
                let authorization = self.key_authorization(key_id, policy);
                let hierarchy_authorization = self.hierarchy_authorization(hierarchy)?;
                let session_salt_handle = self.load_session_salt_handle()?;

                self.backend.load_primary_key(
                    hierarchy.into(),
                    public,
                    authorization,
                    &hierarchy_authorization,
                    session_salt_handle,
                    &obj_name,
                )
            },
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
                let session_salt_handle = self.load_session_salt_handle()?;

                self.backend.load_temporary_key(
                    private,
                    public,
                    self.key_authorization(key_id, policy),
                    parent,
                    session_salt_handle,
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
            }) => {
                let private = private.as_ref().ok_or_else(|| {
                    Error::invalid_state("temporary child key private data is missing")
                })?;

                Ok(ParentKeyData::Child {
                    public: public.clone(),
                    private: Tpm2bPrivate::try_from(private.as_bytes())?,
                    obj_name: obj_name.clone(),
                    policy,
                    parent: temporary_key.parent.clone(),
                })
            }
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
            self
                .backend
                .evict_persistent_handles(&owner_authorization, &key_meta, None)
        })
    }

    pub fn get_random(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        if num_bytes == 0 {
            return Ok(Vec::new());
        }

        let session_salt_handle = self.load_session_salt_handle()?;
        self.backend.get_random(num_bytes, session_salt_handle)
    }

    fn load_internal_srk(&mut self) -> Result<LoadedHandle> {
        let key_meta = self.store.load_internal_srk()?;
        self.backend.resolve_internal_key(key_meta)
    }

    fn load_session_salt_handle(&mut self) -> Result<BackendObjectHandle> {
        let key_meta = self.store.load_session_salt_key()?;
        self
            .backend
            .resolve_internal_key(key_meta)
            .map(|handle| handle.handle().inner())
    }

    fn load_shared_wrapping_handle(&mut self) -> Result<LoadedHandle> {
        let key_meta = self.store.load_shared_wrapping_key()?;
        self.backend.resolve_internal_key(key_meta)
    }
}

