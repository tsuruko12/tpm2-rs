use crate::{
    cache::TemporaryKey,
    db::{KeyMeta, TpmKeyMeta, WrappingKeyMeta},
    error::{Error, Result},
    generate_key_id,
    public::KeyTemplate,
    types::{
        tpm::{Tpm2bAuth, Tpm2bPublicKeyRsa},
        Authorization, CreatedKeyData, HandleResource, Key, KeyData, KeyId, LoadedHandle, Policy,
        PolicyData,
    },
};

use super::super::Context;

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
        template: KeyTemplate,
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
                        template,
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
        template: KeyTemplate,
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
            (KeyTemplate::Symmetric(template), Self::Symmetric { key, wrapping_key }) => {
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
    /// Create a key from `template`.
    ///
    /// Symmetric keys are generated outside the TPM
    /// and then wrapped with a TPM-managed key.
    ///
    /// When `key_name` is provided, persists the key metadata under that unique name;
    /// otherwise, the key is available only through this context. `parent` selects the
    /// TPM parent for asymmetric child keys. `auth_value` and `policy` configure the key's
    /// authorization requirements.
    /// 
    /// `auth_value` is set when the key is created.
    ///
    /// # Errors
    ///
    /// if `parent` is specified for a storage root key or symmetric key, 
    /// returns [`Error::InvalidParameter`].
    pub fn create_key(
        &mut self,
        template: KeyTemplate,
        key_name: Option<&str>,
        auth_value: Option<&[u8]>,
        policy: Option<Policy>,
        parent: Option<&Key>,
    ) -> Result<Key> {
        self.validate_key_creation(template, key_name, parent)?;

        let mut policy = policy.map(PolicyData::try_from).transpose()?;
        let auth = auth_value
            .map(Tpm2bAuth::normalize_sha256)
            .unwrap_or_default();
        let parent_id = parent.map(|key| key.id().clone());

        let created_key = if template.is_storage_parent() {
            self.create_key_from_template(template, auth.clone(), &mut policy, None)?
        } else {
            let wrapping_parent = if matches!(&template, KeyTemplate::Symmetric(_)) {
                self.load_shared_wrapping_handle()?
            } else {
                self.load_parent(parent)?
            };

            let result = self.create_key_from_template(
                template,
                auth.clone(),
                &mut policy,
                Some(&wrapping_parent),
            );

            match result {
                Ok(created_key) => {
                    self.backend.release_handle(wrapping_parent.handle)?;
                    created_key
                }
                Err(e) => {
                    let _ = self.backend.release_handle(wrapping_parent.handle);
                    return Err(e);
                }
            }
        };
        let key_id =
            self.register_created_key(template, created_key, key_name, policy, parent_id)?;

        self.cache
            .set_key_auth(key_id.clone(), auth);

        Ok(Key::new(key_id))
    }

    fn validate_key_creation(
        &self,
        template: KeyTemplate,
        key_name: Option<&str>,
        parent: Option<&Key>,
    ) -> Result<()> {
        if let Some(name) = key_name {
            self.store.ensure_unique_key_name(name)?;

            if matches!(parent.map(|key| key.id()), Some(KeyId::Temporary(_))) {
                return Err(Error::invalid_param(
                    "parent must be a stored key for a named key",
                ));
            }
        }

        if template.is_storage_parent() || matches!(&template, KeyTemplate::Symmetric(_)) {
            if parent.is_some() {
                return Err(Error::invalid_param(
                    "parent cannot be specified for storage root or symmetric keys",
                ));
            }
        }

        Ok(())
    }

    fn create_key_from_template(
        &mut self,
        template: KeyTemplate,
        auth: Tpm2bAuth,
        policy: &mut Option<PolicyData>,
        parent: Option<&LoadedHandle>,
    ) -> Result<CreatedKey> {
        let Some(parent) = parent else {
            let owner_authorization = self.owner_authorization()?;
            let session_salt_handle = self.load_session_salt_handle()?;

            return self
                .backend
                .create_srk_from_template(
                    template,
                    auth,
                    policy.as_mut(),
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
                    policy.as_mut(),
                    parent,
                    session_salt_handle,
                )
                .map(CreatedKey::Tpm),
            KeyTemplate::Symmetric(_) => {
                let mut authorization = if auth.is_empty() && policy.is_none() {
                    None
                } else {
                    Some(Authorization {
                        auth,
                        policy: policy.take(),
                    })
                };

                let result = self.backend.create_sym_key_from_template(
                    template,
                    authorization.as_mut(),
                    parent,
                    session_salt_handle,
                );
                *policy = authorization.and_then(|authorization| authorization.policy);

                result.map(|(key, wrapping_key)| CreatedKey::Symmetric { key, wrapping_key })
            }
        }
    }

    fn register_created_key(
        &mut self,
        template: KeyTemplate,
        created_key: CreatedKey,
        key_name: Option<&str>,
        policy: Option<PolicyData>,
        parent: Option<KeyId>,
    ) -> Result<KeyId> {
        let Some(key_name) = key_name else {
            return self
                .register_temporary_key(created_key.into_temporary_key(template, policy, parent)?);
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
        let key_meta =
            created_key.into_key_meta(template, key_name.clone(), policy, parent_name)?;

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
}
