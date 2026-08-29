use tracing::debug;

use crate::{
    cache::AuthorizationTarget, db::{KeyMeta, TpmKeyMeta}, error::{Error, Result}, hierarchy::Hierarchy, 
    types::{
        Authorization, HandleResource, Key, KeyData, KeyId, LoadedHandle, PolicyData, 
        tpm::{Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmiDhPersistent}
    }
};

use super::super::Context;

enum KeyLoadData {
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
    /// Opens a key registered in the store.
    ///
    /// # Errors
    ///
    /// if no key with the specified name is registered, returns [`Error::KeyNotFound`] .
    pub fn open(&mut self, key_name: &str) -> Result<Key> {
        if self.store.user_key_exists(key_name)? {
            Ok(Key::stored(key_name))
        } else {
            Err(Error::KeyNotFound)
        }
    } 

    pub(super) fn load_parent(&mut self, parent: Option<&Key>) -> Result<LoadedHandle> {
        match parent {
            Some(parent) => self.load_key(parent.id()),
            None => self.load_internal_srk(),
        }
    }

    pub(super) fn load_key(&mut self, key_id: &KeyId) -> Result<LoadedHandle> {
        self.load_key_by_id(key_id, &mut Vec::new())
    }

    fn load_key_by_id(
        &mut self,
        key_id: &KeyId,
        ancestors: &mut Vec<KeyId>,
    ) -> Result<LoadedHandle> {
        if ancestors.contains(key_id) {
            debug!(?key_id, "key parent chain contains a cycle");
            return Err(Error::invalid_state("invalid key parent chain"));
        }

        ancestors.push(key_id.clone());

        let result = (|| match self.load_key_data(key_id)? {
            KeyLoadData::Persistent {
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
            }
            KeyLoadData::Primary {
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
                    public.with_empty_unique(),
                    authorization,
                    &hierarchy_authorization,
                    session_salt_handle,
                    &obj_name,
                )
            }
            KeyLoadData::Child {
                public,
                private,
                obj_name,
                policy,
                parent,
            } => {
                let session_salt_handle = self.load_session_salt_handle()?;
                let parent = match parent {
                    Some(parent) => self.load_key_by_id(&parent, ancestors)?,
                    None => self.load_internal_srk()?,
                };

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

    fn load_key_data(&self, key_id: &KeyId) -> Result<KeyLoadData> {
        match key_id {
            KeyId::Stored(key_name) => self.load_stored_key_data(key_name),
            KeyId::Temporary(id) => self.load_temporary_key_data(id),
        }
    }

    fn load_stored_key_data(&self, key_name: &str) -> Result<KeyLoadData> {
        let KeyMeta::Tpm {
            hierarchy,
            tpm_key_meta,
            persistent_handle,
            parent_name,
            ..
        } = self.store.load_key(key_name)?
        else {
            return Err(Error::invalid_state(
                "unexpected symmetric key as TPM parent",
            ));
        };
        let TpmKeyMeta {
            public,
            private,
            obj_name,
            mut policy,
        } = tpm_key_meta;

        if let Some(policy) = policy.as_mut() && policy.contains_or() {
            let labels = self
                .cache
                .key_policy_branches(KeyId::Stored(key_name.to_string()))
                .ok_or(Error::InvalidPolicy("policy branch was not selected"))?;

            policy.set_selected_labels(labels)?;
        }

        match persistent_handle {
            Some(handle) => Ok(KeyLoadData::Persistent {
                handle,
                obj_name,
                policy,
            }),
            None => match hierarchy {
                Some(hierarchy) => Ok(KeyLoadData::Primary {
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

                    Ok(KeyLoadData::Child {
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

    fn load_temporary_key_data(&self, id: &str) -> Result<KeyLoadData> {
        let temporary_key = self
            .cache
            .temporary_key(id)
            .ok_or_else(|| Error::invalid_state("temporary key is not registered"))?;
        
        let mut policy = temporary_key.policy.clone();
        if let Some(policy) = policy.as_mut() && policy.contains_or() {
            let labels = self
                    .cache
                    .key_policy_branches(KeyId::Temporary(id.to_string()))
                    .ok_or(Error::InvalidPolicy("policy branch was not selected"))?;

            policy.set_selected_labels(labels)?;
        }

        match &temporary_key.data {
            KeyData::Srk(HandleResource::Persistent {
                handle, obj_name, ..
            })
            | KeyData::Rsa(HandleResource::Persistent {
                handle, obj_name, ..
            })
            | KeyData::Ecc(HandleResource::Persistent {
                handle, obj_name, ..
            }) => Ok(KeyLoadData::Persistent {
                handle: *handle,
                obj_name: obj_name.clone(),
                policy,
            }),
            KeyData::Srk(HandleResource::Transient {
                public, obj_name, ..
            }) => Ok(KeyLoadData::Primary {
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

                Ok(KeyLoadData::Child {
                    public: public.clone(),
                    private: Tpm2bPrivate::try_from(private.as_bytes())?,
                    obj_name: obj_name.clone(),
                    policy,
                    parent: temporary_key.parent.clone(),
                })
            }
            KeyData::Symmetric { .. } => Err(Error::invalid_state(
                "unexpected symmetric key as TPM parent",
            )),
        }
    }

    fn key_authorization(&self, key_id: &KeyId, policy: Option<PolicyData>) -> Authorization {
        Authorization {
            auth: self.cache.auth(&AuthorizationTarget::Key(key_id.clone())),
            policy,
        }
    }

    pub(super) fn owner_authorization(&self) -> Result<Authorization> {
        self.hierarchy_authorization(Hierarchy::Storage)
    }

    pub(super) fn hierarchy_authorization(&self, hierarchy: Hierarchy) -> Result<Authorization> {
        let mut policy = self.store.load_hierarchy_policy(hierarchy)?;
        if let Some(policy) = policy.as_mut() && policy.contains_or() {
            let labels = self
                .cache
                .hierarchy_policy_branches(hierarchy)
                .ok_or(Error::InvalidPolicy("policy branch was not selected"))?;

            policy.set_selected_labels(labels)?;
        }
        Ok(Authorization {
            auth: self.cache.auth(&AuthorizationTarget::Hierarchy(hierarchy)),
            policy,
        })
    }
}
