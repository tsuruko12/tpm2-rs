use tracing::debug;

use crate::{
    backend::BackendContext, 
    db::MetadataStore, 
    error::{Error, Result}, 
    public::KeyTemplate, 
    types::{Authorization, AuthorizationCache, HandleResource, Key, KeyData, LoadedHandle, Policy, 
        Tpm2bAuth, TpmiRhHierarchy, 
    }
};

pub struct Context {
    backend: BackendContext,
    store: MetadataStore,
    authorization_cache: AuthorizationCache,
}

impl Context {
    pub fn connect() -> Result<Self> {
        Ok(Self {
            backend: BackendContext::create_context()?,
            store: MetadataStore::new()?,
            authorization_cache: AuthorizationCache::default(),
        })
    }

    #[cfg(target_os = "linux")]
    pub fn connect_from_env() -> Result<Self> {
        Ok(Self {
            backend: BackendContext::create_context_from_tcti_env()?,
            store: MetadataStore::new()?,
            authorization_cache: AuthorizationCache::default(),
        })
    }

    pub fn create(
        &mut self,
        template: KeyTemplate,
        auth_value: Option<&[u8]>,
        policy: Option<Policy>,
        key_name: Option<&str>,
        parent: Option<&Key>,
    ) -> Result<Key> {
        let auth = Tpm2bAuth::normalize_sha256(auth_value.unwrap_or(&[]));
        let authorization = Authorization::new(auth, policy.map(Into::into));
    }

    fn load_parent(&mut self, parent: Option<&Key>) -> Result<LoadedHandle> {
        let Some(parent) = parent else {
            return Ok(self.load_internal_srk()?);
        };

        let parent_obj_name = parent.obj_name().clone();

        match parent.data() {
            KeyData::Srk(resource) => {
                match resource {
                    HandleResource::Persistent { handle } => {
                        let parent_handle = self
                            .backend
                            .resolve_persistent_handle(*handle, parent.obj_name())?;

                        Ok(LoadedHandle::persistent(
                            parent_handle.into(), 
                            parent_obj_name, 
                            parent.authorization().duplicate()
                        ))
                    },
                    HandleResource::Transient { public, private } => {
                        let (auth, policy) = parent.authorization().as_parts();
                        let authorization = Authorization::new(
                            auth.duplicate(), 
                            policy.cloned()
                        );
                        let owner_authorization = Authorization::new(
                            self.authorization_cache.get_owner_auth().duplicate(), 
                            self.store.load_owner_policy()?,
                        );
                        let session_salt_key = self.load_session_salt_key()?;

                        self
                            .backend
                            .load_primary_key(
                                TpmiRhHierarchy::OWNER, 
                                public.clone(), 
                                authorization, 
                                &owner_authorization, 
                                session_salt_key.handle(), 
                                &parent_obj_name
                            )
                    }
                }
            },
            KeyData::Ecc(resource) => {
                match resource {
                    HandleResource::Persistent { handle } => {
                        let parent_handle = self.backend.load_persistent_handle(handle.into())?;

                        Ok(LoadedHandle::persistent(
                            parent_handle.into(), 
                            parent_obj_name, 
                            parent.authorization().duplicate()
                        ))
                    },
                    HandleResource::Transient { public, private } => {
                        let authorization = parent
                    }
                }
            }
        }
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
