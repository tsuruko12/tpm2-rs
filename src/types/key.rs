use std::fmt::{Debug, Formatter, Result as StdResult};

#[cfg(target_os = "linux")]
use tss_esapi::handles::KeyHandle;

use crate::types::tpm::{Tpm2bPublicKeyRsa, TpmiDhPersistent};

#[cfg(target_os = "windows")]
use super::tpm::TpmiDhObject;
use super::{
    Authorization,
    public::SymmetricTemplate,
    tpm::{Tpm2bName, Tpm2bPrivate, Tpm2bPublic},
};

#[cfg(target_os = "linux")]
pub(crate) type BackendObjectHandle = KeyHandle;
#[cfg(target_os = "windows")]
pub(crate) type BackendObjectHandle = TpmiDhObject;

pub(crate) struct CreatedObject {
    pub(crate) handle: BackendObjectHandle,
    pub(crate) public: Tpm2bPublic,
    pub(crate) private: Option<Tpm2bPrivate>,
    pub(crate) name: Tpm2bName,
}

impl Debug for CreatedObject {
    fn fmt(&self, f: &mut Formatter<'_>) -> StdResult {
        f.debug_struct("CreatedObject")
            .field("handle", &self.handle)
            .field("public", &self.public)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

pub(crate) struct CreatedKeyData {
    pub(crate) public: Tpm2bPublic,
    pub(crate) private: Option<Tpm2bPrivate>,
    pub(crate) name: Tpm2bName,
}

impl Debug for CreatedKeyData {
    fn fmt(&self, f: &mut Formatter<'_>) -> StdResult {
        f.debug_struct("CreatedKeyData")
            .field("public", &self.public)
            .field("private", &self.private.is_some())
            .field("name", &self.name)
            .finish()
    }
}

pub(crate) struct LoadedHandle {
    pub(crate) handle: LoadedObjectHandle,
    pub(crate) name: Tpm2bName,
    pub(crate) authorization: Authorization,
}

impl Debug for LoadedHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> StdResult {
        f.debug_struct("LoadedHandle")
            .field("handle", &self.handle)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl LoadedHandle {
    pub(crate) fn new(
        handle: LoadedObjectHandle,
        name: Tpm2bName,
        authorization: Authorization,
    ) -> Self {
        Self {
            handle,
            name,
            authorization,
        }
    }

    pub(crate) fn transient(
        handle: BackendObjectHandle,
        name: Tpm2bName,
        authorization: Authorization,
    ) -> Self {
        Self {
            handle: LoadedObjectHandle::Transient(handle),
            name,
            authorization,
        }
    }

    pub(crate) fn persistent(
        handle: BackendObjectHandle,
        name: Tpm2bName,
        authorization: Authorization,
    ) -> Self {
        Self {
            handle: LoadedObjectHandle::Persistent(handle),
            name,
            authorization,
        }
    }

    pub(crate) fn internal_persistent(
        handle: BackendObjectHandle,
        name: Tpm2bName,
    ) -> Self {
        Self {
            handle: LoadedObjectHandle::Persistent(handle),
            name,
            authorization: Authorization::default(),
        }
    }

    pub(crate) fn is_persistent(&self) -> bool {
        self.handle.is_persistent()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum LoadedObjectHandle {
    Transient(BackendObjectHandle),
    Persistent(BackendObjectHandle),
}

impl LoadedObjectHandle {
    pub(crate) fn inner(&self) -> BackendObjectHandle {
        match self {
            Self::Transient(handle) | Self::Persistent(handle) => *handle,
        }
    }

    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent(_))
    }
}

pub struct Key(KeyId);

impl Key {
    pub(crate) fn new(id: KeyId) -> Self {
        Self(id)
    }

    pub(crate) fn id(&self) -> &KeyId {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum KeyId {
    Stored(String),
    Temporary(String),
}

impl KeyId {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Stored(id) | Self::Temporary(id) => id,
        }
    }
}

pub(crate) enum KeyData {
    Srk(HandleResource),
    Rsa(HandleResource),
    Ecc(HandleResource),
    Symmetric {
        template: SymmetricTemplate,
        wrapping_key: Option<HandleResource>,
        wrapped_key: Tpm2bPublicKeyRsa,
    },
}

pub(crate) enum HandleResource {
    Transient {
        public: Tpm2bPublic,
        private: Option<Tpm2bPrivate>,
        obj_name: Tpm2bName,
    },
    Persistent {
        handle: TpmiDhPersistent,
        obj_name: Tpm2bName,
    },
}

impl Debug for HandleResource {
    fn fmt(&self, f: &mut Formatter<'_>) -> StdResult {
        match self {
            Self::Transient {
                public,
                obj_name,
                ..
            } => f
                .debug_struct("Transient")
                .field("public", public)
                .field("obj_name", obj_name)
                .finish_non_exhaustive(),

            Self::Persistent { handle, obj_name } => f
                .debug_struct("Persistent")
                .field("handle", handle)
                .field("obj_name", obj_name)
                .finish(),
        }
    }
}

impl HandleResource {
    fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent { .. })
    }
}
