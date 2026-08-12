#[cfg(target_os = "linux")]
use tss_esapi::handles::KeyHandle;

use crate::types::TpmiDhPersistent;

#[cfg(target_os = "windows")]
use super::tpm::TpmiDhObject;
use super::{Authorization, tpm::{Tpm2bName, Tpm2bPrivate, Tpm2bPublic}};

#[cfg(target_os = "linux")]
pub(crate) type LoadedObjectHandle = KeyHandle;
#[cfg(target_os = "windows")]
pub(crate) type LoadedObjectHandle = TpmiDhObject;

#[derive(Debug)]
pub(crate) struct CreatedObject {
    pub(crate) handle: LoadedObjectHandle,
    pub(crate) public: Tpm2bPublic,
    pub(crate) private: Option<Tpm2bPrivate>,
    pub(crate) name: Tpm2bName,
}

#[derive(Debug)]
pub(crate) struct LoadedHandle {
    handle: TpmObjectHandle,
    name: Tpm2bName,
    authorization: Authorization,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TpmObjectHandle {
    Transient(LoadedObjectHandle),
    Persistent(LoadedObjectHandle),
}

impl TpmObjectHandle {
    fn loaded_handle(&self) -> LoadedObjectHandle {
        match self {
            Self::Transient(handle) | Self::Persistent(handle) => *handle,
        }
    }

    fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent(_))
    }
}

impl LoadedHandle {
    pub(crate) fn transient(
        handle: LoadedObjectHandle,
        name: Tpm2bName,
        authorization: Authorization,
    ) -> Self {
        Self {
            handle: TpmObjectHandle::Transient(handle),
            name,
            authorization,
        }
    }

    pub(crate) fn persistent(
        handle: LoadedObjectHandle,
        name: Tpm2bName,
        authorization: Authorization,
    ) -> Self {
        Self {
            handle: TpmObjectHandle::Persistent(handle),
            name,
            authorization,
        }
    }

    pub(crate) fn internal_persistent(
        handle: LoadedObjectHandle,
        name: Tpm2bName,
    ) -> Self {
        Self {
            handle: TpmObjectHandle::Persistent(handle),
            name,
            authorization: Authorization::default(),
        }
    }

    pub(crate) fn handle(&self) -> LoadedObjectHandle {
        self.handle.loaded_handle()
    }

    pub(crate) fn is_persistent(&self) -> bool {
        self.handle.is_persistent()
    }

    pub(crate) fn name(&self) -> &Tpm2bName {
        &self.name
    }

    pub(crate) fn authorization(&self) -> &Authorization {
        &self.authorization
    }

    pub(crate) fn into_authorization(self) -> Authorization {
        self.authorization
    }
}

pub struct Key {
    id: String,
    data: KeyData,
    obj_name: Tpm2bName,
    authorization: Authorization,
    name: Option<String>,
    parent_id: Option<String>,
}

impl Key {
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub(crate) fn data(&self) -> &KeyData {
        &self.data
    }

    pub(crate) fn obj_name(&self) -> &Tpm2bName {
        &self.obj_name
    }

    pub(crate) fn authorization(&self) -> &Authorization {
        &self.authorization
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn parent_id(&self) -> Option<&str> {
        self.parent_id.as_deref()
    }

    pub(crate) fn is_persistent(&self) -> bool {
        match &self.data {
            KeyData::Srk(resource)
            | KeyData::Ecc(resource)
            | KeyData::Rsa(resource) => {
                resource.is_persistent()
            },
            KeyData::Symmetric { wrapping_key_resource, .. } => {
                wrapping_key_resource.is_persistent()
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum KeyData {
    Srk(HandleResource),
    Rsa(HandleResource),
    Ecc(HandleResource),
    Symmetric {
        wrapping_key_resource: HandleResource,
        wrapping_key_id: String,
        wrapped_key: Vec<u8>,
    },
}

#[derive(Debug)]
pub(crate) enum HandleResource {
    Transient {
        public: Tpm2bPublic,
        private: Tpm2bPrivate,
    },
    Persistent {
        handle: TpmiDhPersistent,
    },
}

impl HandleResource {
    fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent { .. })
    }
}
