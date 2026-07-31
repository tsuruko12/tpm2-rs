#[cfg(target_os = "windows")]
use crate::types::TpmiDhObject;
use crate::{
    macros::{tpm2b_bytes_type, tpm2b_secret_type},
    types::{Authorization, TpmtPublic},
};
#[cfg(target_os = "linux")]
use tss_esapi::handles::KeyHandle;

tpm2b_secret_type!(Tpm2bPrivate);
tpm2b_bytes_type!(Tpm2bName);

#[cfg(target_os = "linux")]
pub(crate) type LoadedObjectHandle = KeyHandle;
#[cfg(target_os = "windows")]
pub(crate) type LoadedObjectHandle = TpmiDhObject;

#[derive(Debug)]
pub(crate) struct CreatedObject {
    pub(crate) handle: LoadedObjectHandle,
    pub(crate) public: TpmtPublic,
    pub(crate) private: Option<Tpm2bPrivate>,
    pub(crate) name: Tpm2bName,
}

pub(crate) struct LoadedParent {
    handle: LoadedObjectHandle,
    name: Vec<u8>,
    authorization: Authorization,
}

impl LoadedParent {
    pub(crate) fn new(
        handle: LoadedObjectHandle,
        name: impl Into<Vec<u8>>,
        authorization: Authorization,
    ) -> Self {
        Self {
            handle,
            name: name.into(),
            authorization,
        }
    }

    pub(crate) fn handle(&self) -> LoadedObjectHandle {
        self.handle
    }

    pub(crate) fn name(&self) -> &[u8] {
        &self.name
    }

    pub(crate) fn authorization(&self) -> &Authorization {
        &self.authorization
    }
}
