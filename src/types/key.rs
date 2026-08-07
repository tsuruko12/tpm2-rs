#[cfg(target_os = "windows")]
use crate::types::TpmiDhObject;
use crate::{
    Error, Result, 
    macros::tpm2b_secret_type, 
    types::{Authorization, Tpm2bDigest, Tpm2bPublic, TpmAlgId, TpmHandle}
};
#[cfg(target_os = "linux")]
use tss_esapi::handles::KeyHandle;

tpm2b_secret_type!(Tpm2bPrivate);

#[derive(Debug, Default, Clone)]
pub(crate) struct Tpm2bName(Vec<u8>);

impl Tpm2bName {
    const NO_NAME_SIZE: usize = 0;
    const HANDLE_SIZE: usize = size_of::<TpmHandle>();
    const MAX_SIZE: usize = size_of::<TpmAlgId>() + Tpm2bDigest::MAX_SIZE; // TPMT_HA

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<Vec<u8>> for Tpm2bName {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        let size = value.len();

        if size == Self::NO_NAME_SIZE 
            || size == Self::HANDLE_SIZE 
            || size == Self::MAX_SIZE {
            Ok(Self(value))
        } else {
            Err(Error::conversion::<Vec<u8>, Tpm2bName>(None))
        }
    }
}

impl TryFrom<&[u8]> for Tpm2bName {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let size = value.len();

        if size == Self::NO_NAME_SIZE 
            || size == Self::HANDLE_SIZE 
            || size == Self::MAX_SIZE {
            Ok(Self(value.into()))
        } else {
            Err(Error::conversion::<Vec<u8>, Tpm2bName>(None))
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) type LoadedObjectHandle = KeyHandle;
#[cfg(target_os = "windows")]
pub(crate) type LoadedObjectHandle = TpmiDhObject;

#[derive(Debug)]
pub(crate) struct CreatedObject {
    pub(crate) obj_handle: LoadedObjectHandle,
    pub(crate) public: Tpm2bPublic,
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
