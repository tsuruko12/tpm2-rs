use tss_esapi::{
    handles::{PersistentTpmHandle, TpmHandle as EsapiTpmHandle}, 
    interface_types::resource_handles::Hierarchy as EsapiHierarchy, 
    structures::HandleList, tss2_esys::TPM2_HANDLE
};

use crate::{
    Error, Result,
    types::tpm::{TpmHandle, TpmiDhPersistent, TpmiRhHierarchy, TpmlHandle},
};

impl From<HandleList> for TpmlHandle {
    fn from(handle_list: HandleList) -> Self {
        let items = handle_list
            .into_inner()
            .into_iter()
            .map(|handle| TpmHandle::new(handle.into()))
            .collect::<Vec<_>>();

        items.into()
    }
}

impl TryFrom<TpmHandle> for EsapiTpmHandle {
    type Error = Error;

    fn try_from(handle: TpmHandle) -> Result<Self> {
        handle
            .value()
            .try_into()
            .map_err(|_| Error::conversion::<TpmHandle, EsapiTpmHandle>(None))
    }
}

impl From<PersistentTpmHandle> for TpmiDhPersistent {
    fn from(persistent_handle: PersistentTpmHandle) -> Self {
        TPM2_HANDLE::from(persistent_handle)
            .try_into()
            .expect("PersistentTpmHandle must be valid for TpmiDhPersistent")
    }
}

impl From<TpmiDhPersistent> for PersistentTpmHandle {
    fn from(persistent_handle: TpmiDhPersistent) -> Self {
        PersistentTpmHandle::new(persistent_handle.value())
            .expect("TpmiDhPersistent must be valid for PersistentTpmHandle")
    }
}

impl TryFrom<TpmiRhHierarchy> for EsapiHierarchy {
    type Error = Error;

    fn try_from(hierarchy: TpmiRhHierarchy) -> Result<Self> {
        match hierarchy {
            TpmiRhHierarchy::ENDORSEMENT => Ok(Self::Endorsement),
            TpmiRhHierarchy::OWNER => Ok(Self::Owner),
            TpmiRhHierarchy::PLATFORM => Ok(Self::Platform),
            TpmiRhHierarchy::NULL => Ok(Self::Null),
            _ => Err(Error::conversion::<TpmiRhHierarchy, EsapiHierarchy>(Some(&hierarchy))),
        }
    }
}
