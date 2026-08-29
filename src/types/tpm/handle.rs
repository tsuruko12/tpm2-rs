use crate::{
    Error, Result,
    macros::{newtype, tpm_list_type},
};

tpm_list_type!(TpmlHandle(TpmHandle));

newtype!(TpmHandle(u32));

impl TpmHandle {
    pub(crate) const PCR_FIRST: u32 = 0x0000_0000;
    pub(crate) const PCR_LAST: u32 = 0x0000_0017;

    pub(crate) const NV_INDEX_FIRST: u32 = 0x0100_0000;
    pub(crate) const NV_INDEX_LAST: u32 = 0x01FF_FFFF;

    pub(crate) const HMAC_SESSION_FIRST: u32 = 0x0200_0000;
    pub(crate) const HMAC_SESSION_LAST: u32 = 0x02FF_FFFF;

    pub(crate) const POLICY_SESSION_FIRST: u32 = 0x0300_0000;
    pub(crate) const POLICY_SESSION_LAST: u32 = 0x03FF_FFFF;

    pub(crate) const RH_OWNER: Self = Self(0x4000_0001);
    pub(crate) const RH_NULL: Self = Self(0x4000_0007);
    pub(crate) const RH_LOCKOUT: Self = Self(0x4000_000A);
    pub(crate) const RH_ENDORSEMENT: Self = Self(0x4000_000B);
    pub(crate) const RH_PLATFORM: Self = Self(0x4000_000C);

    pub(crate) const RS_PW: Self = Self(0x4000_0009);

    pub(crate) const RH_AUTH_00: u32 = 0x4000_0010;
    pub(crate) const RH_AUTH_FF: u32 = 0x4000_010F;

    pub(crate) const RH_FW_OWNER: Self = Self(0x4000_0140);
    pub(crate) const RH_FW_ENDORSEMENT: Self = Self(0x4000_0141);
    pub(crate) const RH_FW_PLATFORM: Self = Self(0x4000_0142);
    pub(crate) const RH_FW_NULL: Self = Self(0x4000_0143);

    pub(crate) const SVN_OWNER_FIRST: u32 = 0x40010000;
    pub(crate) const SVN_OWNER_LAST: u32 = 0x4001FFFF;

    pub(crate) const SVN_ENDORSEMENT_FIRST: u32 = 0x4002_0000;
    pub(crate) const SVN_ENDORSEMENT_LAST: u32 = 0x4002_FFFF;

    pub(crate) const SVN_PLATFORM_FIRST: u32 = 0x4003_0000;
    pub(crate) const SVN_PLATFORM_LAST: u32 = 0x4003_FFFF;

    pub(crate) const SVN_NULL_FIRST: u32 = 0x4004_0000;
    pub(crate) const SVN_NULL_LAST: u32 = 0x4004_FFFF;

    pub(crate) const TRANSIENT_FIRST: u32 = 0x8000_0000;
    pub(crate) const TRANSIENT_LAST: u32 = 0x80FF_FFFF;

    pub(crate) const PERSISTENT_FIRST: u32 = 0x8100_0000;
    pub(crate) const PERSISTENT_LAST: u32 = 0x81FF_FFFF;

    pub(crate) const fn new(value: u32) -> Self {
        Self(value)
    }

    pub(crate) fn is_hierarchy_handle(&self) -> bool {
        TpmiRhHierarchy::try_from(*self).is_ok()
    }
}

impl From<u32> for TpmHandle {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

newtype!(TpmiDhObject(TpmHandle));

impl TpmiDhObject {
    pub(crate) const RH_NULL: Self = Self(TpmHandle::RH_NULL);

    pub(crate) fn is_persistent(&self) -> bool {
        (TpmHandle::PERSISTENT_FIRST..=TpmHandle::PERSISTENT_LAST).contains(&self.value())
    }

    pub(crate) fn is_transient(&self) -> bool {
        (TpmHandle::TRANSIENT_FIRST..=TpmHandle::TRANSIENT_LAST).contains(&self.value())
    }
}

impl TryFrom<TpmHandle> for TpmiDhObject {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<Self> {
        match tpm_handle.value() {
            TpmHandle::TRANSIENT_FIRST..=TpmHandle::TRANSIENT_LAST
            | TpmHandle::PERSISTENT_FIRST..=TpmHandle::PERSISTENT_LAST => Ok(Self(tpm_handle)),
            _ => Err(Error::conversion::<TpmHandle, TpmiDhObject>(Some(&tpm_handle))),
        }
    }
}

impl From<TpmiDhPersistent> for TpmiDhObject {
    fn from(persistent_handle: TpmiDhPersistent) -> Self {
        Self(persistent_handle.into())
    }
}

newtype!(TpmiRhProvision(TpmHandle));

impl TpmiRhProvision {
    pub(crate) const OWNER: Self = Self(TpmHandle::RH_OWNER);
    pub(crate) const PLATFORM: Self = Self(TpmHandle::RH_PLATFORM);
}

impl TryFrom<TpmHandle> for TpmiRhProvision {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<Self> {
        match tpm_handle {
            TpmHandle::RH_OWNER | TpmHandle::RH_PLATFORM => Ok(Self(tpm_handle)),
            _ => Err(Error::conversion::<TpmHandle, TpmiRhProvision>(Some(&tpm_handle))),
        }
    }
}

newtype!(TpmiDhPersistent(TpmHandle));

impl TpmiDhPersistent {
    pub(crate) const SRK_SEARCH_START: Self = Self(TpmHandle::new(0x8100_0001));
    pub(crate) const SRK_SEARCH_END: Self = Self(TpmHandle::new(0x8100_00FF));
    pub(crate) const STORAGE_AVAILABLE_FIRST: Self = Self(TpmHandle::new(0x8100_8000));
    pub(crate) const STORAGE_AVAILABLE_LAST: Self = Self(TpmHandle::new(0x8100_FFFF));
}

impl TryFrom<u32> for TpmiDhPersistent {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        if (TpmHandle::PERSISTENT_FIRST..=TpmHandle::PERSISTENT_LAST).contains(&value) {
            Ok(Self(value.into()))
        } else {
            Err(Error::conversion::<u32, TpmiDhPersistent>(Some(&value)))
        }  
    }
}

impl TryFrom<TpmHandle> for TpmiDhPersistent {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<Self> {
        tpm_handle.value().try_into()
    }
}

newtype!(TpmiRhHierarchy(TpmHandle));

impl TpmiRhHierarchy {
    pub(crate) const OWNER: Self = Self(TpmHandle(0x4000_0001));
    pub(crate) const NULL: Self = Self(TpmHandle::RH_NULL);
    pub(crate) const ENDORSEMENT: Self = Self(TpmHandle(0x4000_000B));
    pub(crate) const PLATFORM: Self = Self(TpmHandle(0x4000_000C));
}

impl TryFrom<TpmHandle> for TpmiRhHierarchy {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<Self> {
        match tpm_handle {
            TpmHandle::RH_OWNER
            | TpmHandle::RH_NULL
            | TpmHandle::RH_PLATFORM
            | TpmHandle::RH_ENDORSEMENT
            | TpmHandle::RH_FW_OWNER
            | TpmHandle::RH_FW_PLATFORM
            | TpmHandle::RH_FW_ENDORSEMENT
            | TpmHandle::RH_FW_NULL => Ok(Self(tpm_handle)),
            _ if (TpmHandle::SVN_OWNER_FIRST..=TpmHandle::SVN_NULL_LAST)
                .contains(&tpm_handle.value()) =>
            {
                Ok(Self(tpm_handle))
            }
            _ => Err(Error::conversion::<TpmHandle, TpmiRhHierarchy>(
                Some(&tpm_handle),
            )),
        }
    }
}