use crate::{
    Error, Result,
    macros::{newtype, tpm_list_type},
};

tpm_list_type!(TpmlHandle(TpmHandle););

newtype!(TpmHandle(u32));

impl TpmHandle {
    pub(crate) const RH_OWNER: Self = TpmHandle(0x40000001);
    pub(crate) const RH_PLATFORM: Self = TpmHandle(0x4000000C);
    pub(crate) const RH_NULL: Self = TpmHandle(0x4000_0007);

    pub(crate) const fn new(value: u32) -> Self {
        Self(value)
    }
}

impl From<u32> for TpmHandle {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

newtype!(TpmiDhObject(TpmHandle));

impl TpmiDhObject {
    const TRANSIENT_FIRST: u32 = 0x8000_0000;
    const TRANSIENT_LAST: u32 = 0x80FF_FFFF;

    const PERSISTENT_FIRST: u32 = 0x8100_0000;
    const PERSISTENT_LAST: u32 = 0x81FF_FFFF;

    pub(crate) fn is_persistent(&self) -> bool {
        (Self::PERSISTENT_FIRST..=Self::PERSISTENT_LAST).contains(&self.raw())
    }

    pub(crate) fn is_transient(&self) -> bool {
        (Self::TRANSIENT_FIRST..=Self::TRANSIENT_LAST).contains(&self.raw())
    }
}

impl TryFrom<TpmHandle> for TpmiDhObject {
    type Error = Error;

    fn try_from(handle: TpmHandle) -> Result<Self> {
        match handle.raw() {
            Self::TRANSIENT_FIRST..=Self::TRANSIENT_LAST
            | Self::PERSISTENT_FIRST..=Self::PERSISTENT_LAST => Ok(Self(handle)),
            _ => Err(Error::conversion::<TpmHandle, TpmiDhObject>(Some(&handle))),
        }
    }
}

impl TryFrom<u32> for TpmiDhObject {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        TpmHandle::from(value).try_into()
    }
}

newtype!(TpmiRhProvision(TpmHandle));

impl TpmiRhProvision {
    pub(crate) const OWNER: Self = Self(TpmHandle::RH_OWNER);
}

newtype!(TpmiDhPersistent(TpmHandle));

impl TpmiDhPersistent {
    const PERSISTENT_FIRST: u32 = 0x8100_0000;
    const PERSISTENT_LAST: u32 = 0x81FF_FFFF;

    pub(crate) const SRK_SEARCH_START: Self = Self(TpmHandle::new(0x8100_0001));
    pub(crate) const SRK_SEARCH_END: Self = Self(TpmHandle::new(0x8100_00FF));
    pub(crate) const STORAGE_AVAILABLE_FIRST: Self = Self(TpmHandle::new(0x8100_8000));
    pub(crate) const STORAGE_AVAILABLE_LAST: Self = Self(TpmHandle::new(0x8100_FFFF));
}

impl TryFrom<u32> for TpmiDhPersistent {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        if (Self::PERSISTENT_FIRST..=Self::PERSISTENT_LAST).contains(&value) {
            return Ok(Self(value.into()));
        }

        Err(Error::conversion::<TpmiDhObject, TpmiDhPersistent>(None))
    }
}

impl From<TpmiDhPersistent> for TpmiDhObject {
    fn from(persistent_handle: TpmiDhPersistent) -> Self {
        Self(persistent_handle.into())
    }
}

newtype!(TpmiRhHierarchy(TpmHandle));

impl TpmiRhHierarchy {
    pub(crate) const OWNER: Self = Self(TpmHandle(0x4000_0001));
    pub(crate) const NULL: Self = Self(TpmHandle::RH_NULL);
    pub(crate) const ENDORSEMENT: Self = Self(TpmHandle(0x4000_000B));
    pub(crate) const PLATFORM: Self = Self(TpmHandle(0x4000_000C));

    pub(crate) const SVN_OWNER_FIRST: u32 = 0x40010000;
    pub(crate) const SVN_OWNER_LAST: u32 = 0x4001FFFF;

    pub(crate) const SVN_ENDORSEMENT_FIRST: u32 = 0x40020000;
    pub(crate) const SVN_ENDORSEMENT_LAST: u32 = 0x4002FFFF;

    pub(crate) const SVN_PLATFORM_FIRST: u32 = 0x40030000;
    pub(crate) const SVN_PLATFORM_LAST: u32 = 0x4003FFFF;

    pub(crate) const SVN_NULL_FIRST: u32 = 0x40040000;
    pub(crate) const SVN_NULL_LAST: u32 = 0x4004FFFF;
}

impl TryFrom<TpmHandle> for TpmiRhHierarchy {
    type Error = Error;

    fn try_from(handle: TpmHandle) -> Result<Self> {
        match handle.raw() {
            0x4000_0001
            | 0x4000_0007
            | 0x4000_000B
            | 0x4000_000C
            | 0x4000_0140
            | 0x4000_0141
            | 0x4000_0142
            | 0x4000_0143
            | Self::SVN_OWNER_FIRST..=Self::SVN_OWNER_LAST
            | Self::SVN_ENDORSEMENT_FIRST..=Self::SVN_ENDORSEMENT_LAST
            | Self::SVN_PLATFORM_FIRST..=Self::SVN_PLATFORM_LAST
            | Self::SVN_NULL_FIRST..=Self::SVN_NULL_LAST => Ok(Self(handle)),
            _ => Err(Error::conversion::<TpmHandle, TpmiRhHierarchy>(None)),
        }
    }
}