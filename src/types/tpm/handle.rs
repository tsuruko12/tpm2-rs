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
    pub(crate) const OWNER_AVAILABLE_FIRST: Self = Self(TpmHandle::new(0x8100_8000));
    pub(crate) const OWNER_AVAILABLE_LAST: Self = Self(TpmHandle::new(0x8100_FFFF));
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
    fn from(handle: TpmiDhPersistent) -> Self {
        Self(handle.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_last_transient_object_handle() {
        assert!(TpmiDhObject::try_from(TpmHandle::new(0x80FF_FFFF)).is_ok());
    }
}
