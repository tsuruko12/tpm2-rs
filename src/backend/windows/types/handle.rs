use crate::{Error, Result, macros::newtype, types::{TpmHandle, TpmiDhObject}};

newtype!(TpmiDhEntity(TpmHandle) => u32);

impl TpmiDhEntity {
    pub(crate) const RH_NULL: Self = Self(TpmHandle::RH_NULL);
}

newtype!(TpmiRhHierarchy(TpmHandle) => u32);

impl TpmiRhHierarchy {
    pub(crate) const OWNER: Self = Self(TpmHandle::new(0x4000_0001));
    pub(crate) const NULL: Self = Self(TpmHandle::RH_NULL);
    pub(crate) const ENDORSEMENT: Self = Self(TpmHandle::new(0x4000_000B));
    pub(crate) const PLATFORM: Self = Self(TpmHandle::new(0x4000_000C));

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
            _ => Err(Error::conversion::<TpmHandle, TpmiRhHierarchy>()),
        }
    }
}

newtype!(TpmiShAuthSession(TpmHandle) => u32);

impl TpmiShAuthSession {
    pub(crate) const RS_PW: Self = Self(TpmHandle::new(0x40000009));
}

impl TryFrom<u32> for TpmiShAuthSession {
    type Error = Error;

    fn try_from(raw: u32) -> Result<Self> {
        Ok(Self(TpmHandle::from(raw)))
    }
}

newtype!(TpmiShPolicy(TpmHandle) => u32);

impl TpmiShPolicy {
    pub(crate) const FIRST: u32 = 0x0300_0000;
    pub(crate) const LAST: u32 = 0x03ff_ffff;
}

impl TryFrom<TpmiShAuthSession> for TpmiShPolicy {
    type Error = Error;

    fn try_from(handle: TpmiShAuthSession) -> Result<Self> {
        let handle_raw = handle.raw();

        if (TpmiShPolicy::FIRST..=TpmiShPolicy::LAST).contains(&handle_raw) {
            Ok(Self(handle_raw.into()))
        } else {
            Err(Error::conversion::<TpmiShAuthSession, TpmiShPolicy>())
        }
    }
}

newtype!(TpmiShHmac(TpmHandle) => u32);

impl TpmiShHmac {
    pub(crate) const FIRST: u32 = 0x0200_0000;
    pub(crate) const LAST: u32 = 0x02FF_FFFF;
}

impl TryFrom<TpmiShAuthSession> for TpmiShHmac {
    type Error = Error;

    fn try_from(handle: TpmiShAuthSession) -> Result<Self> {
        let handle_raw = handle.raw();

        if (TpmiShHmac::FIRST..=TpmiShHmac::LAST).contains(&handle_raw) {
            Ok(Self(handle_raw.into()))
        } else {
            Err(Error::conversion::<TpmiShAuthSession, TpmiShHmac>())
        }
    }
}

newtype!(TpmiDhContext(TpmHandle) => u32);

impl From<TpmiShAuthSession> for TpmiDhContext {
    fn from(session: TpmiShAuthSession) -> Self {
        Self(session.0)
    }
}

impl TryFrom<TpmiDhObject> for TpmiDhContext {
    type Error = Error;

    fn try_from(handle: TpmiDhObject) -> Result<Self> {
        if handle.is_transient() {
            return Ok(Self(handle.into()))
        }

        Err(Error::conversion::<TpmiDhObject, TpmiDhContext>())
    }
}

// 必要なかったら消す
newtype!(TpmHt(u8));

impl TpmHt {
    pub(crate) const PCR: Self = Self(0x00);
    pub(crate) const NV_INDEX: Self = Self(0x01);

    pub(crate) const HMAC_SESSION: Self = Self(0x02);
    pub(crate) const LOADED_SESSION: Self = Self(0x02);
    pub(crate) const POLICY_SESSION: Self = Self(0x03);
    pub(crate) const SAVED_SESSION: Self = Self(0x03);

    pub(crate) const EXTERNAL_NV: Self = Self(0x11);
    pub(crate) const PERMANENT_NV: Self = Self(0x12);
    pub(crate) const PERMANENT: Self = Self(0x40);
    pub(crate) const TRANSIENT: Self = Self(0x80);
    pub(crate) const PERSISTENT: Self = Self(0x81);
    pub(crate) const AC: Self = Self(0x90);
}
