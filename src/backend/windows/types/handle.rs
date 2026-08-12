use crate::{
    Error, Result,
    macros::newtype,
    types::{TpmHandle, TpmiDhObject},
};

newtype!(TpmiDhEntity(TpmHandle));

impl TpmiDhEntity {
    pub(crate) const RH_NULL: Self = Self(TpmHandle::RH_NULL);
}

newtype!(TpmiShAuthSession(TpmHandle));

impl TpmiShAuthSession {
    pub(crate) const RS_PW: Self = Self(TpmHandle::new(0x40000009));

    pub(crate) fn is_policy_session(&self) -> bool {
        (TpmiShPolicy::FIRST..=TpmiShPolicy::LAST).contains(&self.raw())
    }

    pub(crate) fn is_hmac_session(&self) -> bool {
        (TpmiShHmac::FIRST..=TpmiShHmac::LAST).contains(&self.raw())
    }
}

impl TryFrom<u32> for TpmiShAuthSession {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        if (TpmiShPolicy::FIRST..=TpmiShPolicy::LAST).contains(&value) 
        || (TpmiShHmac::FIRST..=TpmiShHmac::LAST).contains(&value) {
            Ok(Self(value.into()))
        } else {
            Err(Error::conversion::<u32, TpmiShAuthSession>(None))
        }
    }
}

newtype!(TpmiShPolicy(TpmHandle));

impl TpmiShPolicy {
    pub(crate) const FIRST: u32 = 0x0300_0000;
    pub(crate) const LAST: u32 = 0x03ff_ffff;
}

impl TryFrom<TpmiShAuthSession> for TpmiShPolicy {
    type Error = Error;

    fn try_from(session_handle: TpmiShAuthSession) -> Result<Self> {
        let handle_raw = session_handle.raw();

        if session_handle.is_policy_session() {
            Ok(Self(handle_raw.into()))
        } else {
            Err(Error::conversion::<TpmiShAuthSession, TpmiShPolicy>(None))
        }
    }
}

newtype!(TpmiShHmac(TpmHandle));

impl TpmiShHmac {
    pub(crate) const FIRST: u32 = 0x0200_0000;
    pub(crate) const LAST: u32 = 0x02FF_FFFF;
}

impl TryFrom<TpmiShAuthSession> for TpmiShHmac {
    type Error = Error;

    fn try_from(session_handle: TpmiShAuthSession) -> Result<Self> {
        let handle_raw = session_handle.raw();

        if session_handle.is_hmac_session() {
            Ok(Self(handle_raw.into()))
        } else {
            Err(Error::conversion::<TpmiShAuthSession, TpmiShHmac>(None))
        }
    }
}

newtype!(TpmiDhContext(TpmHandle));

impl From<TpmiShAuthSession> for TpmiDhContext {
    fn from(session: TpmiShAuthSession) -> Self {
        Self(session.0)
    }
}

impl TryFrom<TpmiDhObject> for TpmiDhContext {
    type Error = Error;

    fn try_from(handle: TpmiDhObject) -> Result<Self> {
        if handle.is_transient() {
            return Ok(Self(handle.into()));
        }

        Err(Error::conversion::<TpmiDhObject, TpmiDhContext>(None))
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
