use crate::{
    Error, Result, macros::newtype_in_win, types::tpm::{TpmHandle, TpmiDhObject},
};

newtype_in_win!(TpmiDhEntity(TpmHandle));

impl TryFrom<TpmHandle> for TpmiDhEntity {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<Self> {
        let value = tpm_handle.value();

        match tpm_handle {
            TpmHandle::RH_OWNER
            | TpmHandle::RH_ENDORSEMENT
            | TpmHandle::RH_PLATFORM
            | TpmHandle::RH_LOCKOUT
            | TpmHandle::RH_NULL => Ok(Self(tpm_handle)),
            _ if TpmiDhObject::try_from(tpm_handle).is_ok()
                || (TpmHandle::NV_INDEX_FIRST..=TpmHandle::NV_INDEX_LAST).contains(&value)
                || (TpmHandle::PCR_FIRST..=TpmHandle::PCR_LAST).contains(&value)
                || (TpmHandle::RH_AUTH_00..=TpmHandle::RH_AUTH_FF)
                    .contains(&value) => Ok(Self(tpm_handle)),
            _ => Err(Error::conversion::<TpmHandle, TpmiDhEntity>(Some(&tpm_handle))),
        }
    }
}

newtype_in_win!(TpmiShAuthSession(TpmHandle));

impl TpmiShAuthSession {
    pub(in crate::backend::windows) const RS_PW: Self = Self(TpmHandle::RS_PW);
}

impl TryFrom<TpmiShAuthSession> for TpmiShPolicy {
    type Error = Error;

    fn try_from(session_handle: TpmiShAuthSession) -> Result<Self> {
        let tpm_handle = TpmHandle::from(session_handle);
        if TpmiShPolicy::try_from(tpm_handle).is_ok(){
                Ok(Self(tpm_handle))
            } else {
                Err(Error::conversion::<TpmiShAuthSession, TpmiShPolicy>(None))
            }
    }
}

impl TryFrom<TpmiShAuthSession> for TpmiShHmac {
    type Error = Error;

    fn try_from(session_handle: TpmiShAuthSession) -> Result<Self> {
        let tpm_handle = TpmHandle::from(session_handle);
        if TpmiShHmac::try_from(tpm_handle).is_ok(){
                Ok(Self(tpm_handle))
            } else {
                Err(Error::conversion::<TpmiShAuthSession, TpmiShHmac>(None))
            }
    }
}

impl TryFrom<TpmHandle> for TpmiShAuthSession {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<Self> {
        if TpmiShPolicy::try_from(tpm_handle).is_ok()
            || TpmiShHmac::try_from(tpm_handle).is_ok() {
                Ok(Self(tpm_handle))
            } else {
                Err(Error::conversion::<TpmHandle, TpmiShAuthSession>(Some(&tpm_handle)))
            }
    }
} 

newtype_in_win!(TpmiShPolicy(TpmHandle));

impl TryFrom<TpmHandle> for TpmiShPolicy {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<Self> {
        if (TpmHandle::POLICY_SESSION_FIRST..=TpmHandle::POLICY_SESSION_LAST)
            .contains(&tpm_handle.value()) {
                Ok(Self(tpm_handle))
            } else {
                Err(Error::conversion::<TpmiShAuthSession, TpmiShPolicy>(None))
            }
    }
}

newtype_in_win!(TpmiShHmac(TpmHandle));

impl TryFrom<TpmHandle> for TpmiShHmac {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<Self> {
        if (TpmHandle::HMAC_SESSION_FIRST..=TpmHandle::HMAC_SESSION_LAST)
            .contains(&tpm_handle.value()) {
                Ok(Self(tpm_handle))
            } else {
                Err(Error::conversion::<TpmHandle, TpmiShHmac>(Some(&tpm_handle)))
            }
    }
}

newtype_in_win!(TpmiDhContext(TpmHandle));

impl From<TpmiShAuthSession> for TpmiDhContext {
    fn from(session_handle: TpmiShAuthSession) -> Self {
        Self(session_handle.0)
    }
}

impl TryFrom<TpmiDhObject> for TpmiDhContext {
    type Error = Error;

    fn try_from(obj_handle: TpmiDhObject) -> Result<Self> {
        if obj_handle.is_transient() {
            return Ok(Self(obj_handle.into()));
        }

        Err(Error::conversion::<TpmiDhObject, TpmiDhContext>(None))
    }
}

impl TryFrom<TpmHandle> for TpmiDhContext {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<Self> {
        if TpmiShAuthSession::try_from(tpm_handle).is_ok()
            || (TpmHandle::TRANSIENT_FIRST..=TpmHandle::TRANSIENT_LAST)
                .contains(&tpm_handle.value()) {
                    Ok(Self(tpm_handle))
                } else {
                    Err(Error::conversion::<TpmHandle, TpmiDhContext>(Some(&tpm_handle)))
                }
    }
}
