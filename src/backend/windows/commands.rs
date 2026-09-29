mod command;
mod response;

use crate::macros::newtype_in_win;
use crate::{Error, Result, types::tpm::TpmSt};

pub(super) use self::command::{Command, CommandHeader, TpmsAuthCommand};
pub(super) use self::response::{Response, ResponseBody, ResponseHeader, TpmsAuthResponse};

newtype_in_win!(TpmiStCommandTag(TpmSt) => u16);

impl TpmiStCommandTag {
    pub(super) const NO_SESSIONS: Self = Self(TpmSt::NO_SESSIONS);
    pub(super) const SESSIONS: Self = Self(TpmSt::SESSIONS);
}

impl TryFrom<u16> for TpmiStCommandTag {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match TpmSt::try_from(value)? {
            TpmSt::NO_SESSIONS => Ok(Self(TpmSt::NO_SESSIONS)),
            TpmSt::SESSIONS => Ok(Self(TpmSt::SESSIONS)),
            _ => Err(Error::conversion::<u16, TpmiStCommandTag>(None)),
        }
    }
}
