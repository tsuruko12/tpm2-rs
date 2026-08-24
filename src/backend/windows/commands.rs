mod command;
mod response;

use crate::macros::newtype_in_win;
use crate::{
    Error, Result,
    macros::newtype,
};

pub(super) use self::command::{Command, CommandHeader, TpmsAuthCommand};
pub(super) use self::response::{Response, ResponseBody, ResponseHeader, TpmsAuthResponse};

newtype!(TpmSt(u16));

impl TpmSt {
    pub(super) const RSP_COMMAND: Self = Self(0x00C4);
    pub(super) const NULL: Self = Self(0x8000);
    pub(super) const NO_SESSIONS: Self = Self(0x8001);
    pub(super) const SESSIONS: Self = Self(0x8002);

    pub(super) const ATTEST_NV: Self = Self(0x8014);
    pub(super) const ATTEST_COMMAND_AUDIT: Self = Self(0x8015);
    pub(super) const ATTEST_SESSION_AUDIT: Self = Self(0x8016);
    pub(super) const ATTEST_CERTIFY: Self = Self(0x8017);
    pub(super) const ATTEST_QUOTE: Self = Self(0x8018);
    pub(super) const ATTEST_TIME: Self = Self(0x8019);
    pub(super) const ATTEST_CREATION: Self = Self(0x801A);
    pub(super) const ATTEST_NV_DIGEST: Self = Self(0x801C);

    pub(super) const CREATION: Self = Self(0x8021);
    pub(super) const VERIFIED: Self = Self(0x8022);
    pub(super) const AUTH_SECRET: Self = Self(0x8023);
    pub(super) const HASHCHECK: Self = Self(0x8024);
    pub(super) const AUTH_SIGNED: Self = Self(0x8025);
    pub(super) const FU_MANIFEST: Self = Self(0x8029);
}

impl TryFrom<u16> for TpmSt {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match Self(value) {
            Self::RSP_COMMAND
            | Self::NULL
            | Self::NO_SESSIONS
            | Self::SESSIONS
            | Self::ATTEST_NV
            | Self::ATTEST_COMMAND_AUDIT
            | Self::ATTEST_SESSION_AUDIT
            | Self::ATTEST_CERTIFY
            | Self::ATTEST_QUOTE
            | Self::ATTEST_TIME
            | Self::ATTEST_CREATION
            | Self::ATTEST_NV_DIGEST
            | Self::CREATION
            | Self::VERIFIED
            | Self::AUTH_SECRET
            | Self::HASHCHECK
            | Self::AUTH_SIGNED
            | Self::FU_MANIFEST => Ok(Self(value)),
            _ => Err(Error::conversion::<u16, TpmSt>(None)),
        }
    }
}

newtype_in_win!(TpmiStCommandTag(TpmSt) => u16);

impl TpmiStCommandTag {
    pub(super) const NO_SESSIONS: Self = Self(TpmSt::NO_SESSIONS);
    pub(super) const SESSIONS: Self = Self(TpmSt::SESSIONS);
}

impl TryFrom<u16> for TpmiStCommandTag {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match TpmSt(value) {
            TpmSt::NO_SESSIONS | TpmSt::SESSIONS => Ok(Self(TpmSt(value))),
            _ => Err(Error::conversion::<u16, TpmiStCommandTag>(None)),
        }
    }
}