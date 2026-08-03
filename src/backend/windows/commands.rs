mod command;
mod response;

use crate::{
    Error, Result,
    macros::newtype,
};

pub(super) use self::command::{Command, TpmsAuthCommand};
pub(super) use self::response::{ResponseHeader, TpmsAuthResponse};

pub(crate) const TPM_HEADER_SIZE: usize = 10;

newtype!(TpmSt(u16));

impl TpmSt {
    pub(crate) const RSP_COMMAND: Self = Self(0x00C4);
    pub(crate) const NULL: Self = Self(0x8000);
    pub(crate) const NO_SESSIONS: Self = Self(0x8001);
    pub(crate) const SESSIONS: Self = Self(0x8002);

    pub(crate) const ATTEST_NV: Self = Self(0x8014);
    pub(crate) const ATTEST_COMMAND_AUDIT: Self = Self(0x8015);
    pub(crate) const ATTEST_SESSION_AUDIT: Self = Self(0x8016);
    pub(crate) const ATTEST_CERTIFY: Self = Self(0x8017);
    pub(crate) const ATTEST_QUOTE: Self = Self(0x8018);
    pub(crate) const ATTEST_TIME: Self = Self(0x8019);
    pub(crate) const ATTEST_CREATION: Self = Self(0x801A);
    pub(crate) const ATTEST_NV_DIGEST: Self = Self(0x801C);

    pub(crate) const CREATION: Self = Self(0x8021);
    pub(crate) const VERIFIED: Self = Self(0x8022);
    pub(crate) const AUTH_SECRET: Self = Self(0x8023);
    pub(crate) const HASHCHECK: Self = Self(0x8024);
    pub(crate) const AUTH_SIGNED: Self = Self(0x8025);
    pub(crate) const FU_MANIFEST: Self = Self(0x8029);
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct TpmiStCommandTag(TpmSt);

impl TpmiStCommandTag {
    pub(crate) const NO_SESSIONS: Self = Self(TpmSt::NO_SESSIONS);
    pub(crate) const SESSIONS: Self = Self(TpmSt::SESSIONS);

    pub(crate) fn raw(self) -> u16 {
        self.0.raw()
    }
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

impl std::fmt::Debug for TpmiStCommandTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::NO_SESSIONS => f.write_str("NO_SESSIONS"),
            Self::SESSIONS => f.write_str("SESSIONS"),
            _ => write!(f, "UNKNOWN ({:#010x})", self.raw()),
        }
    }
}
