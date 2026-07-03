use crate::{Error, Result};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TpmCap {
    Algs = 0x0000_0000,
    Handles = 0x0000_0001,
    Commands = 0x0000_0002,
    PPCommands = 0x0000_0003,
    AuditCommands = 0x0000_0004,
    Pcrs = 0x0000_0005,
    TpmProperties = 0x0000_0006,
    PcrProperties = 0x0000_0007,
    ECCCurves = 0x0000_0008,
}

impl TpmCap {
    pub(crate) const fn to_be_bytes(self) -> [u8; 4] {
        (self as u32).to_be_bytes()
    }
}

impl TryFrom<u32> for TpmCap {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0x0000_0000 => Ok(Self::Algs),
            0x0000_0001 => Ok(Self::Handles),
            0x0000_0002 => Ok(Self::Commands),
            0x0000_0003 => Ok(Self::PPCommands),
            0x0000_0004 => Ok(Self::AuditCommands),
            0x0000_0005 => Ok(Self::Pcrs),
            0x0000_0006 => Ok(Self::TpmProperties),
            0x0000_0007 => Ok(Self::PcrProperties),
            0x0000_0008 => Ok(Self::ECCCurves),
            _ => Err(Error::Internal("unsupported TPM capability type")),
        }
    }
}
