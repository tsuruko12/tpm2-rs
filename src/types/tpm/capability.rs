use super::{
    TpmlAlgProperty, TpmlCc, TpmlCca, TpmlEccCurve, TpmlHandle, TpmlPcrSelection,
    TpmlTaggedPcrProperty, TpmlTaggedTpmProperty,
};
use crate::{Error, Result, macros::unknown_tpm_data};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TpmCap {
    Algorithms = 0x0000_0000,
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
    pub(crate) fn value(self) -> u32 {
        self as u32
    }
}

impl TryFrom<u32> for TpmCap {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0x0000_0000 => Ok(Self::Algorithms),
            0x0000_0001 => Ok(Self::Handles),
            0x0000_0002 => Ok(Self::Commands),
            0x0000_0003 => Ok(Self::PPCommands),
            0x0000_0004 => Ok(Self::AuditCommands),
            0x0000_0005 => Ok(Self::Pcrs),
            0x0000_0006 => Ok(Self::TpmProperties),
            0x0000_0007 => Ok(Self::PcrProperties),
            0x0000_0008 => Ok(Self::ECCCurves),
            _ => unknown_tpm_data!(value, "capability type"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CapabilityData {
    Algorithms(TpmlAlgProperty),
    Handles(TpmlHandle),
    Commands(TpmlCca),
    PpCommands(TpmlCc),
    AuditCommands(TpmlCc),
    Pcrs(TpmlPcrSelection),
    TpmProperties(TpmlTaggedTpmProperty),
    PcrProperties(TpmlTaggedPcrProperty),
    EccCurves(TpmlEccCurve),
}
