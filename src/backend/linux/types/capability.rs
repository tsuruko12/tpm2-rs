use tss_esapi::{constants::CapabilityType};

use crate::types::TpmCap;

impl From<TpmCap> for CapabilityType {
    fn from(value: TpmCap) -> Self {
        match value {
            TpmCap::Algs => Self::Algorithms,
            TpmCap::Handles => Self::Handles,
            TpmCap::Commands => Self::Command,
            TpmCap::PPCommands => Self::PpCommands,
            TpmCap::AuditCommands => Self::AuditCommands,
            TpmCap::Pcrs => Self::AssignedPcr,
            TpmCap::TpmProperties => Self::TpmProperties,
            TpmCap::PcrProperties => Self::PcrProperties,
            TpmCap::ECCCurves => Self::EccCurves,
        }
    }
}