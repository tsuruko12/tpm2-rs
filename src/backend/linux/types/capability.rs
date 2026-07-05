use tss_esapi::{constants::CapabilityType, structures::CapabilityData as EsapiCapabilityData};

use crate::{
    Error, Result,
    types::{CapabilityData, TpmCap},
};

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

impl TryFrom<EsapiCapabilityData> for CapabilityData {
    type Error = Error;

    fn try_from(value: EsapiCapabilityData) -> Result<Self> {
        match value {
            EsapiCapabilityData::Algorithms(list) => Ok(Self::Algs(list.try_into()?)),
            EsapiCapabilityData::Handles(list) => Ok(Self::Handles(list.into())),
            EsapiCapabilityData::Commands(list) => Ok(Self::Commands(list.into())),
            EsapiCapabilityData::PpCommands(list) => Ok(Self::PpCommands(list.into())),
            EsapiCapabilityData::AuditCommands(list) => Ok(Self::AuditCommands(list.into())),
            EsapiCapabilityData::AssignedPcr(list) => Ok(Self::Pcrs(list.into())),
            EsapiCapabilityData::TpmProperties(list) => Ok(Self::TpmProperties(list.try_into()?)),
            EsapiCapabilityData::PcrProperties(list) => Ok(Self::PcrProperties(list.try_into()?)),
            EsapiCapabilityData::EccCurves(list) => Ok(Self::EccCurves(list.try_into()?)),
            _ => unreachable!("unexpected capability data"),
        }
    }
}
