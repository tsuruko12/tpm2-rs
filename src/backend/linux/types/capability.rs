use tss_esapi::{constants::CapabilityType, structures::CapabilityData as EsapiCapabilityData};

use crate::{
    Error, Result,
    types::tpm::{CapabilityData, TpmCap},
};

impl From<TpmCap> for CapabilityType {
    fn from(value: TpmCap) -> Self {
        match value {
            TpmCap::Algorithms => Self::Algorithms,
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

    fn try_from(cap_data: EsapiCapabilityData) -> Result<Self> {
        match cap_data {
            EsapiCapabilityData::Algorithms(list) => Ok(Self::Algorithms(list.try_into()?)),
            EsapiCapabilityData::Handles(list) => Ok(Self::Handles(list.into())),
            EsapiCapabilityData::Commands(list) => Ok(Self::Commands(list.try_into()?)),
            EsapiCapabilityData::PpCommands(list) => Ok(Self::PpCommands(list.try_into()?)),
            EsapiCapabilityData::AuditCommands(list) => Ok(Self::AuditCommands(list.try_into()?)),
            EsapiCapabilityData::AssignedPcr(list) => Ok(Self::Pcrs(list.into())),
            EsapiCapabilityData::TpmProperties(list) => Ok(Self::TpmProperties(list.try_into()?)),
            EsapiCapabilityData::PcrProperties(list) => Ok(Self::PcrProperties(list.try_into()?)),
            EsapiCapabilityData::EccCurves(list) => Ok(Self::EccCurves(list.try_into()?)),
            _ => unreachable!("unexpected capability data"),
        }
    }
}
