use super::{
    algorithm::TpmAlgId,
    attribute::TpmaCc,
    ecc::TpmEccCurve,
    handle::TpmHandle,
    policy::TpmsPcrSelection,
    tag::{TpmsTaggedPcrSelect, TpmsTaggedProperty},
    tpm::TpmCc,
    unmarshal_algs, unmarshal_cc, unmarshal_cca, unmarshal_ecc_curves,
    unmarshal_handles, unmarshal_pcr_properties, unmarshal_pcrs, unmarshal_tpm_properties,
};
use crate::{Error, Result, types::TpmCap};

#[derive(Debug)]
pub(crate) enum CapabilityData {
    Algs(Vec<TpmAlgId>),
    Handles(Vec<TpmHandle>),
    Commands(Vec<TpmaCc>),
    PpCommands(Vec<TpmCc>),
    AuditCommands(Vec<TpmCc>),
    Pcrs(Vec<TpmsPcrSelection>),
    TpmProperties(Vec<TpmsTaggedProperty>),
    PcrProperties(Vec<TpmsTaggedPcrSelect>),
    EccCurves(Vec<TpmEccCurve>),
}

impl CapabilityData {
    pub(crate) fn unmarshal(bytes: &[u8], capability: TpmCap) -> Result<Self> {
        let count = bytes
            .get(..4)
            .ok_or(Error::Internal("TPM capability list is missing its count"))?;
        let count = u32::from_be_bytes(count.try_into().unwrap()) as usize;
        let body = &bytes[4..];

        match capability {
            TpmCap::Algs => Ok(Self::Algs(unmarshal_algs(body, count)?)),
            TpmCap::Handles => Ok(Self::Handles(unmarshal_handles(body, count)?)),
            TpmCap::Commands => Ok(Self::Commands(unmarshal_cca(body, count)?)),
            TpmCap::PPCommands => Ok(Self::PpCommands(unmarshal_cc(body, count)?)),
            TpmCap::AuditCommands => Ok(Self::AuditCommands(unmarshal_cc(body, count)?)),
            TpmCap::Pcrs => Ok(Self::Pcrs(unmarshal_pcrs(body, count)?)),
            TpmCap::TpmProperties => {
                Ok(Self::TpmProperties(unmarshal_tpm_properties(body, count)?))
            }
            TpmCap::PcrProperties => {
                Ok(Self::PcrProperties(unmarshal_pcr_properties(body, count)?))
            }
            TpmCap::ECCCurves => Ok(Self::EccCurves(unmarshal_ecc_curves(body, count)?)),
        }
    }
}
