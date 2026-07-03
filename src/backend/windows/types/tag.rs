use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TpmsTaggedProperty {
    property: TpmPt,
    value: u32,
}

impl TpmsTaggedProperty {
    pub(crate) fn new(property: TpmPt, value: u32) -> Self {
        Self { property, value }
    }

    pub(crate) fn property(self) -> TpmPt {
        self.property
    }

    pub(crate) fn value(self) -> u32 {
        self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TpmsTaggedPcrSelect {
    tag: TpmPtPcr,
    pcr_select: Vec<u8>,
}

impl TpmsTaggedPcrSelect {
    pub(crate) fn new(tag: TpmPtPcr, pcr_select: Vec<u8>) -> Self {
        Self { tag, pcr_select }
    }

    pub(crate) fn tag(&self) -> TpmPtPcr {
        self.tag
    }

    pub(crate) fn pcr_select(&self) -> &[u8] {
        &self.pcr_select
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TpmPt {
    None = 0x0000_0000,

    // Fixed properties
    FamilyIndicator = 0x0000_0100,
    Level = 0x0000_0101,
    Revision = 0x0000_0102,
    Errata = 0x0000_0103,
    Year = 0x0000_0104,
    Manufacturer = 0x0000_0105,
    VendorString1 = 0x0000_0106,
    VendorString2 = 0x0000_0107,
    VendorString3 = 0x0000_0108,
    VendorString4 = 0x0000_0109,
    VendorTpmType = 0x0000_010A,
    FirmwareVersion1 = 0x0000_010B,
    FirmwareVersion2 = 0x0000_010C,
    InputBuffer = 0x0000_010D,
    HrTransientMin = 0x0000_010E,
    HrPersistentMin = 0x0000_010F,
    HrLoadedMin = 0x0000_0110,
    ActiveSessionsMax = 0x0000_0111,
    PcrCount = 0x0000_0112,
    PcrSelectMin = 0x0000_0113,
    ContextGapMax = 0x0000_0114,
    NvCountersMax = 0x0000_0116,
    NvIndexMax = 0x0000_0117,
    Memory = 0x0000_0118,
    ClockUpdate = 0x0000_0119,
    ContextHash = 0x0000_011A,
    ContextSym = 0x0000_011B,
    ContextSymSize = 0x0000_011C,
    OrderlyCount = 0x0000_011D,
    MaxCommandSize = 0x0000_011E,
    MaxResponseSize = 0x0000_011F,
    MaxDigest = 0x0000_0120,
    MaxObjectContext = 0x0000_0121,
    MaxSessionContext = 0x0000_0122,
    PsFamilyIndicator = 0x0000_0123,
    PsLevel = 0x0000_0124,
    PsRevision = 0x0000_0125,
    PsDayOfYear = 0x0000_0126,
    PsYear = 0x0000_0127,
    SplitMax = 0x0000_0128,
    TotalCommands = 0x0000_0129,
    LibraryCommands = 0x0000_012A,
    VendorCommands = 0x0000_012B,
    NvBufferMax = 0x0000_012C,
    Modes = 0x0000_012D,
    MaxCapBuffer = 0x0000_012E,
    FirmwareSvn = 0x0000_012F,
    FirmwareMaxSvn = 0x0000_0130,
    MlParameterSets = 0x0000_0131,

    // Variable properties
    Permanent = 0x0000_0200,
    StartupClear = 0x0000_0201,
    HrNvIndex = 0x0000_0202,
    HrLoaded = 0x0000_0203,
    HrLoadedAvail = 0x0000_0204,
    HrActive = 0x0000_0205,
    HrActiveAvail = 0x0000_0206,
    HrTransientAvail = 0x0000_0207,
    HrPersistent = 0x0000_0208,
    HrPersistentAvail = 0x0000_0209,
    NvCounters = 0x0000_020A,
    NvCountersAvail = 0x0000_020B,
    AlgorithmSet = 0x0000_020C,
    LoadedCurves = 0x0000_020D,
    LockoutCounter = 0x0000_020E,
    MaxAuthFail = 0x0000_020F,
    LockoutInterval = 0x0000_0210,
    LockoutRecovery = 0x0000_0211,
    NvWriteRecovery = 0x0000_0212,
    AuditCounter0 = 0x0000_0213,
    AuditCounter1 = 0x0000_0214,
}

impl TryFrom<u32> for TpmPt {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0x0000_0000 => Ok(Self::None),
            0x0000_0100 => Ok(Self::FamilyIndicator),
            0x0000_0101 => Ok(Self::Level),
            0x0000_0102 => Ok(Self::Revision),
            0x0000_0103 => Ok(Self::Errata),
            0x0000_0104 => Ok(Self::Year),
            0x0000_0105 => Ok(Self::Manufacturer),
            0x0000_0106 => Ok(Self::VendorString1),
            0x0000_0107 => Ok(Self::VendorString2),
            0x0000_0108 => Ok(Self::VendorString3),
            0x0000_0109 => Ok(Self::VendorString4),
            0x0000_010A => Ok(Self::VendorTpmType),
            0x0000_010B => Ok(Self::FirmwareVersion1),
            0x0000_010C => Ok(Self::FirmwareVersion2),
            0x0000_010D => Ok(Self::InputBuffer),
            0x0000_010E => Ok(Self::HrTransientMin),
            0x0000_010F => Ok(Self::HrPersistentMin),
            0x0000_0110 => Ok(Self::HrLoadedMin),
            0x0000_0111 => Ok(Self::ActiveSessionsMax),
            0x0000_0112 => Ok(Self::PcrCount),
            0x0000_0113 => Ok(Self::PcrSelectMin),
            0x0000_0114 => Ok(Self::ContextGapMax),
            0x0000_0116 => Ok(Self::NvCountersMax),
            0x0000_0117 => Ok(Self::NvIndexMax),
            0x0000_0118 => Ok(Self::Memory),
            0x0000_0119 => Ok(Self::ClockUpdate),
            0x0000_011A => Ok(Self::ContextHash),
            0x0000_011B => Ok(Self::ContextSym),
            0x0000_011C => Ok(Self::ContextSymSize),
            0x0000_011D => Ok(Self::OrderlyCount),
            0x0000_011E => Ok(Self::MaxCommandSize),
            0x0000_011F => Ok(Self::MaxResponseSize),
            0x0000_0120 => Ok(Self::MaxDigest),
            0x0000_0121 => Ok(Self::MaxObjectContext),
            0x0000_0122 => Ok(Self::MaxSessionContext),
            0x0000_0123 => Ok(Self::PsFamilyIndicator),
            0x0000_0124 => Ok(Self::PsLevel),
            0x0000_0125 => Ok(Self::PsRevision),
            0x0000_0126 => Ok(Self::PsDayOfYear),
            0x0000_0127 => Ok(Self::PsYear),
            0x0000_0128 => Ok(Self::SplitMax),
            0x0000_0129 => Ok(Self::TotalCommands),
            0x0000_012A => Ok(Self::LibraryCommands),
            0x0000_012B => Ok(Self::VendorCommands),
            0x0000_012C => Ok(Self::NvBufferMax),
            0x0000_012D => Ok(Self::Modes),
            0x0000_012E => Ok(Self::MaxCapBuffer),
            0x0000_012F => Ok(Self::FirmwareSvn),
            0x0000_0130 => Ok(Self::FirmwareMaxSvn),
            0x0000_0131 => Ok(Self::MlParameterSets),
            0x0000_0200 => Ok(Self::Permanent),
            0x0000_0201 => Ok(Self::StartupClear),
            0x0000_0202 => Ok(Self::HrNvIndex),
            0x0000_0203 => Ok(Self::HrLoaded),
            0x0000_0204 => Ok(Self::HrLoadedAvail),
            0x0000_0205 => Ok(Self::HrActive),
            0x0000_0206 => Ok(Self::HrActiveAvail),
            0x0000_0207 => Ok(Self::HrTransientAvail),
            0x0000_0208 => Ok(Self::HrPersistent),
            0x0000_0209 => Ok(Self::HrPersistentAvail),
            0x0000_020A => Ok(Self::NvCounters),
            0x0000_020B => Ok(Self::NvCountersAvail),
            0x0000_020C => Ok(Self::AlgorithmSet),
            0x0000_020D => Ok(Self::LoadedCurves),
            0x0000_020E => Ok(Self::LockoutCounter),
            0x0000_020F => Ok(Self::MaxAuthFail),
            0x0000_0210 => Ok(Self::LockoutInterval),
            0x0000_0211 => Ok(Self::LockoutRecovery),
            0x0000_0212 => Ok(Self::NvWriteRecovery),
            0x0000_0213 => Ok(Self::AuditCounter0),
            0x0000_0214 => Ok(Self::AuditCounter1),
            _ => Err(Error::Internal("unsupported TPM property")),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TpmPtPcr {
    PcrSave = 0x0000_0000,
    PcrExtendL0 = 0x0000_0001,
    PcrResetL0 = 0x0000_0002,
    PcrExtendL1 = 0x0000_0003,
    PcrResetL1 = 0x0000_0004,
    PcrExtendL2 = 0x0000_0005,
    PcrResetL2 = 0x0000_0006,
    PcrExtendL3 = 0x0000_0007,
    PcrResetL3 = 0x0000_0008,
    PcrExtendL4 = 0x0000_0009,
    PcrResetL4 = 0x0000_000A,
    PcrNoIncrement = 0x0000_0011,
    PcrDrtmReset = 0x0000_0012,
    PcrPolicy = 0x0000_0013,
    PcrAuth = 0x0000_0014,
}

impl TryFrom<u32> for TpmPtPcr {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0x0000_0000 => Ok(Self::PcrSave),
            0x0000_0001 => Ok(Self::PcrExtendL0),
            0x0000_0002 => Ok(Self::PcrResetL0),
            0x0000_0003 => Ok(Self::PcrExtendL1),
            0x0000_0004 => Ok(Self::PcrResetL1),
            0x0000_0005 => Ok(Self::PcrExtendL2),
            0x0000_0006 => Ok(Self::PcrResetL2),
            0x0000_0007 => Ok(Self::PcrExtendL3),
            0x0000_0008 => Ok(Self::PcrResetL3),
            0x0000_0009 => Ok(Self::PcrExtendL4),
            0x0000_000A => Ok(Self::PcrResetL4),
            0x0000_0011 => Ok(Self::PcrNoIncrement),
            0x0000_0012 => Ok(Self::PcrDrtmReset),
            0x0000_0013 => Ok(Self::PcrPolicy),
            0x0000_0014 => Ok(Self::PcrAuth),
            _ => Err(Error::Internal("unsupported TPM PCR property")),
        }
    }
}
