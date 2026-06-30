pub(crate) type TpmiStCommandTag = u16;
pub(crate) type Uint16 = u16;
pub(crate) type Uint32 = u32;
pub(crate) type TpmSt = u16;
pub(crate) type TpmCc = u32;
pub(crate) type TpmRc = u32;

pub(crate) const TPM_ST_RSP_COMMAND: TpmSt = 0x00C4;
pub(crate) const TPM_ST_NO_SESSIONS: TpmiStCommandTag = 0x8001;
pub(crate) const TPM_ST_SESSIONS: TpmiStCommandTag = 0x8002;
