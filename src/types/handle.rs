pub(crate) type TpmHandle = u32;

pub(crate) type TpmHt = u8;

pub(crate) const TPM_HT_PCR: TpmHt = 0x00;
pub(crate) const TPM_HT_NV_INDEX: TpmHt = 0x01;
pub(crate) const TPM_HT_HMAC_SESSION: TpmHt = 0x02;
pub(crate) const TPM_HT_LOADED_SESSION: TpmHt = 0x02;
pub(crate) const TPM_HT_POLICY_SESSION: TpmHt = 0x03;
pub(crate) const TPM_HT_SAVED_SESSION: TpmHt = 0x03;
pub(crate) const TPM_HT_EXTERNAL_NV: TpmHt = 0x11;
pub(crate) const TPM_HT_PERMANENT_NV: TpmHt = 0x12;
pub(crate) const TPM_HT_PERMANENT: TpmHt = 0x40;
pub(crate) const TPM_HT_TRANSIENT: TpmHt = 0x80;
pub(crate) const TPM_HT_PERSISTENT: TpmHt = 0x81;
pub(crate) const TPM_HT_AC: TpmHt = 0x90;
