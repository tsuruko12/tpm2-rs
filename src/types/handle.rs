#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TpmlHandle {
    items: Vec<TpmHandle>,
}

impl TpmlHandle {
    pub(crate) fn new(items: Vec<TpmHandle>) -> Self {
        Self { items }
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct TpmHandle(u32);

impl TpmHandle {
    pub(crate) fn new(value: u32) -> Self {
        Self(value)
    }

    pub(crate) fn value(self) -> u32 {
        self.0
    }
}

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
