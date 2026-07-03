use super::response_code::TPM_RC_FMT1;

pub(crate) type TpmSt = u16;
pub(crate) type TpmCc = u32;

const TPM_RC_FMT1_E_MASK: u32 = 0x3F;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TpmRc(u32);

impl TpmRc {
    pub(crate) fn from_be_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    pub(crate) fn raw(&self) -> u32 {
        self.0
    }

    pub(crate) fn base(&self) -> u32 {
        let raw = self.raw();

        if raw & TPM_RC_FMT1 != 0 {
            TPM_RC_FMT1 | (raw & TPM_RC_FMT1_E_MASK)
        } else {
            raw
        }
    }
}
