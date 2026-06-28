const RC_VER1: u32 = 0x100;

pub(crate) const TPM_RC_INITIALIZE: u32 = RC_VER1 + 0x000;
pub(crate) const TPM_RC_FAILURE: u32 = RC_VER1 + 0x001;
pub(crate) const TPM_RC_DISABLED: u32 = RC_VER1 + 0x020;
pub(crate) const TPM_RC_POLICY: u32 = RC_VER1 + 0x026;
pub(crate) const TPM_RC_PCR: u32 = RC_VER1 + 0x027;
pub(crate) const TPM_RC_PCR_CHANGED: u32 = RC_VER1 + 0x028;
pub(crate) const TPM_RC_AUTH_UNAVAILABLE: u32 = RC_VER1 + 0x02F;
pub(crate) const TPM_RC_REBOOT: u32 = RC_VER1 + 0x030;
pub(crate) const TPM_RC_COMMAND_CODE: u32 = RC_VER1 + 0x043;
