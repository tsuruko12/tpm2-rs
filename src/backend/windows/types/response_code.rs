use crate::macros::newtype;

newtype!(TpmRc(u32));

impl TpmRc {
    const VER1: u32 = 0x100;
    const FMT1: u32 = 0x080;
    const FMT1_ERROR_MASK: u32 = 0x3F;
    const WARN: u32 = 0x900;

    pub(crate) const SUCCESS: Self = Self(0x000);
    pub(crate) const BAD_TAG: Self = Self(0x01E);

    // Format Zero
    pub(crate) const INITIALIZE: Self = Self(Self::VER1 + 0x000);
    pub(crate) const FAILURE: Self = Self(Self::VER1 + 0x001);
    pub(crate) const SEQUENCE: Self = Self(Self::VER1 + 0x003);
    pub(crate) const PRIVATE: Self = Self(Self::VER1 + 0x00B);
    pub(crate) const HMAC: Self = Self(Self::VER1 + 0x019);
    pub(crate) const DISABLED: Self = Self(Self::VER1 + 0x020);
    pub(crate) const EXCLUSIVE: Self = Self(Self::VER1 + 0x021);
    pub(crate) const AUTH_TYPE: Self = Self(Self::VER1 + 0x024);
    pub(crate) const AUTH_MISSING: Self = Self(Self::VER1 + 0x025);
    pub(crate) const POLICY: Self = Self(Self::VER1 + 0x026);
    pub(crate) const PCR: Self = Self(Self::VER1 + 0x027);
    pub(crate) const PCR_CHANGED: Self = Self(Self::VER1 + 0x028);
    pub(crate) const UPGRADE: Self = Self(Self::VER1 + 0x02D);
    pub(crate) const TOO_MANY_CONTEXTS: Self = Self(Self::VER1 + 0x02E);
    pub(crate) const AUTH_UNAVAILABLE: Self = Self(Self::VER1 + 0x02F);
    pub(crate) const REBOOT: Self = Self(Self::VER1 + 0x030);
    pub(crate) const UNBALANCED: Self = Self(Self::VER1 + 0x031);
    pub(crate) const COMMAND_SIZE: Self = Self(Self::VER1 + 0x042);
    pub(crate) const COMMAND_CODE: Self = Self(Self::VER1 + 0x043);
    pub(crate) const AUTHSIZE: Self = Self(Self::VER1 + 0x044);
    pub(crate) const AUTH_CONTEXT: Self = Self(Self::VER1 + 0x045);
    pub(crate) const NV_RANGE: Self = Self(Self::VER1 + 0x046);
    pub(crate) const NV_SIZE: Self = Self(Self::VER1 + 0x047);
    pub(crate) const NV_LOCKED: Self = Self(Self::VER1 + 0x048);
    pub(crate) const NV_AUTHORIZATION: Self = Self(Self::VER1 + 0x049);
    pub(crate) const NV_UNINITIALIZED: Self = Self(Self::VER1 + 0x04A);
    pub(crate) const NV_SPACE: Self = Self(Self::VER1 + 0x04B);
    pub(crate) const NV_DEFINED: Self = Self(Self::VER1 + 0x04C);
    pub(crate) const BAD_CONTEXT: Self = Self(Self::VER1 + 0x050);
    pub(crate) const CPHASH: Self = Self(Self::VER1 + 0x051);
    pub(crate) const PARENT: Self = Self(Self::VER1 + 0x052);
    pub(crate) const NEEDS_TEST: Self = Self(Self::VER1 + 0x053);
    pub(crate) const NO_RESULT: Self = Self(Self::VER1 + 0x054);
    pub(crate) const SENSITIVE: Self = Self(Self::VER1 + 0x055);
    pub(crate) const READ_ONLY: Self = Self(Self::VER1 + 0x056);
    pub(crate) const MAX_FM0: Self = Self(Self::VER1 + 0x07F);

    // Format One
    pub(crate) const ASYMMETRIC: Self = Self(Self::FMT1 + 0x001);
    pub(crate) const ATTRIBUTES: Self = Self(Self::FMT1 + 0x002);
    pub(crate) const HASH: Self = Self(Self::FMT1 + 0x003);
    pub(crate) const VALUE: Self = Self(Self::FMT1 + 0x004);
    pub(crate) const HIERARCHY: Self = Self(Self::FMT1 + 0x005);
    pub(crate) const KEY_SIZE: Self = Self(Self::FMT1 + 0x007);
    pub(crate) const MGF: Self = Self(Self::FMT1 + 0x008);
    pub(crate) const MODE: Self = Self(Self::FMT1 + 0x009);
    pub(crate) const TYPE: Self = Self(Self::FMT1 + 0x00A);
    pub(crate) const HANDLE: Self = Self(Self::FMT1 + 0x00B);
    pub(crate) const KDF: Self = Self(Self::FMT1 + 0x00C);
    pub(crate) const RANGE: Self = Self(Self::FMT1 + 0x00D);
    pub(crate) const AUTH_FAIL: Self = Self(Self::FMT1 + 0x00E);
    pub(crate) const NONCE: Self = Self(Self::FMT1 + 0x00F);
    pub(crate) const PP: Self = Self(Self::FMT1 + 0x010);
    pub(crate) const SCHEME: Self = Self(Self::FMT1 + 0x012);
    pub(crate) const SIZE: Self = Self(Self::FMT1 + 0x015);
    pub(crate) const SYMMETRIC: Self = Self(Self::FMT1 + 0x016);
    pub(crate) const TAG: Self = Self(Self::FMT1 + 0x017);
    pub(crate) const SELECTOR: Self = Self(Self::FMT1 + 0x018);
    pub(crate) const INSUFFICIENT: Self = Self(Self::FMT1 + 0x01A);
    pub(crate) const SIGNATURE: Self = Self(Self::FMT1 + 0x01B);
    pub(crate) const KEY: Self = Self(Self::FMT1 + 0x01C);
    pub(crate) const POLICY_FAIL: Self = Self(Self::FMT1 + 0x01D);
    pub(crate) const INTEGRITY: Self = Self(Self::FMT1 + 0x01F);
    pub(crate) const TICKET: Self = Self(Self::FMT1 + 0x020);
    pub(crate) const RESERVED_BITS: Self = Self(Self::FMT1 + 0x021);
    pub(crate) const BAD_AUTH: Self = Self(Self::FMT1 + 0x022);
    pub(crate) const EXPIRED: Self = Self(Self::FMT1 + 0x023);
    pub(crate) const POLICY_CC: Self = Self(Self::FMT1 + 0x024);
    pub(crate) const BINDING: Self = Self(Self::FMT1 + 0x025);
    pub(crate) const CURVE: Self = Self(Self::FMT1 + 0x026);
    pub(crate) const ECC_POINT: Self = Self(Self::FMT1 + 0x027);
    pub(crate) const FW_LIMITED: Self = Self(Self::FMT1 + 0x028);
    pub(crate) const SVN_LIMITED: Self = Self(Self::FMT1 + 0x029);
    pub(crate) const PARMS: Self = Self(Self::FMT1 + 0x02A);
    pub(crate) const EXT_MU: Self = Self(Self::FMT1 + 0x02B);
    pub(crate) const ONE_SHOT_SIGNATURE: Self = Self(Self::FMT1 + 0x02C);
    pub(crate) const SIGN_CONTEXT_KEY: Self = Self(Self::FMT1 + 0x02D);
    pub(crate) const CHANNEL: Self = Self(Self::FMT1 + 0x030);
    pub(crate) const CHANNEL_KEY: Self = Self(Self::FMT1 + 0x031);

    // Warnings
    pub(crate) const CONTEXT_GAP: Self = Self(Self::WARN + 0x001);
    pub(crate) const OBJECT_MEMORY: Self = Self(Self::WARN + 0x002);
    pub(crate) const SESSION_MEMORY: Self = Self(Self::WARN + 0x003);
    pub(crate) const MEMORY: Self = Self(Self::WARN + 0x004);
    pub(crate) const SESSION_HANDLES: Self = Self(Self::WARN + 0x005);
    pub(crate) const OBJECT_HANDLES: Self = Self(Self::WARN + 0x006);
    pub(crate) const LOCALITY: Self = Self(Self::WARN + 0x007);
    pub(crate) const YIELDED: Self = Self(Self::WARN + 0x008);
    pub(crate) const CANCELED: Self = Self(Self::WARN + 0x009);
    pub(crate) const TESTING: Self = Self(Self::WARN + 0x00A);
    pub(crate) const REFERENCE_H0: Self = Self(Self::WARN + 0x010);
    pub(crate) const REFERENCE_H1: Self = Self(Self::WARN + 0x011);
    pub(crate) const REFERENCE_H2: Self = Self(Self::WARN + 0x012);
    pub(crate) const REFERENCE_H3: Self = Self(Self::WARN + 0x013);
    pub(crate) const REFERENCE_H4: Self = Self(Self::WARN + 0x014);
    pub(crate) const REFERENCE_H5: Self = Self(Self::WARN + 0x015);
    pub(crate) const REFERENCE_H6: Self = Self(Self::WARN + 0x016);
    pub(crate) const REFERENCE_S0: Self = Self(Self::WARN + 0x018);
    pub(crate) const REFERENCE_S1: Self = Self(Self::WARN + 0x019);
    pub(crate) const REFERENCE_S2: Self = Self(Self::WARN + 0x01A);
    pub(crate) const REFERENCE_S3: Self = Self(Self::WARN + 0x01B);
    pub(crate) const REFERENCE_S4: Self = Self(Self::WARN + 0x01C);
    pub(crate) const REFERENCE_S5: Self = Self(Self::WARN + 0x01D);
    pub(crate) const REFERENCE_S6: Self = Self(Self::WARN + 0x01E);
    pub(crate) const NV_RATE: Self = Self(Self::WARN + 0x020);
    pub(crate) const LOCKOUT: Self = Self(Self::WARN + 0x021);
    pub(crate) const RETRY: Self = Self(Self::WARN + 0x022);
    pub(crate) const NV_UNAVAILABLE: Self = Self(Self::WARN + 0x023);
    pub(crate) const NOT_USED: Self = Self(Self::WARN + 0x07F);

    // Format One handle, parameter, session, and index modifiers
    const H: u32 = 0x000;
    const P: u32 = 0x040;
    const S: u32 = 0x800;
    const INDEX_1: u32 = 0x100;
    const INDEX_2: u32 = 0x200;
    const INDEX_3: u32 = 0x300;
    const INDEX_4: u32 = 0x400;
    const INDEX_5: u32 = 0x500;
    const INDEX_6: u32 = 0x600;
    const INDEX_7: u32 = 0x700;
    const INDEX_8: u32 = 0x800;
    const INDEX_9: u32 = 0x900;
    const INDEX_A: u32 = 0xA00;
    const INDEX_B: u32 = 0xB00;
    const INDEX_C: u32 = 0xC00;
    const INDEX_D: u32 = 0xD00;
    const INDEX_E: u32 = 0xE00;
    const INDEX_F: u32 = 0xF00;
    const N_MASK: u32 = 0xF00;

    pub(crate) fn base(self) -> Self {
        let raw = self.raw();

        if raw & Self::FMT1 != 0 {
            Self(Self::FMT1 | (raw & Self::FMT1_ERROR_MASK))
        } else {
            self
        }
    }
}

impl From<u32> for TpmRc {
    fn from(raw: u32) -> Self {
        Self(raw)
    }
}