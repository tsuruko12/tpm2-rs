mod commands;
mod context;
mod error;
mod types;
mod wire;

use crate::macros::newtype_in_win;

pub(crate) use self::context::Context;

// sessions are flushed in submit when CONTINUE_SESSION is set, otherwise call explicitly

newtype_in_win!(TpmRc(u32));

impl TpmRc {
    const VER1: u32 = 0x100;
    const FMT1: u32 = 0x080;
    const WARN: u32 = 0x900;
    const FMT1_ERROR_MASK: u32 = 0x3F;

    const SUCCESS: Self = Self(0x000);
    const BAD_TAG: Self = Self(0x01E);

    // Format Zero
    const INITIALIZE: Self = Self(Self::VER1 + 0x000);
    const FAILURE: Self = Self(Self::VER1 + 0x001);
    const SEQUENCE: Self = Self(Self::VER1 + 0x003);
    const PRIVATE: Self = Self(Self::VER1 + 0x00B);
    const HMAC: Self = Self(Self::VER1 + 0x019);
    const DISABLED: Self = Self(Self::VER1 + 0x020);
    const EXCLUSIVE: Self = Self(Self::VER1 + 0x021);
    const AUTH_TYPE: Self = Self(Self::VER1 + 0x024);
    const AUTH_MISSING: Self = Self(Self::VER1 + 0x025);
    const POLICY: Self = Self(Self::VER1 + 0x026);
    const PCR: Self = Self(Self::VER1 + 0x027);
    const PCR_CHANGED: Self = Self(Self::VER1 + 0x028);
    const UPGRADE: Self = Self(Self::VER1 + 0x02D);
    const TOO_MANY_CONTEXTS: Self = Self(Self::VER1 + 0x02E);
    const AUTH_UNAVAILABLE: Self = Self(Self::VER1 + 0x02F);
    const REBOOT: Self = Self(Self::VER1 + 0x030);
    const UNBALANCED: Self = Self(Self::VER1 + 0x031);
    const COMMAND_SIZE: Self = Self(Self::VER1 + 0x042);
    const COMMAND_CODE: Self = Self(Self::VER1 + 0x043);
    const AUTHSIZE: Self = Self(Self::VER1 + 0x044);
    const AUTH_CONTEXT: Self = Self(Self::VER1 + 0x045);
    const NV_RANGE: Self = Self(Self::VER1 + 0x046);
    const NV_SIZE: Self = Self(Self::VER1 + 0x047);
    const NV_LOCKED: Self = Self(Self::VER1 + 0x048);
    const NV_AUTHORIZATION: Self = Self(Self::VER1 + 0x049);
    const NV_UNINITIALIZED: Self = Self(Self::VER1 + 0x04A);
    const NV_SPACE: Self = Self(Self::VER1 + 0x04B);
    const NV_DEFINED: Self = Self(Self::VER1 + 0x04C);
    const BAD_CONTEXT: Self = Self(Self::VER1 + 0x050);
    const CPHASH: Self = Self(Self::VER1 + 0x051);
    const PARENT: Self = Self(Self::VER1 + 0x052);
    const NEEDS_TEST: Self = Self(Self::VER1 + 0x053);
    const NO_RESULT: Self = Self(Self::VER1 + 0x054);
    const SENSITIVE: Self = Self(Self::VER1 + 0x055);
    const READ_ONLY: Self = Self(Self::VER1 + 0x056);

    // Format One
    const ASYMMETRIC: Self = Self(Self::FMT1 + 0x001);
    const ATTRIBUTES: Self = Self(Self::FMT1 + 0x002);
    const HASH: Self = Self(Self::FMT1 + 0x003);
    const VALUE: Self = Self(Self::FMT1 + 0x004);
    const HIERARCHY: Self = Self(Self::FMT1 + 0x005);
    const KEY_SIZE: Self = Self(Self::FMT1 + 0x007);
    const MGF: Self = Self(Self::FMT1 + 0x008);
    const MODE: Self = Self(Self::FMT1 + 0x009);
    const TYPE: Self = Self(Self::FMT1 + 0x00A);
    const HANDLE: Self = Self(Self::FMT1 + 0x00B);
    const KDF: Self = Self(Self::FMT1 + 0x00C);
    const RANGE: Self = Self(Self::FMT1 + 0x00D);
    const AUTH_FAIL: Self = Self(Self::FMT1 + 0x00E);
    const NONCE: Self = Self(Self::FMT1 + 0x00F);
    const PP: Self = Self(Self::FMT1 + 0x010);
    const SCHEME: Self = Self(Self::FMT1 + 0x012);
    const SIZE: Self = Self(Self::FMT1 + 0x015);
    const SYMMETRIC: Self = Self(Self::FMT1 + 0x016);
    const TAG: Self = Self(Self::FMT1 + 0x017);
    const SELECTOR: Self = Self(Self::FMT1 + 0x018);
    const INSUFFICIENT: Self = Self(Self::FMT1 + 0x01A);
    const SIGNATURE: Self = Self(Self::FMT1 + 0x01B);
    const KEY: Self = Self(Self::FMT1 + 0x01C);
    const POLICY_FAIL: Self = Self(Self::FMT1 + 0x01D);
    const INTEGRITY: Self = Self(Self::FMT1 + 0x01F);
    const TICKET: Self = Self(Self::FMT1 + 0x020);
    const RESERVED_BITS: Self = Self(Self::FMT1 + 0x021);
    const BAD_AUTH: Self = Self(Self::FMT1 + 0x022);
    const EXPIRED: Self = Self(Self::FMT1 + 0x023);
    const POLICY_CC: Self = Self(Self::FMT1 + 0x024);
    const BINDING: Self = Self(Self::FMT1 + 0x025);
    const CURVE: Self = Self(Self::FMT1 + 0x026);
    const ECC_POINT: Self = Self(Self::FMT1 + 0x027);
    const FW_LIMITED: Self = Self(Self::FMT1 + 0x028);
    const SVN_LIMITED: Self = Self(Self::FMT1 + 0x029);
    const PARMS: Self = Self(Self::FMT1 + 0x02A);
    const EXT_MU: Self = Self(Self::FMT1 + 0x02B);
    const ONE_SHOT_SIGNATURE: Self = Self(Self::FMT1 + 0x02C);
    const SIGN_CONTEXT_KEY: Self = Self(Self::FMT1 + 0x02D);
    const CHANNEL: Self = Self(Self::FMT1 + 0x030);
    const CHANNEL_KEY: Self = Self(Self::FMT1 + 0x031);

    // Warnings
    const CONTEXT_GAP: Self = Self(Self::WARN + 0x001);
    const OBJECT_MEMORY: Self = Self(Self::WARN + 0x002);
    const SESSION_MEMORY: Self = Self(Self::WARN + 0x003);
    const MEMORY: Self = Self(Self::WARN + 0x004);
    const SESSION_HANDLES: Self = Self(Self::WARN + 0x005);
    const OBJECT_HANDLES: Self = Self(Self::WARN + 0x006);
    const LOCALITY: Self = Self(Self::WARN + 0x007);
    const YIELDED: Self = Self(Self::WARN + 0x008);
    const CANCELED: Self = Self(Self::WARN + 0x009);
    const TESTING: Self = Self(Self::WARN + 0x00A);
    const REFERENCE_H0: Self = Self(Self::WARN + 0x010);
    const REFERENCE_H1: Self = Self(Self::WARN + 0x011);
    const REFERENCE_H2: Self = Self(Self::WARN + 0x012);
    const REFERENCE_H3: Self = Self(Self::WARN + 0x013);
    const REFERENCE_H4: Self = Self(Self::WARN + 0x014);
    const REFERENCE_H5: Self = Self(Self::WARN + 0x015);
    const REFERENCE_H6: Self = Self(Self::WARN + 0x016);
    const REFERENCE_S0: Self = Self(Self::WARN + 0x018);
    const REFERENCE_S1: Self = Self(Self::WARN + 0x019);
    const REFERENCE_S2: Self = Self(Self::WARN + 0x01A);
    const REFERENCE_S3: Self = Self(Self::WARN + 0x01B);
    const REFERENCE_S4: Self = Self(Self::WARN + 0x01C);
    const REFERENCE_S5: Self = Self(Self::WARN + 0x01D);
    const REFERENCE_S6: Self = Self(Self::WARN + 0x01E);
    const NV_RATE: Self = Self(Self::WARN + 0x020);
    const LOCKOUT: Self = Self(Self::WARN + 0x021);
    const RETRY: Self = Self(Self::WARN + 0x022);
    const NV_UNAVAILABLE: Self = Self(Self::WARN + 0x023);
    const NOT_USED: Self = Self(Self::WARN + 0x07F);

    // Format One handle, parameter, session, and index modifiers
    const H: u32 = 0x000;
    const P: u32 = 0x040;
    const S: u32 = 0x800;
    const N_MASK: u32 = 0xF00;

    fn base(&self) -> Self {
        let value = self.0;

        if value & Self::FMT1 != 0 {
            Self(Self::FMT1 | (value & Self::FMT1_ERROR_MASK))
        } else {
            *self
        }
    }
}

impl From<u32> for TpmRc {
    fn from(value: u32) -> Self {
        Self(value)
    }
}