use crate::{
    Error, Result,
    macros::{newtype, tpm_list_type},
};
use bitflags::bitflags;

tpm_list_type!(TpmlCca(TpmaCc););

newtype!(TpmaCc(u32));

impl TpmaCc {
    const COMMAND_INDEX_MASK: u32 = 0x0000_FFFF;

    const NV: u32 = 1 << 22;
    const EXTENSIVE: u32 = 1 << 23;
    const FLUSHED: u32 = 1 << 24;
    const C_HANDLES_MASK: u32 = 0b111 << 25;
    const R_HANDLE: u32 = 1 << 28;
    const V: u32 = 1 << 29;

    const RESERVED_MASK: u32 = 0xC03F_0000;
}

impl TryFrom<u32> for TpmaCc {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        if value & Self::RESERVED_MASK != 0 {
            return Err(Error::conversion::<u32, TpmaCc>(None));
        }

        Ok(Self(value))
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct TpmaSession: u8 {
        const CONTINUE_SESSION = 0x01;
        const AUDIT_EXCLUSIVE = 0x02;
        const AUDIT_RESET = 0x04;
        const DECRYPT = 0x20;
        const ENCRYPT = 0x40;
        const AUDIT = 0x80;
    }
}

impl TpmaSession {
    pub(crate) fn continue_session() -> Self {
        Self::CONTINUE_SESSION
    }

    pub(crate) fn decrypt() -> Self {
        Self::DECRYPT
    }

    pub(crate) fn encrypt() -> Self {
        Self::ENCRYPT
    }

    pub(crate) fn encrypt_decrypt() -> Self {
        Self::DECRYPT | Self::ENCRYPT
    }

    pub(crate) fn with_continue_session(mut self) -> Self {
        self |= Self::CONTINUE_SESSION;
        self
    }
}
