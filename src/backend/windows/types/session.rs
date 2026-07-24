use bitflags::bitflags;

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum TpmSe {
    Hmac = 0x00,
    Policy = 0x01,
    Trial = 0x03,
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
