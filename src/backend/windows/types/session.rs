#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::backend::windows) enum TpmSe {
    Hmac = 0x00,
    Policy = 0x01,
    Trial = 0x03,
}
