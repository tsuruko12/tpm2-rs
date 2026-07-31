#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum TpmSe {
    Hmac = 0x00,
    Policy = 0x01,
    Trial = 0x03,
}
