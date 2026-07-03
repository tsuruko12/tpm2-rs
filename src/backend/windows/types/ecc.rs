use crate::error::{Error, Result};

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TpmEccCurve {
    None = 0x0000,
    NistP192 = 0x0001,
    NistP224 = 0x0002,
    NistP256 = 0x0003,
    NistP384 = 0x0004,
    NistP521 = 0x0005,
    BnP256 = 0x0010,
    BnP638 = 0x0011,
    Sm2P256 = 0x0020,
    BpP256R1 = 0x0030,
    BpP384R1 = 0x0031,
    BpP512R1 = 0x0032,
    Curve25519 = 0x0040,
    Curve448 = 0x0041,
}

impl TryFrom<u16> for TpmEccCurve {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0x0000 => Ok(Self::None),
            0x0001 => Ok(Self::NistP192),
            0x0002 => Ok(Self::NistP224),
            0x0003 => Ok(Self::NistP256),
            0x0004 => Ok(Self::NistP384),
            0x0005 => Ok(Self::NistP521),
            0x0010 => Ok(Self::BnP256),
            0x0011 => Ok(Self::BnP638),
            0x0020 => Ok(Self::Sm2P256),
            0x0030 => Ok(Self::BpP256R1),
            0x0031 => Ok(Self::BpP384R1),
            0x0032 => Ok(Self::BpP512R1),
            0x0040 => Ok(Self::Curve25519),
            0x0041 => Ok(Self::Curve448),
            _ => Err(Error::Internal("unsupported TPM ECC curve")),
        }
    }
}
