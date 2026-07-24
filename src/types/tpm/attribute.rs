use crate::{Error, Result, macros::{newtype, tpm_list_type}};

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
            tracing::error!(
                value = format_args!("{value:#010x}"),
                "invalid command attributes"
            );
            return Err(Error::InvalidData);
        }

        Ok(Self(value))
    }
}
