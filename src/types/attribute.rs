#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TpmlCca {
    items: Vec<TpmaCc>,
}

impl TpmlCca {
    pub(crate) fn new(items: Vec<TpmaCc>) -> Self {
        Self { items }
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TpmaCc(u32);

impl TpmaCc {
    const COMMAND_INDEX_MASK: u32 = 0x0000_FFFF;

    const NV: u32 = 1 << 23;
    const EXTENSIVE: u32 = 1 << 24;
    const FLUSHED: u32 = 1 << 25;
    const C_HANDLES_MASK: u32 = 0b111 << 26;
    const R_HANDLE: u32 = 1 << 29;
    const V: u32 = 1 << 30;

    pub(crate) fn new(value: u32) -> Self {
        Self(value)
    }

    pub(crate) fn from_be_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    pub(crate) fn raw(self) -> u32 {
        self.0
    }
}
