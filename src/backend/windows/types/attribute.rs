use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub(in crate::backend::windows) struct TpmaLocality: u8 {
        const ZERO = 0x01;
        const ONE = 0x02;
        const TWO = 0x04;
        const THREE = 0x08;
        const FOUR = 0x10;

        const _ = 0xE0; // Extended
    }
}
