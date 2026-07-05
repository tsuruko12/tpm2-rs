#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TpmlCc {
    items: Vec<TpmCc>,
}

impl TpmlCc {
    pub(crate) fn new(items: Vec<TpmCc>) -> Self {
        Self { items }
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

pub(crate) type TpmCc = u32;
