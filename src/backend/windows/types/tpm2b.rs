use std::ops::Deref;

use zeroize::Zeroizing;

use crate::Result;

use super::{Uint16, unmarshal_tpm2b};

pub(crate) struct Digest {
    size: Uint16,
    buffer: Zeroizing<Vec<u8>>,
}

impl Deref for Digest {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl Digest {
    pub(crate) fn new(bytes: &[u8]) -> Result<Self> {
        let (size, buffer) = unmarshal_tpm2b(bytes)?;

        Ok(Self { size, buffer })
    }
}
