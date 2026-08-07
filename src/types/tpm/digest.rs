use crate::{Error, Result};

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tpm2bDigest(Vec<u8>);

impl Tpm2bDigest {
    pub(crate) const MAX_SIZE: usize = 64;

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<Vec<u8>> for Tpm2bDigest {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        if value.len() > Self::MAX_SIZE {
            return Err(Error::invalid_state("digest length exceeds 64 bytes"));
        }

        Ok(Self(value))
    }
}

impl TryFrom<&[u8]> for Tpm2bDigest {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() > Self::MAX_SIZE {
            return Err(Error::invalid_state("digest length exceeds 64 bytes"));
        }

        Ok(Self(value.into()))
    }
}
