use tss_esapi::structures::Digest;

use crate::{Error, Result, types::Tpm2bDigest};

impl TryFrom<Tpm2bDigest> for Digest {
    type Error = Error;

    fn try_from(digest: Tpm2bDigest) -> Result<Self> {
        digest
            .as_bytes()
            .try_into()
            .map_err(|_| Error::conversion::<Tpm2bDigest, Digest>(None))
    }
}

impl TryFrom<Digest> for Tpm2bDigest {
    type Error = Error;

    fn try_from(digest: Digest) -> Result<Self> {
        digest
            .value()
            .try_into()
            .map_err(|_| Error::conversion::<Digest, Tpm2bDigest>(None))
    }
}
