use tss_esapi::structures::{Auth, Digest, Private};

use crate::types::tpm::{Tpm2bAuth, Tpm2bDigest, Tpm2bPrivate};

impl From<Tpm2bDigest> for Digest {
    fn from(digest: Tpm2bDigest) -> Self {
        digest
            .as_bytes()
            .try_into()
            .expect("Tpm2bDigest must be valid for Digest")
    }
}

impl From<Digest> for Tpm2bDigest {
    fn from(digest: Digest) -> Self {
        digest
            .value()
            .try_into()
            .expect("Digest must be valid for Tpm2bDigest")
    }
}

impl From<Tpm2bPrivate> for Private {
    fn from(private: Tpm2bPrivate) -> Self {
        private
            .as_bytes()
            .try_into()
            .expect("Tpm2bPrivate must be valid for Private")
    }
}

impl From<Private> for Tpm2bPrivate {
    fn from(private: Private) -> Self {
        private
            .value()
            .try_into()
            .expect("Private must be valid for Tpm2bPrivate")
    }
}

impl From<Tpm2bAuth> for Auth {
    fn from(auth: Tpm2bAuth) -> Self {
        auth
            .as_bytes()
            .try_into()
            .expect("Tpm2bAuth must be valid for Auth")
    }
}

impl From<&Tpm2bAuth> for Auth {
    fn from(auth: &Tpm2bAuth) -> Self {
        auth.clone().into()
    }
}

impl From<Auth> for Tpm2bAuth {
    fn from(auth: Auth) -> Self {
        auth
            .value()
            .try_into()
            .expect("Auth must be valid for Tpm2bAuth")
    }
}
