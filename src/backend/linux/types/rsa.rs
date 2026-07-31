use tss_esapi::structures::RsaScheme as EsapiRsaScheme;

use crate::types::TpmtRsaScheme;

impl From<EsapiRsaScheme> for TpmtRsaScheme {
    fn from(scheme: EsapiRsaScheme) -> Self {
        match scheme {
            EsapiRsaScheme::Oaep(hash) => Self::oaep(hash.into()),
            EsapiRsaScheme::RsaPss(hash) => Self::rsa_pss(hash.into()),
            EsapiRsaScheme::RsaSsa(hash) => Self::rsa_ssa(hash.into()),
            EsapiRsaScheme::RsaEs => Self::rsa_es(),
            EsapiRsaScheme::Null => Self::null(),
        }
    }
}
