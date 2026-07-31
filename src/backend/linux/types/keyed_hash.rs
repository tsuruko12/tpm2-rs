use tss_esapi::{
    structures::{HashScheme, HmacScheme, XorScheme},
    tss2_esys::TPMS_SCHEME_XOR,
};

use crate::{
    Error, Result,
    types::{TpmsSchemeHash, TpmsSchemeXor},
};

impl From<HmacScheme> for TpmsSchemeHash {
    fn from(hmac_scheme: HmacScheme) -> Self {
        Self {
            hash_alg: HashScheme::from(hmac_scheme).hashing_algorithm().into(),
        }
    }
}

impl TryFrom<XorScheme> for TpmsSchemeXor {
    type Error = Error;

    fn try_from(xor_scheme: XorScheme) -> Result<Self> {
        let tpms_scheme_xor = TPMS_SCHEME_XOR::from(xor_scheme);

        Ok(Self {
            hash_alg: tpms_scheme_xor.hashAlg.try_into()?,
            kdf: tpms_scheme_xor.kdf.try_into()?,
        })
    }
}
