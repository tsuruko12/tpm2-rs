use tss_esapi::{
    structures::{HashScheme, HmacScheme, XorScheme},
    tss2_esys::{TPMS_KEYEDHASH_PARMS, TPMS_SCHEME_XOR, TPMT_KEYEDHASH_SCHEME, TPMU_SCHEME_KEYEDHASH},
};

use crate::{
    Error, Result,
    types::tpm::{
        TpmAlgId, TpmsKeyedHashParms, TpmsSchemeHash, TpmsSchemeXor, TpmtKeyedHashScheme,
        TpmuPublicParms, TpmuSchemeKeyedHash,
    },
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

impl TryFrom<TPMS_KEYEDHASH_PARMS> for TpmuPublicParms {
    type Error = Error;

    fn try_from(keyed_hash_params: TPMS_KEYEDHASH_PARMS) -> Result<Self> {
        Ok(Self::KeyedHashDetail(TpmsKeyedHashParms {
            scheme: keyed_hash_params.scheme.try_into()?,
        }))
    }
}

impl TryFrom<TPMT_KEYEDHASH_SCHEME> for TpmtKeyedHashScheme {
    type Error = Error;

    fn try_from(keyed_hash_scheme: TPMT_KEYEDHASH_SCHEME) -> Result<Self> {
        let scheme = TpmAlgId::try_from(keyed_hash_scheme.scheme)?;

        match scheme {
            TpmAlgId::Hmac => Ok(Self::hmac(
                unsafe { keyed_hash_scheme.details.hmac }.try_into()?,
            )),
            TpmAlgId::Xor => Ok(Self::xor(
                unsafe { keyed_hash_scheme.details.exclusiveOr }.try_into()?,
            )),
            TpmAlgId::Null => Ok(Self::null()),
            _ => Err(Error::conversion::<TpmAlgId, TpmtKeyedHashScheme>(Some(&scheme))),
        }
    }
}

impl TryFrom<TpmtKeyedHashScheme> for TPMT_KEYEDHASH_SCHEME {
    type Error = Error;

    fn try_from(keyed_hash_scheme: TpmtKeyedHashScheme) -> Result<Self> {
        let (scheme, details) = keyed_hash_scheme.into_parts();
        let raw_scheme = scheme.value();
        let details = match (TpmAlgId::try_from(raw_scheme)?, details) {
            (TpmAlgId::Hmac, TpmuSchemeKeyedHash::Hmac(scheme_hash)) => TPMU_SCHEME_KEYEDHASH { 
                hmac: scheme_hash.into() 
            },
            (TpmAlgId::Xor, TpmuSchemeKeyedHash::Xor(scheme_xor)) => TPMU_SCHEME_KEYEDHASH { 
                exclusiveOr: scheme_xor.into() 
            },
            (TpmAlgId::Null, TpmuSchemeKeyedHash::Null) => TPMU_SCHEME_KEYEDHASH::default(),
            _ => return Err(Error::invalid_state("keyed-hash scheme and details are inconsistent")),
        };

        Ok(Self {
            scheme: raw_scheme,
            details,
        })
    }
}

impl TryFrom<TPMS_SCHEME_XOR> for TpmsSchemeXor {
    type Error = Error;

    fn try_from(scheme_xor: TPMS_SCHEME_XOR) -> Result<Self> {
        Ok(Self {
            hash_alg: scheme_xor.hashAlg.try_into()?,
            kdf: scheme_xor.kdf.try_into()?,
        })
    }
}

impl From<TpmsSchemeXor> for TPMS_SCHEME_XOR {
    fn from(scheme_xor: TpmsSchemeXor) -> Self {
        Self {
            hashAlg: scheme_xor.hash_alg.value(),
            kdf: scheme_xor.kdf.value(),
        }
    }
}
