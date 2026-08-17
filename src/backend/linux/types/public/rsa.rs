use tss_esapi::{
    structures::{PublicKeyRsa, RsaScheme as EsapiRsaScheme},
    tss2_esys::{TPMS_RSA_PARMS, TPMT_RSA_SCHEME, TPMU_ASYM_SCHEME},
};

use crate::{
    Error, Result,
    types::{
        Tpm2bPublicKeyRsa, TpmAlgId, TpmiRsaKeyBits, TpmsRsaParms, TpmtRsaScheme, TpmuPublicParms, TpmuRsaScheme
    },
};

impl From<EsapiRsaScheme> for TpmtRsaScheme {
    fn from(scheme: EsapiRsaScheme) -> Self {
        match scheme {
            EsapiRsaScheme::Oaep(hash_scheme) => Self::oaep(hash_scheme.into()),
            EsapiRsaScheme::RsaPss(hash_scheme) => Self::rsa_pss(hash_scheme.into()),
            EsapiRsaScheme::RsaSsa(hash_scheme) => Self::rsa_ssa(hash_scheme.into()),
            EsapiRsaScheme::RsaEs => Self::rsa_es(),
            EsapiRsaScheme::Null => Self::null(),
        }
    }
}

impl TryFrom<TPMS_RSA_PARMS> for TpmuPublicParms {
    type Error = Error;

    fn try_from(rsa_params: TPMS_RSA_PARMS) -> Result<Self> {
        Ok(Self::RsaDetail(TpmsRsaParms::new(
            rsa_params.symmetric.try_into()?,
            rsa_params.scheme.try_into()?,
            TpmiRsaKeyBits::from(rsa_params.keyBits),
            rsa_params.exponent,
        )))
    }
}

impl TryFrom<TpmsRsaParms> for TPMS_RSA_PARMS {
    type Error = Error;

    fn try_from(rsa_params: TpmsRsaParms) -> Result<Self> {
        Ok(Self {
            symmetric: rsa_params.symmetric().try_into()?,
            scheme: rsa_params.scheme().try_into()?,
            keyBits: rsa_params.key_bits().raw(),
            exponent: rsa_params.exponent(),
        })
    }
}

impl TryFrom<TPMT_RSA_SCHEME> for TpmtRsaScheme {
    type Error = Error;

    fn try_from(rsa_scheme: TPMT_RSA_SCHEME) -> Result<Self> {
        let scheme = TpmAlgId::try_from(rsa_scheme.scheme)?;

        match scheme {
            TpmAlgId::RsaSsa => Ok(Self::rsa_ssa(
                unsafe { rsa_scheme.details.rsassa }.try_into()?,
            )),
            TpmAlgId::RsaEs => Ok(Self::rsa_es()),
            TpmAlgId::RsaPss => Ok(Self::rsa_pss(
                unsafe { rsa_scheme.details.rsapss }.try_into()?,
            )),
            TpmAlgId::Oaep => Ok(Self::oaep(unsafe { rsa_scheme.details.oaep }.try_into()?)),
            TpmAlgId::Null => Ok(Self::null()),
            _ => Err(Error::conversion::<TpmAlgId, TpmtRsaScheme>(Some(&scheme))),
        }
    }
}

impl TryFrom<TpmtRsaScheme> for TPMT_RSA_SCHEME {
    type Error = Error;

    fn try_from(rsa_scheme: TpmtRsaScheme) -> Result<Self> {
        let (scheme, details) = rsa_scheme.into_parts();
        let raw_scheme = scheme.raw();
        let details = match (TpmAlgId::try_from(raw_scheme)?, details) {
            (TpmAlgId::RsaSsa, TpmuRsaScheme::RsaSsa(scheme_hash)) => TPMU_ASYM_SCHEME {
                rsassa: scheme_hash.into(),
            },
            (TpmAlgId::RsaEs, TpmuRsaScheme::RsaEs(_)) => TPMU_ASYM_SCHEME {
                rsaes: Default::default(),
            },
            (TpmAlgId::RsaPss, TpmuRsaScheme::RsaPss(scheme_hash)) => TPMU_ASYM_SCHEME { 
                rsapss: scheme_hash.into() 
            },
            (TpmAlgId::Oaep, TpmuRsaScheme::Oaep(scheme_hash)) => TPMU_ASYM_SCHEME { 
                oaep: scheme_hash.into() 
            },
            (TpmAlgId::Null, TpmuRsaScheme::Null) => TPMU_ASYM_SCHEME::default(),
            _ => return Err(Error::invalid_state("RSA scheme and details are inconsistent")),
        };

        Ok(Self {
            scheme: raw_scheme,
            details,
        })
    }
}

impl From<Tpm2bPublicKeyRsa> for PublicKeyRsa {
    fn from(public_key: Tpm2bPublicKeyRsa) -> Self {
        public_key
            .as_bytes()
            .try_into()
            .expect("Tpm2bPublicKeyRsa must be valid for PublicKeyRsa")
    }
}

impl From<PublicKeyRsa> for Tpm2bPublicKeyRsa {
    fn from(public_key: PublicKeyRsa) -> Self {
        public_key
            .value()
            .try_into()
            .expect("PublicKeyRsa must be valid for Tpm2bPublicKeyRsa")
    }
}