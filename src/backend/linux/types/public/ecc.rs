use tss_esapi::{
    interface_types::ecc::EccCurve as EsapiEccCurve,
    structures::{EccCurveList, EccScheme},
    tss2_esys::{TPMS_ECC_PARMS, TPMS_SCHEME_ECDAA, TPMT_ECC_SCHEME, TPMU_ASYM_SCHEME},
};

use crate::{
    Error, Result,
    types::{
        EccCurve,
        tpm::{TpmAlgId, TpmEccCurve, TpmlEccCurve, TpmsEccParms, TpmsSchemeEcdaa,
            TpmtEccScheme, TpmuEccScheme, TpmuPublicParms},
    },
};

impl From<EccCurve> for EsapiEccCurve {
    fn from(curve: EccCurve) -> Self {
        match curve {
            EccCurve::NistP256 => Self::NistP256,
            EccCurve::NistP384 => Self::NistP384,
            EccCurve::NistP521 => Self::NistP521,
        }
    }
}

impl TryFrom<TpmEccCurve> for EsapiEccCurve {
    type Error = Error;

    fn try_from(curve: TpmEccCurve) -> Result<Self> {
        match curve {
            TpmEccCurve::NistP192 => Ok(Self::NistP192),
            TpmEccCurve::NistP224 => Ok(Self::NistP224),
            TpmEccCurve::NistP256 => Ok(Self::NistP256),
            TpmEccCurve::NistP384 => Ok(Self::NistP384),
            TpmEccCurve::NistP521 => Ok(Self::NistP521),
            TpmEccCurve::BnP256 => Ok(Self::BnP256),
            TpmEccCurve::BnP638 => Ok(Self::BnP638),
            TpmEccCurve::Sm2P256 => Ok(Self::Sm2P256),
            _ => Err(Error::conversion::<TpmEccCurve, EsapiEccCurve>(Some(
                &curve,
            ))),
        }
    }
}

impl From<EsapiEccCurve> for TpmEccCurve {
    fn from(curve: EsapiEccCurve) -> Self {
        match curve {
            EsapiEccCurve::NistP192 => Self::NistP192,
            EsapiEccCurve::NistP224 => Self::NistP224,
            EsapiEccCurve::NistP256 => Self::NistP256,
            EsapiEccCurve::NistP384 => Self::NistP384,
            EsapiEccCurve::NistP521 => Self::NistP521,
            EsapiEccCurve::BnP256 => Self::BnP256,
            EsapiEccCurve::BnP638 => Self::BnP638,
            EsapiEccCurve::Sm2P256 => Self::Sm2P256,
        }
    }
}

impl TryFrom<EccCurveList> for TpmlEccCurve {
    type Error = Error;

    fn try_from(curve_list: EccCurveList) -> Result<Self> {
        let items = curve_list
            .into_inner()
            .into_iter()
            .map(|item| TpmEccCurve::try_from(u16::from(item)))
            .collect::<Result<Vec<_>>>()?;

        Ok(items.into())
    }
}

impl From<EccScheme> for TpmtEccScheme {
    fn from(ecc_scheme: EccScheme) -> Self {
        match ecc_scheme {
            EccScheme::EcDsa(hash_scheme) => Self::ecdsa(hash_scheme.into()),
            EccScheme::EcDh(hash_scheme) => Self::ecdh(hash_scheme.into()),
            EccScheme::Sm2(hash_scheme) => Self::sm2(hash_scheme.into()),
            EccScheme::EcSchnorr(hash_scheme) => Self::ec_schnorr(hash_scheme.into()),
            EccScheme::EcMqv(hash_scheme) => Self::ec_mqv(hash_scheme.into()),
            EccScheme::EcDaa(ecdaa_scheme) => Self::ecdaa(TpmsSchemeEcdaa {
                hash_alg: ecdaa_scheme.hashing_algorithm().into(),
                count: ecdaa_scheme.count(),
            }),
            EccScheme::Null => Self::null(),
        }
    }
}

impl TryFrom<TPMS_ECC_PARMS> for TpmuPublicParms {
    type Error = Error;

    fn try_from(ecc_params: TPMS_ECC_PARMS) -> Result<Self> {
        Ok(Self::EccDetail(TpmsEccParms::new(
            ecc_params.symmetric.try_into()?,
            ecc_params.scheme.try_into()?,
            ecc_params.curveID.try_into()?,
            ecc_params.kdf.try_into()?,
        )))
    }
}

impl TryFrom<TpmsEccParms> for TPMS_ECC_PARMS {
    type Error = Error;

    fn try_from(ecc_params: TpmsEccParms) -> Result<Self> {
        Ok(Self {
            symmetric: ecc_params.symmetric().try_into()?,
            scheme: ecc_params.scheme().try_into()?,
            curveID: ecc_params.curve_id().value(),
            kdf: ecc_params.kdf().try_into()?,
        })
    }
}

impl TryFrom<TPMT_ECC_SCHEME> for TpmtEccScheme {
    type Error = Error;

    fn try_from(ecc_scheme: TPMT_ECC_SCHEME) -> Result<Self> {
        let scheme = TpmAlgId::try_from(ecc_scheme.scheme)?;

        match scheme {
            TpmAlgId::Ecdsa => Ok(Self::ecdsa(unsafe { ecc_scheme.details.ecdsa }.try_into()?)),
            TpmAlgId::Ecdh => Ok(Self::ecdh(unsafe { ecc_scheme.details.ecdh }.try_into()?)),
            TpmAlgId::Ecdaa => {
                let details = unsafe { ecc_scheme.details.ecdaa };

                Ok(Self::ecdaa(TpmsSchemeEcdaa {
                    hash_alg: details.hashAlg.try_into()?,
                    count: details.count,
                }))
            }
            TpmAlgId::Sm2 => Ok(Self::sm2(unsafe { ecc_scheme.details.sm2 }.try_into()?)),
            TpmAlgId::EcSchnorr => Ok(Self::ec_schnorr(
                unsafe { ecc_scheme.details.ecschnorr }.try_into()?,
            )),
            TpmAlgId::EcMqv => Ok(Self::ec_mqv(
                unsafe { ecc_scheme.details.ecmqv }.try_into()?,
            )),
            TpmAlgId::Null => Ok(Self::null()),
            _ => Err(Error::conversion::<TpmAlgId, TpmtEccScheme>(Some(&scheme))),
        }
    }
}

impl TryFrom<TpmtEccScheme> for TPMT_ECC_SCHEME {
    type Error = Error;

    fn try_from(ecc_scheme: TpmtEccScheme) -> Result<Self> {
        let (scheme, details) = ecc_scheme.into_parts();
        let raw_scheme = scheme.value();
        let details = match (TpmAlgId::try_from(raw_scheme)?, details) {
            (TpmAlgId::Ecdsa, TpmuEccScheme::Ecdsa(scheme_hash)) => TPMU_ASYM_SCHEME { 
                ecdsa: scheme_hash.into() 
            },
            (TpmAlgId::Ecdh, TpmuEccScheme::Ecdh(scheme_hash)) => TPMU_ASYM_SCHEME { 
                ecdh: scheme_hash.into() 
            },
            (TpmAlgId::Ecdaa, TpmuEccScheme::Ecdaa(details)) => TPMU_ASYM_SCHEME {
                ecdaa: TPMS_SCHEME_ECDAA {
                    hashAlg: details.hash_alg.value(),
                    count: details.count,
                },
            },
            (TpmAlgId::Sm2, TpmuEccScheme::Sm2(scheme_hash)) => TPMU_ASYM_SCHEME { 
                sm2: scheme_hash.into() 
            },
            (TpmAlgId::EcSchnorr, TpmuEccScheme::EcSchnorr(scheme_hash)) => TPMU_ASYM_SCHEME { 
                ecschnorr: scheme_hash.into() 
            },
            (TpmAlgId::EcMqv, TpmuEccScheme::EcMqv(scheme_hash)) => TPMU_ASYM_SCHEME { 
                ecmqv: scheme_hash.into() 
            },
            (TpmAlgId::Null, TpmuEccScheme::Null) => TPMU_ASYM_SCHEME::default(),
            _ => return Err(Error::invalid_state("ECC scheme and details are inconsistent")),
        };

        Ok(Self {
            scheme: raw_scheme,
            details,
        })
    }
}
