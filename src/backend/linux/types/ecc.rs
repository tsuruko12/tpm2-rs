use tss_esapi::{
    interface_types::ecc::EccCurve as EsapiEccCurve,
    structures::{EccCurveList, EccScheme},
};

use crate::{
    Error, Result,
    types::{EccCurve, TpmEccCurve, TpmlEccCurve, TpmsSchemeEcdaa, TpmtEccScheme},
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
            EccScheme::EcDsa(hash) => Self::ecdsa(hash.into()),
            EccScheme::EcDh(hash) => Self::ecdh(hash.into()),
            EccScheme::Sm2(hash) => Self::sm2(hash.into()),
            EccScheme::EcSchnorr(hash) => Self::ec_schnorr(hash.into()),
            EccScheme::EcMqv(hash) => Self::ec_mqv(hash.into()),
            EccScheme::EcDaa(ecdaa_scheme) => Self::ecdaa(TpmsSchemeEcdaa {
                hash_alg: ecdaa_scheme.hashing_algorithm().into(),
                count: ecdaa_scheme.count(),
            }),
            EccScheme::Null => Self::null(),
        }
    }
}
