use tss_esapi::{interface_types::ecc::EccCurve as EsapiEccCurve, structures::EccCurveList};

use crate::{
    Error, Result,
    types::{EccCurve, TpmEccCurve, TpmlEccCurve},
};

impl From<EccCurve> for EsapiEccCurve {
    fn from(value: EccCurve) -> Self {
        match value {
            EccCurve::NistP256 => Self::NistP256,
            EccCurve::NistP384 => Self::NistP384,
            EccCurve::NistP521 => Self::NistP521,
        }
    }
}

impl TryFrom<TpmEccCurve> for EsapiEccCurve {
    type Error = Error;

    fn try_from(value: TpmEccCurve) -> Result<Self> {
        match value {
            TpmEccCurve::NistP192 => Ok(Self::NistP192),
            TpmEccCurve::NistP224 => Ok(Self::NistP224),
            TpmEccCurve::NistP256 => Ok(Self::NistP256),
            TpmEccCurve::NistP384 => Ok(Self::NistP384),
            TpmEccCurve::NistP521 => Ok(Self::NistP521),
            TpmEccCurve::BnP256 => Ok(Self::BnP256),
            TpmEccCurve::BnP638 => Ok(Self::BnP638),
            TpmEccCurve::Sm2P256 => Ok(Self::Sm2P256),
            _ => {
                tracing::error!(
                    value = ?value,
                    "failed to convert to ESAPI value",
                );
                Err(Error::Internal(
                    "failed to convert ECC curve to ESAPI value",
                ))
            }
        }
    }
}

impl TryFrom<EccCurveList> for TpmlEccCurve {
    type Error = Error;

    fn try_from(value: EccCurveList) -> Result<Self> {
        value
            .into_inner()
            .into_iter()
            .map(|item| TpmEccCurve::try_from(u16::from(item)))
            .collect::<Result<Vec<_>>>()
            .map(Self::new)
    }
}
