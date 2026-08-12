use super::super::{algorithm::HashAlgorithm, tpm::{TpmiEccCurve, TpmsSchemeHash}};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EccTemplate {
    exportable: bool,
    curve: EccCurve,
    scheme: EccScheme,
}

impl EccTemplate {
    pub(super) fn fixed(curve: EccCurve, scheme: EccScheme) -> Self {
        Self {
            exportable: false,
            curve,
            scheme,
        }
    }

    pub(super) fn set_exportable(&mut self) {
        self.exportable = true;
    }

    pub fn exportable(&self) -> bool {
        self.exportable
    }

    pub fn curve(&self) -> EccCurve {
        self.curve
    }

    pub fn scheme(&self) -> EccScheme {
        self.scheme
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccCurve {
    NistP256,
    NistP384,
    NistP521,
}

impl EccCurve {
    pub(super) const DEFAULT: Self = Self::NistP256;
    pub(crate) const MAX_BITS: usize = 521;
}

impl From<EccCurve> for TpmiEccCurve {
    fn from(ecc_curve: EccCurve) -> Self {
        match ecc_curve {
            EccCurve::NistP256 => Self::NIST_P256,
            EccCurve::NistP384 => Self::NIST_P384,
            EccCurve::NistP521 => Self::NIST_P521,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccScheme {
    Ecdsa(HashAlgorithm),
}

impl From<EccScheme> for TpmsSchemeHash {
    fn from(ecc_scheme: EccScheme) -> Self {
        match ecc_scheme {
            EccScheme::Ecdsa(hash_alg) => Self { hash_alg: hash_alg.into() },
        }
    }
}
