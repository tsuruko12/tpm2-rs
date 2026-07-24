use super::algorithm::HashAlgorithm;

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
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccScheme {
    Ecdsa(HashAlgorithm),
}
