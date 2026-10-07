use super::super::algorithm::HashAlgorithm;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EccTemplate {
    exportable: bool,
    restricted: bool,
    curve: EccCurve,
    scheme: EccScheme,
}

impl EccTemplate {
    pub fn sign(curve: EccCurve, scheme: EccScheme) -> Self {
        Self::unrestricted(curve, scheme)
    }

    pub(super) fn restricted(curve: EccCurve, scheme: EccScheme) -> Self {
        Self {
            exportable: false,
            restricted: true,
            curve,
            scheme,
        }
    }

    pub(super) fn unrestricted(curve: EccCurve, scheme: EccScheme) -> Self {
        Self {
            exportable: false,
            restricted: false,
            curve,
            scheme,
        }
    }

    pub fn with_exportable(mut self, exportable: bool) -> Self {
        self.exportable = exportable;
        self
    }

    pub(crate) fn is_exportable(&self) -> bool {
        self.exportable
    }

    pub(crate) fn is_restricted(&self) -> bool {
        self.restricted
    }

    pub(crate) fn curve(&self) -> EccCurve {
        self.curve
    }

    pub(crate) fn scheme(&self) -> EccScheme {
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

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccScheme {
    Ecdsa(HashAlgorithm),
}
