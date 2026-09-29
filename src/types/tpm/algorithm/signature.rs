use super::super::algorithm::{
    TpmAlgId, TpmiAlgHash, TpmsSchemeHash,
    ecc::{TpmsSchemeEcdaa, TpmsSignatureEcc},
    hash::TpmtHa,
    rsa::TpmsSignatureRsa,
};
use crate::{Error, Result, macros::newtype, signature::SignatureScheme};

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmtSigScheme {
    scheme: TpmiAlgSigScheme,
    details: TpmuSigScheme,
}

impl TpmtSigScheme {
    pub(crate) fn rsa_ssa(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::RSA_SSA,
            details: TpmuSigScheme::RsaSsa(scheme_hash),
        }
    }

    pub(crate) fn rsa_pss(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::RSA_PSS,
            details: TpmuSigScheme::RsaPss(scheme_hash),
        }
    }

    pub(crate) fn ecdsa(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::ECDSA,
            details: TpmuSigScheme::Ecdsa(scheme_hash),
        }
    }

    pub(crate) fn ecdaa(scheme_ecdaa: TpmsSchemeEcdaa) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::ECDAA,
            details: TpmuSigScheme::Ecdaa(scheme_ecdaa),
        }
    }

    pub(crate) fn sm2(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::SM2,
            details: TpmuSigScheme::Sm2(scheme_hash),
        }
    }

    pub(crate) fn ec_schnorr(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::EC_SCHNORR,
            details: TpmuSigScheme::EcSchnorr(scheme_hash),
        }
    }

    pub(crate) fn hmac(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgSigScheme::HMAC,
            details: TpmuSigScheme::Hmac(scheme_hash),
        }
    }

    pub(crate) fn null() -> Self {
        Self {
            scheme: TpmiAlgSigScheme::NULL,
            details: TpmuSigScheme::Null,
        }
    }

    pub(crate) fn digest_size(&self) -> Option<usize> {
        let hash = match self.details {
            TpmuSigScheme::EcSchnorr(hash_scheme)
            | TpmuSigScheme::Ecdsa(hash_scheme)
            | TpmuSigScheme::Eddsa(hash_scheme)
            | TpmuSigScheme::Hmac(hash_scheme)
            | TpmuSigScheme::RsaPss(hash_scheme)
            | TpmuSigScheme::RsaSsa(hash_scheme)
            | TpmuSigScheme::Sm2(hash_scheme) => hash_scheme.hash_alg,
            TpmuSigScheme::Ecdaa(ecdaa_scheme) => ecdaa_scheme.hash_alg,
            TpmuSigScheme::Null => return Some(0),
        };

        TpmAlgId::from(hash).digest_size()
    }

    pub(crate) fn details(&self) -> TpmuSigScheme {
        self.details
    }

    pub(crate) fn into_parts(self) -> (TpmiAlgSigScheme, TpmuSigScheme) {
        (self.scheme, self.details)
    }
}

impl From<SignatureScheme> for TpmtSigScheme {
    fn from(sig_scheme: SignatureScheme) -> Self {
        match sig_scheme {
            SignatureScheme::Ecdsa(hash_alg) => Self::ecdsa(hash_alg.into()),
            SignatureScheme::RsaPss(hash_alg) => Self::rsa_pss(hash_alg.into()),
            SignatureScheme::RsaSsa(hash_alg) => Self::rsa_ssa(hash_alg.into()),
        }
    }
}

newtype!(TpmiAlgSigScheme(TpmAlgId));

impl TpmiAlgSigScheme {
    pub(crate) const RSA_SSA: Self = Self(TpmAlgId::RsaSsa);
    pub(crate) const RSA_PSS: Self = Self(TpmAlgId::RsaPss);
    pub(crate) const ECDSA: Self = Self(TpmAlgId::Ecdsa);
    pub(crate) const ECDAA: Self = Self(TpmAlgId::Ecdaa);
    pub(crate) const SM2: Self = Self(TpmAlgId::Sm2);
    pub(crate) const EC_SCHNORR: Self = Self(TpmAlgId::EcSchnorr);
    pub(crate) const HMAC: Self = Self(TpmAlgId::Hmac);
    pub(crate) const NULL: Self = Self(TpmAlgId::Null);
}

impl TryFrom<TpmAlgId> for TpmiAlgSigScheme {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        match alg {
            TpmAlgId::RsaSsa
            | TpmAlgId::RsaPss
            | TpmAlgId::Ecdsa
            | TpmAlgId::Ecdaa
            | TpmAlgId::Sm2
            | TpmAlgId::EcSchnorr
            | TpmAlgId::EdDsa
            | TpmAlgId::HashEdDsa
            | TpmAlgId::Hmac
            | TpmAlgId::MlDsa
            | TpmAlgId::HashMlDsa
            | TpmAlgId::Null => Ok(Self(alg)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgSigScheme>(Some(&alg))),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TpmuSigScheme {
    RsaSsa(TpmsSchemeHash),
    RsaPss(TpmsSchemeHash),
    Ecdsa(TpmsSchemeHash),
    Sm2(TpmsSchemeHash),
    EcSchnorr(TpmsSchemeHash),
    Eddsa(TpmsSchemeHash),
    Ecdaa(TpmsSchemeEcdaa),
    Hmac(TpmsSchemeHash),
    Null,
}

impl TpmuSigScheme {
    pub(crate) fn hash_alg(&self) -> Option<TpmiAlgHash> {
        match self {
            Self::EcSchnorr(scheme_hash)
            | Self::Ecdsa(scheme_hash)
            | Self::Eddsa(scheme_hash)
            | Self::Hmac(scheme_hash)
            | Self::RsaPss(scheme_hash)
            | Self::RsaSsa(scheme_hash)
            | Self::Sm2(scheme_hash) => Some(scheme_hash.hash_alg),
            Self::Ecdaa(ecdaa_scheme) => Some(ecdaa_scheme.hash_alg),
            Self::Null => None,
        }
    }
}

pub(crate) struct TpmtSignature {
    sig_alg: TpmiAlgSigScheme,
    signature: TpmuSignature,
}

impl TpmtSignature {
    pub(crate) fn ecdsa(sig_ecc: TpmsSignatureEcc) -> Self {
        Self {
            sig_alg: TpmiAlgSigScheme::ECDSA,
            signature: TpmuSignature::Ecdsa(sig_ecc),
        }
    }

    pub(crate) fn rsa_ssa(sig_rsa: TpmsSignatureRsa) -> Self {
        Self {
            sig_alg: TpmiAlgSigScheme::RSA_SSA,
            signature: TpmuSignature::RsaSsa(sig_rsa),
        }
    }

    pub(crate) fn rsa_pss(sig_rsa: TpmsSignatureRsa) -> Self {
        Self {
            sig_alg: TpmiAlgSigScheme::RSA_PSS,
            signature: TpmuSignature::RsaPss(sig_rsa),
        }
    }
}

#[derive(Clone)]
pub(crate) enum TpmuSignature {
    RsaSsa(TpmsSignatureRsa),
    RsaPss(TpmsSignatureRsa),
    Ecdsa(TpmsSignatureEcc),
    Sm2(TpmsSignatureEcc),
    EcSchnorr(TpmsSignatureEcc),
    Eddsa(TpmsSignatureEcc),
    Hmac(TpmtHa),
    Ecdaa(TpmsSignatureEcc),
    Null,
}
