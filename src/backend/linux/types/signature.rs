use tss_esapi::structures::{
    EcDaaScheme, EccSignature as EsapiEccSignature, HmacScheme, RsaSignature as EsapiRsaSignature,
    Signature as EsapiSignature, SignatureScheme as EsapiSignatureScheme,
};

use crate::{
    Error, Result,
    algorithm::{EccSignature, RsaSignature},
    types::{
        Signature,
        tpm::{TpmsSchemeEcdaa, TpmtSigScheme, TpmuSigScheme},
    },
};

impl TryFrom<EsapiSignature> for Signature {
    type Error = Error;

    fn try_from(signature: EsapiSignature) -> Result<Self> {
        match signature {
            EsapiSignature::EcDsa(ecc_sig) => Ok(Self::Ecdsa(ecc_sig.try_into()?)),
            EsapiSignature::RsaPss(rsa_sig) => Ok(Self::RsaPss(rsa_sig.try_into()?)),
            EsapiSignature::RsaSsa(rsa_sig) => Ok(Self::RsaSsa(rsa_sig.try_into()?)),
            _ => Err(Error::conversion::<EsapiSignature, Signature>(None)),
        }
    }
}

impl TryFrom<EsapiEccSignature> for EccSignature {
    type Error = Error;

    fn try_from(ecc_sig: EsapiEccSignature) -> Result<Self> {
        Ok(Self::new(
            ecc_sig.hashing_algorithm().try_into()?,
            ecc_sig.signature_r().value(),
            ecc_sig.signature_s().value(),
        ))
    }
}

impl TryFrom<EsapiRsaSignature> for RsaSignature {
    type Error = Error;

    fn try_from(rsa_sig: EsapiRsaSignature) -> Result<Self> {
        Ok(Self::new(
            rsa_sig.hashing_algorithm().try_into()?,
            rsa_sig.signature().value(),
        ))
    }
}

impl TryFrom<TpmtSigScheme> for EsapiSignatureScheme {
    type Error = Error;

    fn try_from(sig_scheme: TpmtSigScheme) -> Result<Self> {
        match sig_scheme.details() {
            TpmuSigScheme::EcSchnorr(scheme_hash) => Ok(Self::EcSchnorr {
                hash_scheme: scheme_hash.try_into()?,
            }),
            TpmuSigScheme::Ecdaa(scheme_ecdaa) => Ok(Self::EcDaa {
                ecdaa_scheme: scheme_ecdaa.try_into()?,
            }),
            TpmuSigScheme::Ecdsa(scheme_hash) => Ok(Self::EcDsa {
                hash_scheme: scheme_hash.try_into()?,
            }),
            TpmuSigScheme::Hmac(scheme_hash) => Ok(Self::Hmac {
                hmac_scheme: HmacScheme::new(scheme_hash.hash_alg.try_into()?),
            }),
            TpmuSigScheme::RsaPss(scheme_hash) => Ok(Self::RsaPss {
                hash_scheme: scheme_hash.try_into()?,
            }),
            TpmuSigScheme::RsaSsa(scheme_hash) => Ok(Self::RsaSsa {
                hash_scheme: scheme_hash.try_into()?,
            }),
            TpmuSigScheme::Sm2(scheme_hash) => Ok(Self::Sm2 {
                hash_scheme: scheme_hash.try_into()?,
            }),
            TpmuSigScheme::Null => Ok(Self::Null),
            _ => Err(Error::conversion::<TpmtSigScheme, EsapiSignatureScheme>(
                Some(&sig_scheme),
            )),
        }
    }
}

impl TryFrom<TpmsSchemeEcdaa> for EcDaaScheme {
    type Error = Error;

    fn try_from(ecdaa_scheme: TpmsSchemeEcdaa) -> Result<Self> {
        Ok(Self::new(
            ecdaa_scheme.hash_alg.try_into()?,
            ecdaa_scheme.count,
        ))
    }
}
