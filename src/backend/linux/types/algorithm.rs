use tss_esapi::{
    constants::{AlgorithmIdentifier, EccCurveIdentifier},
    interface_types::algorithm::HashingAlgorithm,
    structures::{AlgorithmPropertyList, EccCurveList, HashScheme},
};

use crate::{
    Error, Result,
    algorithm::HashAlgorithm,
    types::tpm::{
        TpmAlgId, TpmEccCurve, TpmaAlgorithm, TpmiAlgHash, TpmlAlgProperty, TpmlEccCurve, TpmsAlgProperty, TpmsSchemeHash
    },
};

impl TryFrom<TpmiAlgHash> for HashingAlgorithm {
    type Error = Error;

    fn try_from(hash_alg: TpmiAlgHash) -> Result<Self> {
        hash_alg.value()
            .try_into()
            .map_err(|_| Error::conversion::<TpmiAlgHash, HashingAlgorithm>(Some(&hash_alg)))
    }
}

impl From<HashingAlgorithm> for TpmiAlgHash {
    fn from(hash_alg: HashingAlgorithm) -> Self {
        match hash_alg {
            HashingAlgorithm::Sha1 => Self::SHA1,
            HashingAlgorithm::Sha256 => Self::SHA256,
            HashingAlgorithm::Sha384 => Self::SHA384,
            HashingAlgorithm::Sha512 => Self::SHA512,
            HashingAlgorithm::Sm3_256 => Self::SM3_256,
            HashingAlgorithm::Sha3_256 => Self::SHA3_256,
            HashingAlgorithm::Sha3_384 => Self::SHA3_384,
            HashingAlgorithm::Sha3_512 => Self::SHA3_512,
            HashingAlgorithm::Null => Self::NULL,
        }
    }
}

impl From<HashAlgorithm> for HashingAlgorithm {
    fn from(hash_alg: HashAlgorithm) -> Self {
        match hash_alg {
            HashAlgorithm::Sha1 => Self::Sha1,
            HashAlgorithm::Sha256 => Self::Sha256,
            HashAlgorithm::Sha384 => Self::Sha384,
            HashAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

impl From<HashScheme> for TpmsSchemeHash {
    fn from(hash_scheme: HashScheme) -> Self {
        Self {
            hash_alg: hash_scheme.hashing_algorithm().into(),
        }
    }
}

impl TryFrom<TpmsSchemeHash> for HashScheme {
    type Error = Error;

    fn try_from(hash_scheme: TpmsSchemeHash) -> Result<Self> {
        Ok(Self::new(hash_scheme.hash_alg.try_into()?))
    }
}

impl From<HashingAlgorithm> for TpmsSchemeHash {
    fn from(hash_alg: HashingAlgorithm) -> Self {
        Self {
            hash_alg: hash_alg.into(),
        }
    }
}

impl TryFrom<TpmAlgId> for AlgorithmIdentifier {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        alg.value()
            .try_into()
            .map_err(|_| Error::conversion::<TpmAlgId, AlgorithmIdentifier>(Some(&alg)))
    }
}

impl TryFrom<AlgorithmIdentifier> for TpmAlgId {
    type Error = Error;

    fn try_from(alg_id: AlgorithmIdentifier) -> Result<Self> {
        (alg_id as u16).try_into()
    }
}

impl TryFrom<AlgorithmPropertyList> for TpmlAlgProperty {
    type Error = Error;

    fn try_from(alg_prop_list: AlgorithmPropertyList) -> Result<Self> {
        let items = alg_prop_list
            .iter()
            .map(|item| {
                let alg = TpmAlgId::try_from(item.algorithm_identifier())?;
                let alg_properties = TpmaAlgorithm::from(u32::from(item.algorithm_properties()));

                Ok(TpmsAlgProperty::new(alg, alg_properties))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(items.into())
    }
}

impl From<EccCurveList> for TpmlEccCurve {
    fn from(curve_list: EccCurveList) -> Self {
        let items = curve_list
            .into_inner()
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();

        items.into()
    }
}

impl From<EccCurveIdentifier> for TpmEccCurve {
    fn from(curve_id: EccCurveIdentifier) -> Self {
        match curve_id {
            EccCurveIdentifier::BnP256 => Self::BnP256,
            EccCurveIdentifier::BnP638 => Self::BnP638,
            EccCurveIdentifier::NistP192 => Self::NistP192,
            EccCurveIdentifier::NistP224 => Self::NistP224,
            EccCurveIdentifier::NistP256 => Self::NistP256,
            EccCurveIdentifier::NistP384 => Self::NistP384,
            EccCurveIdentifier::NistP521 => Self::NistP521,
            EccCurveIdentifier::Sm2P256 => Self::Sm2P256,
        }
    }
}