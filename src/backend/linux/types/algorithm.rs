use tss_esapi::{
    constants::AlgorithmIdentifier,
    interface_types::algorithm::HashingAlgorithm,
    structures::{AlgorithmPropertyList, HashScheme, KeyDerivationFunctionScheme},
};

use crate::{
    Error, Result,
    algorithm::HashAlgorithm,
    types::{
        TpmAlgId, TpmaAlgorithm, TpmiAlgHash, TpmlAlgProperty, TpmsAlgProperty, TpmsSchemeHash,
        TpmtKdfScheme,
    },
};

impl TryFrom<TpmiAlgHash> for HashingAlgorithm {
    type Error = Error;

    fn try_from(hash: TpmiAlgHash) -> Result<Self> {
        hash.raw()
            .try_into()
            .map_err(|_| Error::conversion::<TpmiAlgHash, HashingAlgorithm>(Some(&hash)))
    }
}

impl From<HashingAlgorithm> for TpmiAlgHash {
    fn from(hash: HashingAlgorithm) -> Self {
        match hash {
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
    fn from(hash: HashAlgorithm) -> Self {
        match hash {
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
    fn from(hash: HashingAlgorithm) -> Self {
        Self {
            hash_alg: hash.into(),
        }
    }
}

impl TryFrom<TpmAlgId> for AlgorithmIdentifier {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        alg.raw()
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

impl From<KeyDerivationFunctionScheme> for TpmtKdfScheme {
    fn from(kdf_scheme: KeyDerivationFunctionScheme) -> Self {
        match kdf_scheme {
            KeyDerivationFunctionScheme::Kdf1Sp800_108(hash) => Self::kdf1_sp800_108(hash.into()),
            KeyDerivationFunctionScheme::Kdf1Sp800_56a(hash) => Self::kdf1_sp800_56a(hash.into()),
            KeyDerivationFunctionScheme::Kdf2(hash) => Self::kdf2(hash.into()),
            KeyDerivationFunctionScheme::Mgf1(hash) => Self::mgf1(hash.into()),
            KeyDerivationFunctionScheme::Null => Self::null(),
        }
    }
}
