use tss_esapi::{
    constants::AlgorithmIdentifier,
    interface_types::algorithm::HashingAlgorithm,
    structures::{AlgorithmPropertyList, HashScheme, KeyDerivationFunctionScheme},
    tss2_esys::{TPMS_SCHEME_HASH, TPMT_KDF_SCHEME, TPMU_KDF_SCHEME},
};

use crate::{
    Error, Result,
    algorithm::HashAlgorithm,
    types::{
        TpmAlgId, TpmaAlgorithm, TpmiAlgHash, TpmlAlgProperty, TpmsAlgProperty, TpmsSchemeHash,
        TpmtKdfScheme, TpmuKdfScheme,
    },
};

impl TryFrom<TpmiAlgHash> for HashingAlgorithm {
    type Error = Error;

    fn try_from(hash_alg: TpmiAlgHash) -> Result<Self> {
        hash_alg.raw()
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
            KeyDerivationFunctionScheme::Kdf1Sp800_108(hash_scheme) => Self::kdf1_sp800_108(
                hash_scheme.into()
            ),
            KeyDerivationFunctionScheme::Kdf1Sp800_56a(hash_scheme) => Self::kdf1_sp800_56a(
                hash_scheme.into()
            ),
            KeyDerivationFunctionScheme::Kdf2(hash_scheme) => Self::kdf2(hash_scheme.into()),
            KeyDerivationFunctionScheme::Mgf1(hash_scheme) => Self::mgf1(hash_scheme.into()),
            KeyDerivationFunctionScheme::Null => Self::null(),
        }
    }
}

impl TryFrom<TPMS_SCHEME_HASH> for TpmsSchemeHash {
    type Error = Error;

    fn try_from(scheme_hash: TPMS_SCHEME_HASH) -> Result<Self> {
        Ok(Self {
            hash_alg: scheme_hash.hashAlg.try_into()?,
        })
    }
}

impl From<TpmsSchemeHash> for TPMS_SCHEME_HASH {
    fn from(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            hashAlg: scheme_hash.hash_alg.raw(),
        }
    }
}

impl TryFrom<TPMT_KDF_SCHEME> for TpmtKdfScheme {
    type Error = Error;

    fn try_from(kdf_scheme: TPMT_KDF_SCHEME) -> Result<Self> {
        let scheme = TpmAlgId::try_from(kdf_scheme.scheme)?;

        match scheme {
            TpmAlgId::Mgf1 => Ok(Self::mgf1(unsafe { kdf_scheme.details.mgf1 }.try_into()?)),
            TpmAlgId::Kdf1Sp80056a => Ok(Self::kdf1_sp800_56a(
                unsafe { kdf_scheme.details.kdf1_sp800_56a }.try_into()?,
            )),
            TpmAlgId::Kdf2 => Ok(Self::kdf2(unsafe { kdf_scheme.details.kdf2 }.try_into()?)),
            TpmAlgId::Kdf1Sp800108 => Ok(Self::kdf1_sp800_108(
                unsafe { kdf_scheme.details.kdf1_sp800_108 }.try_into()?,
            )),
            TpmAlgId::Null => Ok(Self::null()),
            _ => Err(Error::conversion::<TpmAlgId, TpmtKdfScheme>(Some(&scheme))),
        }
    }
}

impl TryFrom<TpmtKdfScheme> for TPMT_KDF_SCHEME {
    type Error = Error;

    fn try_from(kdf_scheme: TpmtKdfScheme) -> Result<Self> {
        let (scheme, details) = kdf_scheme.into_parts();
        let raw_scheme = scheme.raw();
        let details = match (TpmAlgId::try_from(raw_scheme)?, details) {
            (TpmAlgId::Mgf1, TpmuKdfScheme::Mgf1(scheme_hash)) => TPMU_KDF_SCHEME { 
                mgf1: scheme_hash.into() 
            },
            (TpmAlgId::Kdf1Sp80056a, TpmuKdfScheme::Kdf1Sp800_56a(scheme_hash)) => TPMU_KDF_SCHEME { 
                kdf1_sp800_56a: scheme_hash.into() 
            },
            (TpmAlgId::Kdf2, TpmuKdfScheme::Kdf2(scheme_hash)) => TPMU_KDF_SCHEME { 
                kdf2: scheme_hash.into() 
            },
            (TpmAlgId::Kdf1Sp800108, TpmuKdfScheme::Kdf1Sp800_108(scheme_hash)) => TPMU_KDF_SCHEME { 
                kdf1_sp800_108: scheme_hash.into() 
            },
            (TpmAlgId::Null, TpmuKdfScheme::Null) => TPMU_KDF_SCHEME::default(),
            _ => return Err(Error::invalid_state("KDF scheme and details are inconsistent")),
        };

        Ok(Self {
            scheme: raw_scheme,
            details,
        })
    }
}
