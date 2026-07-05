use tracing::error;
use tss_esapi::{
    constants::AlgorithmIdentifier, interface_types::algorithm::HashingAlgorithm,
    structures::AlgorithmPropertyList,
};

use crate::{
    Error, Result,
    types::{TpmAlgId, TpmaAlgorithm, TpmlAlgProperty, TpmsAlgProperty},
};

impl TryFrom<TpmAlgId> for HashingAlgorithm {
    type Error = Error;

    fn try_from(value: TpmAlgId) -> Result<Self> {
        match value {
            TpmAlgId::Sha1 => Ok(Self::Sha1),
            TpmAlgId::Sha256 => Ok(Self::Sha256),
            TpmAlgId::Sha384 => Ok(Self::Sha384),
            TpmAlgId::Sha512 => Ok(Self::Sha512),
            TpmAlgId::Sm3_256 => Ok(Self::Sm3_256),
            TpmAlgId::Sha3_256 => Ok(Self::Sha3_256),
            TpmAlgId::Sha3_384 => Ok(Self::Sha3_384),
            TpmAlgId::Sha3_512 => Ok(Self::Sha3_512),
            TpmAlgId::Null => Ok(Self::Null),
            _ => {
                error!(value = ?value, "failed to convert to ESAPI value");
                Err(Error::Internal(
                    "failed to convert algorithm identifier to ESAPI value",
                ))
            }
        }
    }
}

impl From<HashingAlgorithm> for TpmAlgId {
    fn from(value: HashingAlgorithm) -> Self {
        match value {
            HashingAlgorithm::Sha1 => Self::Sha1,
            HashingAlgorithm::Sha256 => Self::Sha256,
            HashingAlgorithm::Sha384 => Self::Sha384,
            HashingAlgorithm::Sha512 => Self::Sha512,
            HashingAlgorithm::Sm3_256 => Self::Sm3_256,
            HashingAlgorithm::Sha3_256 => Self::Sha3_256,
            HashingAlgorithm::Sha3_384 => Self::Sha3_384,
            HashingAlgorithm::Sha3_512 => Self::Sha3_512,
            HashingAlgorithm::Null => Self::Null,
        }
    }
}

impl TryFrom<TpmAlgId> for AlgorithmIdentifier {
    type Error = Error;

    fn try_from(value: TpmAlgId) -> Result<Self> {
        Self::try_from(value as u16).map_err(|_| {
            error!(value = ?value, "failed to convert to ESAPI value");
            Error::Internal("failed to convert algorithm identifier to ESAPI value")
        })
    }
}

impl TryFrom<AlgorithmIdentifier> for TpmAlgId {
    type Error = Error;

    fn try_from(value: AlgorithmIdentifier) -> Result<Self> {
        Self::try_from(u16::from(value)).map_err(|_| {
            error!(value = ?value, "failed to convert to algorithm identifier");
            Error::Internal("failed to convert ESAPI value to algorithm identifier")
        })
    }
}

impl TryFrom<AlgorithmPropertyList> for TpmlAlgProperty {
    type Error = Error;

    fn try_from(value: AlgorithmPropertyList) -> Result<Self> {
        let mut items = Vec::new();

        for item in value.as_ref() {
            let alg = TpmAlgId::try_from(item.algorithm_identifier())?;
            let alg_properties = TpmaAlgorithm::new(item.algorithm_properties().into());

            items.push(TpmsAlgProperty::new(alg, alg_properties));
        }

        Ok(Self::new(items))
    }
}
