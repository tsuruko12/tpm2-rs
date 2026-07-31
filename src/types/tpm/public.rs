use bitflags::bitflags;

use crate::{
    Error, Result,
    macros::newtype,
    types::{
        TpmiRsaKeyBits, TpmtRsaScheme,
        tpm::{keyed_hash::TpmsKeyedHashParms, symmetric::TpmsSymCipherParms},
    },
};

use super::{
    TpmAlgId, TpmiAlgHash,
    digest::Tpm2bDigest,
    ecc::{TpmsEccParms, TpmsEccPoint},
    rsa::{Tpm2bPublicKeyRsa, TpmsRsaParms},
};

#[derive(Debug, Clone)]
pub(crate) struct TpmtPublic {
    alg_type: TpmiAlgPublic,
    name_alg: TpmiAlgHash,
    object_attributes: TpmaObject,
    auth_policy: Tpm2bDigest,
    parameters: TpmuPublicParms,
    unique: TpmuPublicId,
}

impl TpmtPublic {
    pub(crate) fn new(
        alg_type: TpmiAlgPublic,
        name_alg: impl Into<TpmiAlgHash>,
        object_attributes: TpmaObject,
        auth_policy: Tpm2bDigest,
        parameters: TpmuPublicParms,
        unique: TpmuPublicId,
    ) -> Self {
        Self {
            alg_type: alg_type,
            name_alg: name_alg.into(),
            object_attributes,
            auth_policy,
            parameters,
            unique,
        }
    }

    pub(crate) fn storage_parent() -> Self {
        Self {
            alg_type: TpmiAlgPublic::RSA,
            name_alg: TpmiAlgHash::SHA256,
            object_attributes: TpmaObject::storage_parent(),
            auth_policy: Tpm2bDigest::default(),
            parameters: TpmuPublicParms::RsaDetail(TpmsRsaParms::storage_parent()),
            unique: TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::default()),
        }
    }

    pub(crate) fn rsa_decrypt() -> Self {
        let rsa_params = TpmsRsaParms::unrestricted(
            TpmtRsaScheme::oaep(TpmiAlgHash::SHA256.into()),
            TpmiRsaKeyBits::BITS2048,
        );

        Self {
            alg_type: TpmiAlgPublic::RSA,
            name_alg: TpmiAlgHash::SHA256,
            object_attributes: TpmaObject::decrypt(false, false),
            auth_policy: Tpm2bDigest::default(),
            parameters: TpmuPublicParms::RsaDetail(rsa_params),
            unique: TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::default()),
        }
    }

    pub(crate) fn alg_type(&self) -> TpmiAlgPublic {
        self.alg_type
    }

    pub(crate) fn name_alg(&self) -> TpmiAlgHash {
        self.name_alg
    }

    pub(crate) fn object_attributes(&self) -> TpmaObject {
        self.object_attributes
    }

    pub(crate) fn auth_policy(&self) -> &Tpm2bDigest {
        &self.auth_policy
    }

    pub(crate) fn parameters(&self) -> TpmuPublicParms {
        self.parameters
    }

    pub(crate) fn unique(&self) -> &TpmuPublicId {
        &self.unique
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TpmuPublicParms {
    SymDetail(TpmsSymCipherParms),
    KeyedHashDetail(TpmsKeyedHashParms),
    RsaDetail(TpmsRsaParms),
    EccDetail(TpmsEccParms),
}

newtype!(TpmiAlgPublic(TpmAlgId) => u16);

impl TpmiAlgPublic {
    pub(crate) const RSA: Self = Self(TpmAlgId::Rsa);
    pub(crate) const KEYED_HASH: Self = Self(TpmAlgId::KeyedHash);
    pub(crate) const ECC: Self = Self(TpmAlgId::Ecc);
    pub(crate) const SYM_CIPHER: Self = Self(TpmAlgId::SymCipher);
}

impl TryFrom<TpmAlgId> for TpmiAlgPublic {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        match alg {
            TpmAlgId::Rsa
            | TpmAlgId::KeyedHash
            | TpmAlgId::Ecc
            | TpmAlgId::SymCipher
            | TpmAlgId::MlDsa
            | TpmAlgId::HashMlDsa
            | TpmAlgId::MlKem => Ok(Self(alg)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgPublic>(Some(&alg))),
        }
    }
}

impl TryFrom<u16> for TpmiAlgPublic {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        TpmAlgId::try_from(value)?.try_into()
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct TpmaObject: u32 {
        const FIXED_TPM = 0x0000_0002;
        const ST_CLEAR = 0x0000_0004;
        const FIXED_PARENT = 0x0000_0010;
        const SENSITIVE_DATA_ORIGIN = 0x0000_0020;
        const USER_WITH_AUTH = 0x0000_0040;
        const ADMIN_WITH_POLICY = 0x0000_0080;
        const FIRMWARE_LIMITED = 0x0000_0100;
        const SVN_LIMITED = 0x0000_0200;
        const NO_DA = 0x0000_0400;
        const ENCRYPTED_DUPLICATION = 0x0000_0800;
        const RESTRICTED = 0x0001_0000;
        const DECRYPT = 0x0002_0000;
        const SIGN_ENCRYPT = 0x0004_0000;
        const X509_SIGN = 0x0008_0000;
    }
}

impl TpmaObject {
    fn base() -> Self {
        Self::SENSITIVE_DATA_ORIGIN | Self::USER_WITH_AUTH
    }

    fn sign(restricted: bool, duplicable: bool) -> Self {
        let mut attrs = Self::base() | Self::SIGN_ENCRYPT;

        if restricted {
            attrs |= Self::RESTRICTED;
        }

        if !duplicable {
            attrs |= Self::FIXED_TPM | Self::FIXED_PARENT;
        }

        attrs
    }

    fn decrypt(restricted: bool, duplicable: bool) -> Self {
        let mut attrs = Self::base() | Self::DECRYPT;

        if restricted {
            attrs |= Self::RESTRICTED;
        }

        if !duplicable {
            attrs |= Self::FIXED_TPM | Self::FIXED_PARENT;
        }

        attrs
    }

    fn storage_parent() -> Self {
        Self::base()
            | Self::FIXED_TPM
            | Self::FIXED_PARENT
            | Self::NO_DA
            | Self::RESTRICTED
            | Self::DECRYPT
    }
}

#[derive(Debug, Clone)]
pub(crate) enum TpmuPublicId {
    KeyedHash(Tpm2bDigest),
    Sym(Tpm2bDigest),
    Rsa(Tpm2bPublicKeyRsa),
    Ecc(TpmsEccPoint),
}

impl TpmuPublicId {
    pub(crate) fn keyed_hash(value: Tpm2bDigest) -> Self {
        Self::KeyedHash(value)
    }

    pub(crate) fn sym(value: Tpm2bDigest) -> Self {
        Self::Sym(value)
    }

    pub(crate) fn rsa(value: Vec<u8>) -> Self {
        Self::Rsa(Tpm2bPublicKeyRsa::from(value))
    }

    pub(crate) fn ecc(x: Vec<u8>, y: Vec<u8>) -> Self {
        Self::Ecc(TpmsEccPoint::new(x, y))
    }
}
