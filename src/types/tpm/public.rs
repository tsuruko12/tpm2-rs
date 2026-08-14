use bitflags::bitflags;

use crate::{
    Error, Result, macros::{newtype, tpm2b_bytes_type}, public::RsaKeyBits, types::public::{
        KeyTemplate,
        ecc::EccTemplate,
        rsa::{RsaScheme, RsaTemplate},
    }
};
use super::{
    Tpm2bDigest, TpmAlgId, TpmHandle, TpmiAlgHash,
    algorithm::{
        TpmiAlgRsaScheme, TpmiRsaKeyBits, TpmsEccParms, TpmsEccPoint,
        TpmsKeyedHashParms, TpmsRsaParms, TpmsSymCipherParms, TpmtHa, TpmtRsaScheme,
    },
};

#[derive(Debug, Clone)]
pub(crate) struct Tpm2bPublic(TpmtPublic);

impl Tpm2bPublic {
    pub(crate) fn into_inner(self) -> TpmtPublic {
        self.0
    }

    pub(crate) fn as_inner(&self) -> &TpmtPublic {
        &self.0
    }
}

impl From<TpmtPublic> for Tpm2bPublic {
    fn from(public: TpmtPublic) -> Self {
        Self(public)
    }
}

impl Tpm2bPublic {
    pub(crate) fn from_template(template: &KeyTemplate, auth_policy: impl Into<Tpm2bDigest>) -> Self {
        let auth_policy = auth_policy.into();

        match template {
            KeyTemplate::Ecc(template) => TpmtPublic::ecc(template, auth_policy).into(),
            KeyTemplate::Rsa(template) => TpmtPublic::rsa(template, auth_policy).into(),
            KeyTemplate::Symmetric(_) => Self::rsa_decrypt(auth_policy),
        }
    }

    pub(crate) fn storage_parent() -> Self {
        TpmtPublic::new(
            TpmiAlgPublic::RSA, 
            TpmiAlgHash::SHA256, 
            TpmaObject::storage_parent(), 
            Tpm2bDigest::default(), 
            TpmuPublicParms::RsaDetail(TpmsRsaParms::storage_parent()), 
            TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::default()),
        )
        .into()
    }

    pub(crate) fn rsa_decrypt(auth_policy: Tpm2bDigest) -> Self {
        let rsa_params = TpmsRsaParms::unrestricted(
            TpmtRsaScheme::oaep(TpmiAlgHash::SHA256.into()),
            TpmiRsaKeyBits::BITS2048,
        );

        TpmtPublic::new(
            TpmiAlgPublic::RSA, 
            TpmiAlgHash::SHA256, 
            TpmaObject::decrypt(false, false), 
            auth_policy, 
            TpmuPublicParms::RsaDetail(rsa_params), 
            TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::default()),
        )
        .into()
    }

    pub(crate) fn is_storage_parent(&self) -> bool {
        let public = self.as_inner();

        if public.alg_type() != TpmiAlgPublic::RSA
            || !public
                .object_attributes()
                .contains(TpmaObject::RESTRICTED | TpmaObject::DECRYPT)
            || public
                .object_attributes()
                .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return false;
        }

        match public.parameters() {
            TpmuPublicParms::RsaDetail(parameters) => {
                !parameters.symmetric().is_null()
                    && matches!(parameters.scheme().into_parts().0, TpmiAlgRsaScheme::NULL)
            }
            _ => false,
        }
    }
}

#[derive(Clone)]
pub(crate) struct TpmtPublic {
    alg_type: TpmiAlgPublic,
    name_alg: TpmiAlgHash,
    object_attributes: TpmaObject,
    auth_policy: Tpm2bDigest,
    parameters: TpmuPublicParms,
    unique: TpmuPublicId,
}

impl std::fmt::Debug for TpmtPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmtPublic")
            .field("alg_type", &self.alg_type)
            .field("name_alg", &self.name_alg)
            .field("object_attributes", &self.object_attributes)
            .field("parameters", &self.parameters)
            .finish_non_exhaustive()
    }
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

    fn ecc(template: &EccTemplate, auth_policy: Tpm2bDigest) -> Self {
        let parameters = TpmuPublicParms::EccDetail(
            TpmsEccParms::ecdsa(
                template.curve().into(), 
                template.scheme().into(),
            )
        );

        Self { 
            alg_type: TpmiAlgPublic::ECC, 
            name_alg: TpmiAlgHash::SHA256, 
            object_attributes: TpmaObject::sign(false, template.exportable()), 
            auth_policy, 
            parameters, 
            unique: TpmuPublicId::Ecc(TpmsEccPoint::default()),
        }
    }

    fn rsa(template: &RsaTemplate, auth_policy: Tpm2bDigest) -> Self {
        let duplicable = template.exportable();
        let (rsa_params, object_attributes) = match template.scheme() {
            Some(scheme) => {
                let params = TpmsRsaParms::unrestricted(scheme.into(), template.key_bits().into());
                let attrs = if matches!(scheme, RsaScheme::Oaep(_) | RsaScheme::RsaEs) {
                    TpmaObject::decrypt(false, duplicable)
                } else {
                    TpmaObject::sign(false, duplicable)
                };

                (params, attrs)
            },
            None => (TpmsRsaParms::storage_parent(), TpmaObject::storage_parent()),
        };
        let parameters = TpmuPublicParms::RsaDetail(rsa_params);

        Self { 
            alg_type: TpmiAlgPublic::RSA, 
            name_alg: TpmiAlgHash::SHA256, 
            object_attributes, 
            auth_policy, 
            parameters, 
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

newtype!(TpmiAlgPublic(TpmAlgId));

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
    pub(crate) fn keyed_hash(digest: Tpm2bDigest) -> Self {
        Self::KeyedHash(digest)
    }

    pub(crate) fn sym(digest: Tpm2bDigest) -> Self {
        Self::Sym(digest)
    }

    pub(crate) fn rsa(public_key: Tpm2bPublicKeyRsa) -> Self {
        Self::Rsa(public_key)
    }

    pub(crate) fn ecc(point: TpmsEccPoint) -> Self {
        Self::Ecc(point)
    }
}

tpm2b_bytes_type!(Tpm2bPublicKeyRsa, RsaKeyBits::MAX_BITS / 8); // TODO: consider zeroize type not to be debug

impl zeroize::Zeroize for Tpm2bPublicKeyRsa {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
tpm2b_bytes_type!(Tpm2bName, TpmtHa::MAX_BYTES);

// size 4 -> handle (TPM_HANDLE)
// size 0 -> no name
// others -> TPM_ALG_ID + digest (TPMT_HA)

impl Tpm2bName {
    const NO_NAME_SIZE: usize = 0;
    const HANDLE_SIZE: usize = size_of::<TpmHandle>();
}
