use crate::{
    Error, Result,
    macros::{newtype, tpm_list_type},
    types::algorithm::HashAlgorithm,
};

tpm_list_type!(TpmlAlgProperty(TpmsAlgProperty););

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TpmsAlgProperty {
    alg: TpmAlgId,
    alg_properties: TpmaAlgorithm,
}

impl TpmsAlgProperty {
    pub(crate) const fn new(alg: TpmAlgId, alg_properties: TpmaAlgorithm) -> Self {
        Self {
            alg,
            alg_properties,
        }
    }

    pub(crate) const fn alg(self) -> TpmAlgId {
        self.alg
    }

    pub(crate) const fn alg_properties(self) -> TpmaAlgorithm {
        self.alg_properties
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TpmAlgId {
    Rsa = 0x0001,
    Tdes = 0x0003,
    Sha1 = 0x0004,
    Hmac = 0x0005,
    Aes = 0x0006,
    Mgf1 = 0x0007,
    KeyedHash = 0x0008,
    Xor = 0x000A,
    Sha256 = 0x000B,
    Sha384 = 0x000C,
    Sha512 = 0x000D,
    Sha256_192 = 0x000E,
    Null = 0x0010,
    Sm3_256 = 0x0012,
    Sm4 = 0x0013,
    RsaSsa = 0x0014,
    RsaEs = 0x0015,
    RsaPss = 0x0016,
    Oaep = 0x0017,
    Ecdsa = 0x0018,
    Ecdh = 0x0019,
    Ecdaa = 0x001A,
    Sm2 = 0x001B,
    EcSchnorr = 0x001C,
    EcMqv = 0x001D,
    Hkdf = 0x001F,
    Kdf1Sp80056a = 0x0020,
    Kdf2 = 0x0021,
    Kdf1Sp800108 = 0x0022,
    Ecc = 0x0023,
    SymCipher = 0x0025,
    Camellia = 0x0026,
    Sha3_256 = 0x0027,
    Sha3_384 = 0x0028,
    Sha3_512 = 0x0029,
    Shake256_192 = 0x002C,
    Shake256_256 = 0x002D,
    Shake256_512 = 0x002E,
    Cmac = 0x003F,
    Ctr = 0x0040,
    Ofb = 0x0041,
    Cbc = 0x0042,
    Cfb = 0x0043,
    Ecb = 0x0044,
    EdDsa = 0x0060,
    HashEdDsa = 0x0061,
    MlKem = 0x00A0,
    MlDsa = 0x00A1,
    HashMlDsa = 0x00A2,
}

impl TpmAlgId {
    pub(crate) fn raw(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for TpmAlgId {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0x0001 => Ok(Self::Rsa),
            0x0003 => Ok(Self::Tdes),
            0x0004 => Ok(Self::Sha1),
            0x0005 => Ok(Self::Hmac),
            0x0006 => Ok(Self::Aes),
            0x0007 => Ok(Self::Mgf1),
            0x0008 => Ok(Self::KeyedHash),
            0x000A => Ok(Self::Xor),
            0x000B => Ok(Self::Sha256),
            0x000C => Ok(Self::Sha384),
            0x000D => Ok(Self::Sha512),
            0x000E => Ok(Self::Sha256_192),
            0x0010 => Ok(Self::Null),
            0x0012 => Ok(Self::Sm3_256),
            0x0013 => Ok(Self::Sm4),
            0x0014 => Ok(Self::RsaSsa),
            0x0015 => Ok(Self::RsaEs),
            0x0016 => Ok(Self::RsaPss),
            0x0017 => Ok(Self::Oaep),
            0x0018 => Ok(Self::Ecdsa),
            0x0019 => Ok(Self::Ecdh),
            0x001A => Ok(Self::Ecdaa),
            0x001B => Ok(Self::Sm2),
            0x001C => Ok(Self::EcSchnorr),
            0x001D => Ok(Self::EcMqv),
            0x001F => Ok(Self::Hkdf),
            0x0020 => Ok(Self::Kdf1Sp80056a),
            0x0021 => Ok(Self::Kdf2),
            0x0022 => Ok(Self::Kdf1Sp800108),
            0x0023 => Ok(Self::Ecc),
            0x0025 => Ok(Self::SymCipher),
            0x0026 => Ok(Self::Camellia),
            0x0027 => Ok(Self::Sha3_256),
            0x0028 => Ok(Self::Sha3_384),
            0x0029 => Ok(Self::Sha3_512),
            0x002C => Ok(Self::Shake256_192),
            0x002D => Ok(Self::Shake256_256),
            0x002E => Ok(Self::Shake256_512),
            0x003F => Ok(Self::Cmac),
            0x0040 => Ok(Self::Ctr),
            0x0041 => Ok(Self::Ofb),
            0x0042 => Ok(Self::Cbc),
            0x0043 => Ok(Self::Cfb),
            0x0044 => Ok(Self::Ecb),
            0x0060 => Ok(Self::EdDsa),
            0x0061 => Ok(Self::HashEdDsa),
            0x00A0 => Ok(Self::MlKem),
            0x00A1 => Ok(Self::MlDsa),
            0x00A2 => Ok(Self::HashMlDsa),
            _ => Err(Error::conversion::<u16, TpmAlgId>(None)),
        }
    }
}

newtype!(TpmiAlgHash(TpmAlgId) => u16);

impl TpmiAlgHash {
    pub(crate) const SHA1: Self = Self(TpmAlgId::Sha1);
    pub(crate) const SHA256: Self = Self(TpmAlgId::Sha256);
    pub(crate) const SHA384: Self = Self(TpmAlgId::Sha384);
    pub(crate) const SHA512: Self = Self(TpmAlgId::Sha512);
    pub(crate) const SHA256_192: Self = Self(TpmAlgId::Sha256_192);
    pub(crate) const SM3_256: Self = Self(TpmAlgId::Sm3_256);
    pub(crate) const SHA3_256: Self = Self(TpmAlgId::Sha3_256);
    pub(crate) const SHA3_384: Self = Self(TpmAlgId::Sha3_384);
    pub(crate) const SHA3_512: Self = Self(TpmAlgId::Sha3_512);
    pub(crate) const SHAKE256_192: Self = Self(TpmAlgId::Shake256_192);
    pub(crate) const SHAKE256_256: Self = Self(TpmAlgId::Shake256_256);
    pub(crate) const SHAKE256_512: Self = Self(TpmAlgId::Shake256_512);
    pub(crate) const NULL: Self = Self(TpmAlgId::Null);
}

impl TryFrom<TpmAlgId> for TpmiAlgHash {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        match alg {
            TpmAlgId::Sha1
            | TpmAlgId::Sha256
            | TpmAlgId::Sha384
            | TpmAlgId::Sha512
            | TpmAlgId::Sha256_192
            | TpmAlgId::Null
            | TpmAlgId::Sm3_256
            | TpmAlgId::Sha3_256
            | TpmAlgId::Sha3_384
            | TpmAlgId::Sha3_512
            | TpmAlgId::Shake256_192
            | TpmAlgId::Shake256_256
            | TpmAlgId::Shake256_512 => Ok(Self(alg)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgHash>(Some(&alg))),
        }
    }
}

impl TryFrom<u16> for TpmiAlgHash {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        Self::try_from(TpmAlgId::try_from(value)?)
    }
}

impl From<HashAlgorithm> for TpmiAlgHash {
    fn from(hash: HashAlgorithm) -> Self {
        match hash {
            HashAlgorithm::Sha1 => Self::SHA1,
            HashAlgorithm::Sha256 => Self::SHA256,
            HashAlgorithm::Sha384 => Self::SHA384,
            HashAlgorithm::Sha512 => Self::SHA512,
        }
    }
}

impl From<HashAlgorithm> for TpmsSchemeHash {
    fn from(hash: HashAlgorithm) -> Self {
        Self {
            hash_alg: hash.into(),
        }
    }
}

impl From<TpmiAlgHash> for TpmsSchemeHash {
    fn from(hash_alg: TpmiAlgHash) -> Self {
        Self { hash_alg }
    }
}

newtype!(TpmiAlgKdf(TpmAlgId) => u16);

impl TpmiAlgKdf {
    pub(crate) const MGF1: Self = Self(TpmAlgId::Mgf1);
    pub(crate) const KDF2: Self = Self(TpmAlgId::Kdf2);
    pub(crate) const KDF1_SP800_56A: Self = Self(TpmAlgId::Kdf1Sp80056a);
    pub(crate) const KDF1_SP800_108: Self = Self(TpmAlgId::Kdf1Sp800108);
    pub(crate) const NULL: Self = Self(TpmAlgId::Null);
}

impl TryFrom<u16> for TpmiAlgKdf {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        TpmAlgId::try_from(value)?.try_into()
    }
}

impl TryFrom<TpmAlgId> for TpmiAlgKdf {
    type Error = Error;

    fn try_from(alg: TpmAlgId) -> Result<Self> {
        match alg {
            TpmAlgId::Mgf1
            | TpmAlgId::Kdf2
            | TpmAlgId::Kdf1Sp80056a
            | TpmAlgId::Kdf1Sp800108
            | TpmAlgId::Hkdf
            | TpmAlgId::Null => Ok(Self(alg)),
            _ => Err(Error::conversion::<TpmAlgId, TpmiAlgKdf>(Some(&alg))),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmsSchemeHash {
    pub(crate) hash_alg: TpmiAlgHash,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmsEmpty;

#[derive(Debug, Clone, Copy)]
pub(crate) struct TpmtKdfScheme {
    scheme: TpmiAlgKdf,
    details: TpmuKdfScheme,
}

impl TpmtKdfScheme {
    pub(crate) fn mgf1(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgKdf::MGF1,
            details: TpmuKdfScheme::Mgf1(scheme_hash),
        }
    }

    pub(crate) fn kdf2(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgKdf::KDF2,
            details: TpmuKdfScheme::Kdf2(scheme_hash),
        }
    }

    pub(crate) fn kdf1_sp800_56a(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgKdf::KDF1_SP800_56A,
            details: TpmuKdfScheme::Kdf1Sp800_56a(scheme_hash),
        }
    }

    pub(crate) fn kdf1_sp800_108(scheme_hash: TpmsSchemeHash) -> Self {
        Self {
            scheme: TpmiAlgKdf::KDF1_SP800_108,
            details: TpmuKdfScheme::Kdf1Sp800_108(scheme_hash),
        }
    }

    pub(crate) fn null() -> Self {
        Self {
            scheme: TpmiAlgKdf::NULL,
            details: TpmuKdfScheme::Null,
        }
    }

    pub(crate) fn into_parts(self) -> (TpmiAlgKdf, TpmuKdfScheme) {
        (self.scheme, self.details)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TpmuKdfScheme {
    Mgf1(TpmsSchemeHash),
    Kdf2(TpmsSchemeHash),
    Kdf1Sp800_56a(TpmsSchemeHash),
    Kdf1Sp800_108(TpmsSchemeHash),
    Null,
}

newtype!(TpmaAlgorithm(u32));

impl TpmaAlgorithm {
    const ASYMMETRIC: u32 = 1 << 0;
    const SYMMETRIC: u32 = 1 << 1;
    const HASH: u32 = 1 << 2;
    const OBJECT: u32 = 1 << 3;
    const SIGNING: u32 = 1 << 8;
    const ENCRYPTING: u32 = 1 << 9;
    const METHOD: u32 = 1 << 10;

    pub(crate) const fn is_asymmetric(&self) -> bool {
        self.contains(Self::ASYMMETRIC)
    }

    pub(crate) const fn is_symmetric(&self) -> bool {
        self.contains(Self::SYMMETRIC)
    }

    pub(crate) const fn is_hash(&self) -> bool {
        self.contains(Self::HASH)
    }

    pub(crate) const fn is_object(&self) -> bool {
        self.contains(Self::OBJECT)
    }

    pub(crate) const fn is_signing(&self) -> bool {
        self.contains(Self::SIGNING)
    }

    pub(crate) const fn is_encrypting(&self) -> bool {
        self.contains(Self::ENCRYPTING)
    }

    pub(crate) const fn is_method(&self) -> bool {
        self.contains(Self::METHOD)
    }

    const fn contains(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }
}

impl From<u32> for TpmaAlgorithm {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
