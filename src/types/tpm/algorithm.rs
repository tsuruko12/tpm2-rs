use crate::{
    Error, Result, macros::{newtype, tpm_list_type, unknown_tpm_data}, types::algorithm::HashAlgorithm,
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

    fn try_from(raw: u16) -> Result<Self> {
        match raw {
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
            _ => unknown_tpm_data!(raw, "algorithm identifier"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TpmiAlgHash(TpmAlgId);

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

    pub(crate) fn raw(self) -> u16 {
        self.0.raw()
    }
}

impl TryFrom<TpmAlgId> for TpmiAlgHash {
    type Error = Error;

    fn try_from(alg_id: TpmAlgId) -> Result<Self> {
        match alg_id {
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
                | TpmAlgId::Shake256_512 => Ok(Self(alg_id)),
            _ => unknown_tpm_data!(alg_id, "hash algorithm identifier"),
        }
    }
}

impl From<TpmiAlgHash> for TpmAlgId {
    fn from(value: TpmiAlgHash) -> Self {
        value.0
    }
}

impl TryFrom<u16> for TpmiAlgHash {
    type Error = Error;

    fn try_from(raw: u16) -> Result<Self> {
        Self::try_from(TpmAlgId::try_from(raw)?)
    }
}

impl From<HashAlgorithm> for TpmiAlgHash {
    fn from(hash_alg: HashAlgorithm) -> Self {
        match hash_alg {
            HashAlgorithm::Sha1 => Self::SHA1,
            HashAlgorithm::Sha256 => Self::SHA256,
            HashAlgorithm::Sha384 => Self::SHA384,
            HashAlgorithm::Sha512 => Self::SHA512,
        }
    }
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
    fn from(raw: u32) -> Self {
        Self(raw)
    }
}
