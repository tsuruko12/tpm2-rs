use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TpmlAlgProperty {
    items: Vec<TpmsAlgProperty>,
}

impl TpmlAlgProperty {
    pub(crate) fn new(items: Vec<TpmsAlgProperty>) -> Self {
        Self { items }
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

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

pub(crate) type TpmiAlgHash = TpmAlgId;

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
    Null = 0x0010,
    Sm3_256 = 0x0012,
    Sm4 = 0x0013,
    Rsassa = 0x0014,
    Rsaes = 0x0015,
    Rsapss = 0x0016,
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
            0x0010 => Ok(Self::Null),
            0x0012 => Ok(Self::Sm3_256),
            0x0013 => Ok(Self::Sm4),
            0x0014 => Ok(Self::Rsassa),
            0x0015 => Ok(Self::Rsaes),
            0x0016 => Ok(Self::Rsapss),
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
            _ => Err(Error::Internal("unsupported TPM algorithm identifier")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TpmaAlgorithm(u32);

impl TpmaAlgorithm {
    const ASYMMETRIC: u32 = 1 << 0;
    const SYMMETRIC: u32 = 1 << 1;
    const HASH: u32 = 1 << 2;
    const OBJECT: u32 = 1 << 3;
    const SIGNING: u32 = 1 << 8;
    const ENCRYPTING: u32 = 1 << 9;
    const METHOD: u32 = 1 << 10;

    pub(crate) const fn new(value: u32) -> Self {
        Self(value)
    }

    pub(crate) const fn from_be_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }

    pub(crate) const fn is_asymmetric(self) -> bool {
        self.contains(Self::ASYMMETRIC)
    }

    pub(crate) const fn is_symmetric(self) -> bool {
        self.contains(Self::SYMMETRIC)
    }

    pub(crate) const fn is_hash(self) -> bool {
        self.contains(Self::HASH)
    }

    pub(crate) const fn is_object(self) -> bool {
        self.contains(Self::OBJECT)
    }

    pub(crate) const fn is_signing(self) -> bool {
        self.contains(Self::SIGNING)
    }

    pub(crate) const fn is_encrypting(self) -> bool {
        self.contains(Self::ENCRYPTING)
    }

    pub(crate) const fn is_method(self) -> bool {
        self.contains(Self::METHOD)
    }

    const fn contains(self, flag: u32) -> bool {
        self.0 & flag != 0
    }
}
