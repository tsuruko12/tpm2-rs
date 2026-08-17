use crate::macros::tpm2b_zeroize_type;
use super::{
    TpmiAlgPublic,Tpm2bAuth, Tpm2bDigest, 
    buffer::Tpm2bLabel,
};
use super::super::public::{EccCurve, RsaKeyBits};

tpm2b_zeroize_type!(Tpm2bSensitiveData, 128);

pub(crate) enum TpmuSensitiveCreate {
    Create(Vec<u8>), // MAX_SYM_DATA should be 128
    Derive(TpmsDerive),
}

#[derive(Debug, Clone)]
pub(crate) struct TpmsDerive {
    label: Tpm2bLabel,
    context: Tpm2bLabel,
}

tpm2b_zeroize_type!(Tpm2bSensitive(TpmtSensitive), TpmtSensitive::MAX_BYTES);

pub(crate) struct TpmtSensitive {
    sensitive_type: TpmiAlgPublic,
    auth_value: Tpm2bAuth,
    seed_value: Tpm2bDigest,
    sensitive: TpmuSensitiveComposite,
}

impl TpmtSensitive {
    const MAX_BYTES: usize = size_of::<TpmiAlgPublic>() 
        + Tpm2bAuth::MAX_BYTES 
        + Tpm2bDigest::MAX_BYTES 
        + TpmuSensitiveComposite::MAX_BYTES;
}

pub(crate) enum TpmuSensitiveComposite {
    Rsa(Tpm2bPrivateKeyRsa),
    Ecc(Tpm2bEccParameter),
    Bits(Tpm2bSensitiveData),
    Sym(Tpm2bSymKey),
}

impl TpmuSensitiveComposite {
    const MAX_BYTES: usize = Tpm2bPrivateKeyRsa::MAX_BYTES;
}

tpm2b_zeroize_type!(Tpm2bPrivateKeyRsa, RsaKeyBits::MAX_BITS / 2 / 8);
tpm2b_zeroize_type!(Tpm2bEccParameter, EccCurve::MAX_BITS.div_ceil(8));
tpm2b_zeroize_type!(Tpm2bSymKey, 64); // max bytes is the larger of the largest symmetric key and digest

