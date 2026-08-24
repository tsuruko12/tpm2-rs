mod ecc;
mod keyed_hash;
mod rsa;
mod symmetric;

use tss_esapi::{
    structures::{Name, Public},
    tss2_esys::{
        TPM2B_DIGEST, TPM2B_ECC_PARAMETER, TPM2B_PUBLIC_KEY_RSA, TPMS_ECC_POINT,
        TPMS_KEYEDHASH_PARMS, TPMS_SYMCIPHER_PARMS, TPMT_PUBLIC, TPMU_PUBLIC_ID,
        TPMU_PUBLIC_PARMS,
    },
};

use crate::{
    Error, Result,
    types::tpm::{
        Tpm2bDigest, Tpm2bEccParameter, Tpm2bName, Tpm2bPublic, Tpm2bPublicKeyRsa, TpmAlgId,
        TpmaObject, TpmiAlgHash, TpmiAlgPublic, TpmsEccPoint, TpmtPublic, TpmuPublicId,
        TpmuPublicParms,
    },
};

impl TryFrom<Public> for Tpm2bPublic {
    type Error = Error;

    fn try_from(public: Public) -> Result<Self> {
        Ok(TpmtPublic::try_from(TPMT_PUBLIC::from(public))?.into())
    }
}

impl TryFrom<TPMT_PUBLIC> for TpmtPublic {
    type Error = Error;

    fn try_from(public: TPMT_PUBLIC) -> Result<Self> {
        let alg = TpmAlgId::try_from(public.type_)?;
        let (parameters, unique) = match alg {
            TpmAlgId::Rsa => {
                let parameters = TpmuPublicParms::try_from(unsafe { public.parameters.rsaDetail })?;
                let unique = unsafe { public.unique.rsa };
                let public_key = Tpm2bPublicKeyRsa::try_from(tpm2b_bytes(&unique.buffer, unique.size)?)?;

                (
                    parameters,
                    TpmuPublicId::rsa(public_key),
                )
            },
            TpmAlgId::KeyedHash => {
                let parameters =
                    TpmuPublicParms::try_from(unsafe { public.parameters.keyedHashDetail })?;
                let unique = Tpm2bDigest::try_from(unsafe { public.unique.keyedHash })?;

                (parameters, TpmuPublicId::keyed_hash(unique))
            },
            TpmAlgId::Ecc => {
                let parameters = TpmuPublicParms::try_from(unsafe { public.parameters.eccDetail })?;
                let unique = unsafe { public.unique.ecc };

                (
                    parameters,
                    TpmuPublicId::ecc(TpmsEccPoint::new(
                        tpm2b_bytes(&unique.x.buffer, unique.x.size)?,
                        tpm2b_bytes(&unique.y.buffer, unique.y.size)?,
                    )?),
                )
            },
            TpmAlgId::SymCipher => {
                let parameters = TpmuPublicParms::try_from(unsafe { public.parameters.symDetail })?;
                let unique = Tpm2bDigest::try_from(unsafe { public.unique.sym })?;

                (parameters, TpmuPublicId::sym(unique))
            },
            _ => return Err(Error::conversion::<TpmAlgId, TpmtPublic>(Some(&alg))),
        };

        Ok(Self::new(
            TpmiAlgPublic::try_from(alg)?,
            TpmiAlgHash::try_from(public.nameAlg)?,
            TpmaObject::from_bits_retain(public.objectAttributes),
            public.authPolicy.try_into()?,
            parameters,
            unique,
        ))
    }
}

impl TryFrom<Tpm2bPublic> for Public {
    type Error = Error;

    fn try_from(public: Tpm2bPublic) -> Result<Self> {
        TPMT_PUBLIC::try_from(public.into_inner())?
            .try_into()
            .map_err(Error::from_tss_err)
    }
}

impl TryFrom<TpmtPublic> for TPMT_PUBLIC {
    type Error = Error;

    fn try_from(public: TpmtPublic) -> Result<Self> {
        let alg_type = public.alg_type();
        let alg = TpmAlgId::try_from(alg_type.value())?;
        let (parameters, unique) = match (alg, public.parameters(), public.unique()) {
            (TpmAlgId::Rsa, TpmuPublicParms::RsaDetail(params), TpmuPublicId::Rsa(unique)) => (
                TPMU_PUBLIC_PARMS {
                    rsaDetail: params.try_into()?,
                },
                TPMU_PUBLIC_ID {
                    rsa: tpm2b_public_key_rsa(unique)?,
                },
            ),
            (
                TpmAlgId::KeyedHash,
                TpmuPublicParms::KeyedHashDetail(params),
                TpmuPublicId::KeyedHash(unique),
            ) => (
                TPMU_PUBLIC_PARMS {
                    keyedHashDetail: TPMS_KEYEDHASH_PARMS {
                        scheme: params.scheme.try_into()?,
                    },
                },
                TPMU_PUBLIC_ID {
                    keyedHash: unique.try_into()?,
                },
            ),
            (TpmAlgId::Ecc, TpmuPublicParms::EccDetail(params), TpmuPublicId::Ecc(unique)) => {
                let (x, y) = unique.as_parts();

                (
                    TPMU_PUBLIC_PARMS {
                        eccDetail: params.try_into()?,
                    },
                    TPMU_PUBLIC_ID {
                        ecc: TPMS_ECC_POINT {
                            x: tpm2b_ecc_parameter(x)?,
                            y: tpm2b_ecc_parameter(y)?,
                        },
                    },
                )
            }
            (
                TpmAlgId::SymCipher,
                TpmuPublicParms::SymDetail(params),
                TpmuPublicId::Sym(unique),
            ) => (
                TPMU_PUBLIC_PARMS {
                    symDetail: TPMS_SYMCIPHER_PARMS {
                        sym: params.sym().try_into()?,
                    },
                },
                TPMU_PUBLIC_ID {
                    sym: unique.try_into()?,
                },
            ),
            _ => return Err(Error::invalid_state(
                    "public type, parameters, and unique are inconsistent",
                )),
        };

        Ok(Self {
            type_: alg_type.value(),
            nameAlg: public.name_alg().value(),
            objectAttributes: public.object_attributes().bits(),
            authPolicy: public.auth_policy().try_into()?,
            parameters,
            unique,
        })
    }
}


impl TryFrom<TPM2B_DIGEST> for Tpm2bDigest {
    type Error = Error;

    fn try_from(digest: TPM2B_DIGEST) -> Result<Self> {
        Self::try_from(tpm2b_bytes(&digest.buffer, digest.size)?)
    }
}

impl TryFrom<&Tpm2bDigest> for TPM2B_DIGEST {
    type Error = Error;

    fn try_from(digest: &Tpm2bDigest) -> Result<Self> {
        let mut raw = Self::default();
        raw.size = digest.size();
        write_tpm2b(&mut raw.buffer, digest.as_bytes())?;

        Ok(raw)
    }
}

impl From<Name> for Tpm2bName {
    fn from(name: Name) -> Self {
        name
            .value()
            .try_into()
            .expect("Name must be valid for Tpm2bName")
    }
}

fn tpm2b_bytes(buffer: &[u8], size: u16) -> Result<Vec<u8>> {
    let size = usize::from(size);

    if size > buffer.len() {
        return Err(Error::invalid_state("TPM2B size exceeds its buffer"));
    }

    Ok(buffer[..size].to_vec())
}

fn tpm2b_public_key_rsa(value: &Tpm2bPublicKeyRsa) -> Result<TPM2B_PUBLIC_KEY_RSA> {
    let mut raw = TPM2B_PUBLIC_KEY_RSA::default();
    raw.size = value.size();
    write_tpm2b(&mut raw.buffer, value.as_bytes())?;

    Ok(raw)
}

fn tpm2b_ecc_parameter(value: &Tpm2bEccParameter) -> Result<TPM2B_ECC_PARAMETER> {
    let mut raw = TPM2B_ECC_PARAMETER::default();
    raw.size = value.size();
    write_tpm2b(&mut raw.buffer, value.as_bytes())?;

    Ok(raw)
}

fn write_tpm2b(buf: &mut [u8], bytes: &[u8]) -> Result<()> {
    if bytes.len() > buf.len() {
        return Err(Error::invalid_state("TPM2B value exceeds its buffer"));
    }

    buf[..bytes.len()].copy_from_slice(bytes);

    Ok(())
}
