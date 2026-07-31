use tss_esapi::{
    structures::Public,
    tss2_esys::{
        TPM2B_DIGEST, TPM2B_ECC_PARAMETER, TPM2B_PUBLIC_KEY_RSA, TPMS_ECC_PARMS, TPMS_ECC_POINT,
        TPMS_KEYEDHASH_PARMS, TPMS_RSA_PARMS, TPMS_SCHEME_ECDAA, TPMS_SCHEME_HASH, TPMS_SCHEME_XOR,
        TPMS_SYMCIPHER_PARMS, TPMT_ECC_SCHEME, TPMT_KDF_SCHEME, TPMT_KEYEDHASH_SCHEME, TPMT_PUBLIC,
        TPMT_RSA_SCHEME, TPMT_SYM_DEF_OBJECT, TPMU_ASYM_SCHEME, TPMU_KDF_SCHEME, TPMU_PUBLIC_ID,
        TPMU_PUBLIC_PARMS, TPMU_SCHEME_KEYEDHASH, TPMU_SYM_KEY_BITS, TPMU_SYM_MODE,
    },
};

use crate::{
    Error, Result,
    types::{
        Tpm2bDigest, TpmAlgId, TpmaObject, TpmiAlgHash, TpmiAlgPublic, TpmiAlgSymMode,
        TpmiAlgSymObject, TpmiRsaKeyBits, TpmsEccParms, TpmsKeyedHashParms, TpmsRsaParms,
        TpmsSchemeEcdaa, TpmsSchemeHash, TpmsSchemeXor, TpmtEccScheme, TpmtKdfScheme,
        TpmtKeyedHashScheme, TpmtPublic, TpmtRsaScheme, TpmtSymDefObject, TpmuEccScheme,
        TpmuKdfScheme, TpmuPublicId, TpmuPublicParms, TpmuRsaScheme, TpmuSchemeKeyedHash,
    },
};

impl TryFrom<Public> for TpmtPublic {
    type Error = Error;

    fn try_from(public: Public) -> Result<Self> {
        TPMT_PUBLIC::from(public).try_into()
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

                (
                    parameters,
                    TpmuPublicId::rsa(tpm2b_bytes(&unique.buffer, unique.size)?),
                )
            }
            TpmAlgId::KeyedHash => {
                let parameters =
                    TpmuPublicParms::try_from(unsafe { public.parameters.keyedHashDetail })?;
                let unique = Tpm2bDigest::try_from(unsafe { public.unique.keyedHash })?;

                (parameters, TpmuPublicId::keyed_hash(unique))
            }
            TpmAlgId::Ecc => {
                let parameters = TpmuPublicParms::try_from(unsafe { public.parameters.eccDetail })?;
                let unique = unsafe { public.unique.ecc };

                (
                    parameters,
                    TpmuPublicId::ecc(
                        tpm2b_bytes(&unique.x.buffer, unique.x.size)?,
                        tpm2b_bytes(&unique.y.buffer, unique.y.size)?,
                    ),
                )
            }
            TpmAlgId::SymCipher => {
                let parameters = TpmuPublicParms::try_from(unsafe { public.parameters.symDetail })?;
                let unique = Tpm2bDigest::try_from(unsafe { public.unique.sym })?;

                (parameters, TpmuPublicId::sym(unique))
            }
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

impl TryFrom<TpmtPublic> for Public {
    type Error = Error;

    fn try_from(public: TpmtPublic) -> Result<Self> {
        Self::try_from(TPMT_PUBLIC::try_from(public)?).map_err(Error::from_tss_err)
    }
}

impl TryFrom<TpmtPublic> for TPMT_PUBLIC {
    type Error = Error;

    fn try_from(public: TpmtPublic) -> Result<Self> {
        let alg_type = public.alg_type();
        let alg = TpmAlgId::try_from(alg_type.raw())?;
        let (parameters, unique) = match (alg, public.parameters(), public.unique()) {
            (TpmAlgId::Rsa, TpmuPublicParms::RsaDetail(params), TpmuPublicId::Rsa(unique)) => (
                TPMU_PUBLIC_PARMS {
                    rsaDetail: params.try_into()?,
                },
                TPMU_PUBLIC_ID {
                    rsa: tpm2b_public_key_rsa(unique.as_bytes())?,
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
                            x: tpm2b_ecc_parameter(x.as_bytes())?,
                            y: tpm2b_ecc_parameter(y.as_bytes())?,
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
            _ => {
                return Err(Error::invalid_state(
                    "public type, parameters, and unique are inconsistent",
                ));
            }
        };

        Ok(Self {
            type_: alg_type.raw(),
            nameAlg: public.name_alg().raw(),
            objectAttributes: public.object_attributes().bits(),
            authPolicy: public.auth_policy().try_into()?,
            parameters,
            unique,
        })
    }
}

impl TryFrom<TPMS_RSA_PARMS> for TpmuPublicParms {
    type Error = Error;

    fn try_from(rsa_params: TPMS_RSA_PARMS) -> Result<Self> {
        Ok(Self::RsaDetail(TpmsRsaParms::new(
            rsa_params.symmetric.try_into()?,
            rsa_params.scheme.try_into()?,
            TpmiRsaKeyBits::from(rsa_params.keyBits),
            rsa_params.exponent,
        )))
    }
}

impl TryFrom<TPMS_ECC_PARMS> for TpmuPublicParms {
    type Error = Error;

    fn try_from(ecc_params: TPMS_ECC_PARMS) -> Result<Self> {
        Ok(Self::EccDetail(TpmsEccParms::new(
            ecc_params.symmetric.try_into()?,
            ecc_params.scheme.try_into()?,
            ecc_params.curveID.try_into()?,
            ecc_params.kdf.try_into()?,
        )))
    }
}

impl TryFrom<TPMS_SYMCIPHER_PARMS> for TpmuPublicParms {
    type Error = Error;

    fn try_from(sym_cipher_params: TPMS_SYMCIPHER_PARMS) -> Result<Self> {
        let sym = TpmtSymDefObject::try_from(sym_cipher_params.sym)?;

        Ok(Self::SymDetail(sym.into()))
    }
}

impl TryFrom<TPMS_KEYEDHASH_PARMS> for TpmuPublicParms {
    type Error = Error;

    fn try_from(keyed_hash_params: TPMS_KEYEDHASH_PARMS) -> Result<Self> {
        Ok(Self::KeyedHashDetail(TpmsKeyedHashParms {
            scheme: keyed_hash_params.scheme.try_into()?,
        }))
    }
}

impl TryFrom<TPMT_SYM_DEF_OBJECT> for TpmtSymDefObject {
    type Error = Error;

    fn try_from(sym_def: TPMT_SYM_DEF_OBJECT) -> Result<Self> {
        let algorithm = TpmAlgId::try_from(sym_def.algorithm)?;
        let (key_bits, mode) = match algorithm {
            TpmAlgId::Tdes => unsafe { (sym_def.keyBits.sym, sym_def.mode.sym) },
            TpmAlgId::Aes => unsafe { (sym_def.keyBits.aes, sym_def.mode.aes) },
            TpmAlgId::Sm4 => unsafe { (sym_def.keyBits.sm4, sym_def.mode.sm4) },
            TpmAlgId::Camellia => unsafe { (sym_def.keyBits.camellia, sym_def.mode.camellia) },
            TpmAlgId::Null => return Ok(Self::null()),
            _ => {
                return Err(Error::conversion::<TpmAlgId, TpmtSymDefObject>(Some(
                    &algorithm,
                )));
            }
        };

        Ok(Self::new(
            TpmiAlgSymObject::try_from(algorithm)?,
            key_bits.into(),
            TpmiAlgSymMode::try_from(mode)?,
        ))
    }
}

impl TryFrom<TPMT_RSA_SCHEME> for TpmtRsaScheme {
    type Error = Error;

    fn try_from(rsa_scheme: TPMT_RSA_SCHEME) -> Result<Self> {
        let scheme = TpmAlgId::try_from(rsa_scheme.scheme)?;

        match scheme {
            TpmAlgId::RsaSsa => Ok(Self::rsa_ssa(
                unsafe { rsa_scheme.details.rsassa }.try_into()?,
            )),
            TpmAlgId::RsaEs => Ok(Self::rsa_es()),
            TpmAlgId::RsaPss => Ok(Self::rsa_pss(
                unsafe { rsa_scheme.details.rsapss }.try_into()?,
            )),
            TpmAlgId::Oaep => Ok(Self::oaep(unsafe { rsa_scheme.details.oaep }.try_into()?)),
            TpmAlgId::Null => Ok(Self::null()),
            _ => Err(Error::conversion::<TpmAlgId, TpmtRsaScheme>(Some(&scheme))),
        }
    }
}

impl TryFrom<TPMT_ECC_SCHEME> for TpmtEccScheme {
    type Error = Error;

    fn try_from(ecc_scheme: TPMT_ECC_SCHEME) -> Result<Self> {
        let scheme = TpmAlgId::try_from(ecc_scheme.scheme)?;

        match scheme {
            TpmAlgId::Ecdsa => Ok(Self::ecdsa(unsafe { ecc_scheme.details.ecdsa }.try_into()?)),
            TpmAlgId::Ecdh => Ok(Self::ecdh(unsafe { ecc_scheme.details.ecdh }.try_into()?)),
            TpmAlgId::Ecdaa => {
                let details = unsafe { ecc_scheme.details.ecdaa };

                Ok(Self::ecdaa(TpmsSchemeEcdaa {
                    hash_alg: details.hashAlg.try_into()?,
                    count: details.count,
                }))
            }
            TpmAlgId::Sm2 => Ok(Self::sm2(unsafe { ecc_scheme.details.sm2 }.try_into()?)),
            TpmAlgId::EcSchnorr => Ok(Self::ec_schnorr(
                unsafe { ecc_scheme.details.ecschnorr }.try_into()?,
            )),
            TpmAlgId::EcMqv => Ok(Self::ec_mqv(
                unsafe { ecc_scheme.details.ecmqv }.try_into()?,
            )),
            TpmAlgId::Null => Ok(Self::null()),
            _ => Err(Error::conversion::<TpmAlgId, TpmtEccScheme>(Some(&scheme))),
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

impl TryFrom<TPMT_KEYEDHASH_SCHEME> for TpmtKeyedHashScheme {
    type Error = Error;

    fn try_from(keyed_hash_scheme: TPMT_KEYEDHASH_SCHEME) -> Result<Self> {
        let scheme = TpmAlgId::try_from(keyed_hash_scheme.scheme)?;

        match scheme {
            TpmAlgId::Hmac => Ok(Self::hmac(
                unsafe { keyed_hash_scheme.details.hmac }.try_into()?,
            )),
            TpmAlgId::Xor => Ok(Self::xor(
                unsafe { keyed_hash_scheme.details.exclusiveOr }.try_into()?,
            )),
            TpmAlgId::Null => Ok(Self::null()),
            _ => Err(Error::conversion::<TpmAlgId, TpmtKeyedHashScheme>(Some(
                &scheme,
            ))),
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

impl TryFrom<TPMS_SCHEME_XOR> for TpmsSchemeXor {
    type Error = Error;

    fn try_from(scheme_xor: TPMS_SCHEME_XOR) -> Result<Self> {
        Ok(Self {
            hash_alg: scheme_xor.hashAlg.try_into()?,
            kdf: scheme_xor.kdf.try_into()?,
        })
    }
}

impl TryFrom<TpmsRsaParms> for TPMS_RSA_PARMS {
    type Error = Error;

    fn try_from(rsa_params: TpmsRsaParms) -> Result<Self> {
        Ok(Self {
            symmetric: rsa_params.symmetric().try_into()?,
            scheme: rsa_params.scheme().try_into()?,
            keyBits: rsa_params.key_bits().raw(),
            exponent: rsa_params.exponent(),
        })
    }
}

impl TryFrom<TpmsEccParms> for TPMS_ECC_PARMS {
    type Error = Error;

    fn try_from(ecc_params: TpmsEccParms) -> Result<Self> {
        Ok(Self {
            symmetric: ecc_params.symmetric().try_into()?,
            scheme: ecc_params.scheme().try_into()?,
            curveID: ecc_params.curve_id().raw(),
            kdf: ecc_params.kdf().try_into()?,
        })
    }
}

impl TryFrom<TpmtSymDefObject> for TPMT_SYM_DEF_OBJECT {
    type Error = Error;

    fn try_from(sym_def: TpmtSymDefObject) -> Result<Self> {
        let algorithm = sym_def.algorithm();
        let alg = TpmAlgId::try_from(algorithm.raw())?;
        let (key_bits, mode) = match alg {
            TpmAlgId::Tdes => (
                TPMU_SYM_KEY_BITS {
                    sym: sym_def.key_bits().raw(),
                },
                TPMU_SYM_MODE {
                    sym: sym_def.mode().raw(),
                },
            ),
            TpmAlgId::Aes => (
                TPMU_SYM_KEY_BITS {
                    aes: sym_def.key_bits().raw(),
                },
                TPMU_SYM_MODE {
                    aes: sym_def.mode().raw(),
                },
            ),
            TpmAlgId::Sm4 => (
                TPMU_SYM_KEY_BITS {
                    sm4: sym_def.key_bits().raw(),
                },
                TPMU_SYM_MODE {
                    sm4: sym_def.mode().raw(),
                },
            ),
            TpmAlgId::Camellia => (
                TPMU_SYM_KEY_BITS {
                    camellia: sym_def.key_bits().raw(),
                },
                TPMU_SYM_MODE {
                    camellia: sym_def.mode().raw(),
                },
            ),
            TpmAlgId::Null => {
                if !sym_def.is_null() {
                    return Err(Error::invalid_state(
                        "symmetric definition algorithm and details are inconsistent",
                    ));
                }

                (TPMU_SYM_KEY_BITS::default(), TPMU_SYM_MODE::default())
            }
            _ => {
                return Err(Error::conversion::<TpmAlgId, TPMT_SYM_DEF_OBJECT>(Some(
                    &alg,
                )));
            }
        };

        Ok(Self {
            algorithm: algorithm.raw(),
            keyBits: key_bits,
            mode,
        })
    }
}

impl TryFrom<TpmtRsaScheme> for TPMT_RSA_SCHEME {
    type Error = Error;

    fn try_from(rsa_scheme: TpmtRsaScheme) -> Result<Self> {
        let (scheme, details) = rsa_scheme.into_parts();
        let raw_scheme = scheme.raw();
        let details = match (TpmAlgId::try_from(raw_scheme)?, details) {
            (TpmAlgId::RsaSsa, TpmuRsaScheme::RsaSsa(hash)) => TPMU_ASYM_SCHEME {
                rsassa: hash.into(),
            },
            (TpmAlgId::RsaEs, TpmuRsaScheme::RsaEs(_)) => TPMU_ASYM_SCHEME {
                rsaes: Default::default(),
            },
            (TpmAlgId::RsaPss, TpmuRsaScheme::RsaPss(hash)) => TPMU_ASYM_SCHEME {
                rsapss: hash.into(),
            },
            (TpmAlgId::Oaep, TpmuRsaScheme::Oaep(hash)) => TPMU_ASYM_SCHEME { oaep: hash.into() },
            (TpmAlgId::Null, TpmuRsaScheme::Null) => TPMU_ASYM_SCHEME::default(),
            _ => {
                return Err(Error::invalid_state(
                    "RSA scheme and details are inconsistent",
                ));
            }
        };

        Ok(Self {
            scheme: raw_scheme,
            details,
        })
    }
}

impl TryFrom<TpmtEccScheme> for TPMT_ECC_SCHEME {
    type Error = Error;

    fn try_from(ecc_scheme: TpmtEccScheme) -> Result<Self> {
        let (scheme, details) = ecc_scheme.into_parts();
        let raw_scheme = scheme.raw();
        let details = match (TpmAlgId::try_from(raw_scheme)?, details) {
            (TpmAlgId::Ecdsa, TpmuEccScheme::Ecdsa(hash)) => {
                TPMU_ASYM_SCHEME { ecdsa: hash.into() }
            }
            (TpmAlgId::Ecdh, TpmuEccScheme::Ecdh(hash)) => TPMU_ASYM_SCHEME { ecdh: hash.into() },
            (TpmAlgId::Ecdaa, TpmuEccScheme::Ecdaa(details)) => TPMU_ASYM_SCHEME {
                ecdaa: TPMS_SCHEME_ECDAA {
                    hashAlg: details.hash_alg.raw(),
                    count: details.count,
                },
            },
            (TpmAlgId::Sm2, TpmuEccScheme::Sm2(hash)) => TPMU_ASYM_SCHEME { sm2: hash.into() },
            (TpmAlgId::EcSchnorr, TpmuEccScheme::EcSchnorr(hash)) => TPMU_ASYM_SCHEME {
                ecschnorr: hash.into(),
            },
            (TpmAlgId::EcMqv, TpmuEccScheme::EcMqv(hash)) => {
                TPMU_ASYM_SCHEME { ecmqv: hash.into() }
            }
            (TpmAlgId::Null, TpmuEccScheme::Null) => TPMU_ASYM_SCHEME::default(),
            _ => {
                return Err(Error::invalid_state(
                    "ECC scheme and details are inconsistent",
                ));
            }
        };

        Ok(Self {
            scheme: raw_scheme,
            details,
        })
    }
}

impl TryFrom<TpmtKdfScheme> for TPMT_KDF_SCHEME {
    type Error = Error;

    fn try_from(kdf_scheme: TpmtKdfScheme) -> Result<Self> {
        let (scheme, details) = kdf_scheme.into_parts();
        let raw_scheme = scheme.raw();
        let details = match (TpmAlgId::try_from(raw_scheme)?, details) {
            (TpmAlgId::Mgf1, TpmuKdfScheme::Mgf1(hash)) => TPMU_KDF_SCHEME { mgf1: hash.into() },
            (TpmAlgId::Kdf1Sp80056a, TpmuKdfScheme::Kdf1Sp800_56a(hash)) => TPMU_KDF_SCHEME {
                kdf1_sp800_56a: hash.into(),
            },
            (TpmAlgId::Kdf2, TpmuKdfScheme::Kdf2(hash)) => TPMU_KDF_SCHEME { kdf2: hash.into() },
            (TpmAlgId::Kdf1Sp800108, TpmuKdfScheme::Kdf1Sp800_108(hash)) => TPMU_KDF_SCHEME {
                kdf1_sp800_108: hash.into(),
            },
            (TpmAlgId::Null, TpmuKdfScheme::Null) => TPMU_KDF_SCHEME::default(),
            _ => {
                return Err(Error::invalid_state(
                    "KDF scheme and details are inconsistent",
                ));
            }
        };

        Ok(Self {
            scheme: raw_scheme,
            details,
        })
    }
}

impl TryFrom<TpmtKeyedHashScheme> for TPMT_KEYEDHASH_SCHEME {
    type Error = Error;

    fn try_from(keyed_hash_scheme: TpmtKeyedHashScheme) -> Result<Self> {
        let (scheme, details) = keyed_hash_scheme.into_parts();
        let raw_scheme = scheme.raw();
        let details = match (TpmAlgId::try_from(raw_scheme)?, details) {
            (TpmAlgId::Hmac, TpmuSchemeKeyedHash::Hmac(hash)) => {
                TPMU_SCHEME_KEYEDHASH { hmac: hash.into() }
            }
            (TpmAlgId::Xor, TpmuSchemeKeyedHash::Xor(xor)) => TPMU_SCHEME_KEYEDHASH {
                exclusiveOr: xor.into(),
            },
            (TpmAlgId::Null, TpmuSchemeKeyedHash::Null) => TPMU_SCHEME_KEYEDHASH::default(),
            _ => {
                return Err(Error::invalid_state(
                    "keyed-hash scheme and details are inconsistent",
                ));
            }
        };

        Ok(Self {
            scheme: raw_scheme,
            details,
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

impl From<TpmsSchemeXor> for TPMS_SCHEME_XOR {
    fn from(scheme_xor: TpmsSchemeXor) -> Self {
        Self {
            hashAlg: scheme_xor.hash_alg.raw(),
            kdf: scheme_xor.kdf.raw(),
        }
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
        raw.size = write_tpm2b(&mut raw.buffer, digest.as_bytes())?;

        Ok(raw)
    }
}

fn tpm2b_bytes(buffer: &[u8], size: u16) -> Result<Vec<u8>> {
    let size = usize::from(size);

    if size > buffer.len() {
        return Err(Error::invalid_state("TPM2B size exceeds its buffer"));
    }

    Ok(buffer[..size].to_vec())
}

fn tpm2b_public_key_rsa(bytes: &[u8]) -> Result<TPM2B_PUBLIC_KEY_RSA> {
    let mut raw = TPM2B_PUBLIC_KEY_RSA::default();
    raw.size = write_tpm2b(&mut raw.buffer, bytes)?;

    Ok(raw)
}

fn tpm2b_ecc_parameter(bytes: &[u8]) -> Result<TPM2B_ECC_PARAMETER> {
    let mut raw = TPM2B_ECC_PARAMETER::default();
    raw.size = write_tpm2b(&mut raw.buffer, bytes)?;

    Ok(raw)
}

fn write_tpm2b(buffer: &mut [u8], bytes: &[u8]) -> Result<u16> {
    if bytes.len() > buffer.len() {
        return Err(Error::invalid_state("TPM2B value exceeds its buffer"));
    }

    let size = u16::try_from(bytes.len())
        .map_err(|_| Error::invalid_state("TPM2B value length exceeds u16"))?;
    buffer[..bytes.len()].copy_from_slice(bytes);

    Ok(size)
}
