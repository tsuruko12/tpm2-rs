use tracing::debug;
use tss_esapi::{
    constants::StructureTag,
    structures::{HashcheckTicket, Ticket},
    tss2_esys::{TPM2B_DIGEST, TPMT_TK_HASHCHECK},
};

use crate::{
    Error, Result,
    types::tpm::{TpmSt, TpmtTkHashCheck},
};

impl TryFrom<TpmtTkHashCheck> for HashcheckTicket {
    type Error = Error;

    fn try_from(hash_check_tk: TpmtTkHashCheck) -> Result<Self> {
        let data = hash_check_tk.digest().as_bytes();
        let mut buffer = [0u8; 64];
        buffer[..data.len()].copy_from_slice(data);

        let digest = TPM2B_DIGEST {
            size: hash_check_tk.digest().size(),
            buffer,
        };
        let tpmt_tk_hash_check = TPMT_TK_HASHCHECK {
            tag: hash_check_tk.tag().value(),
            hierarchy: hash_check_tk.hierarchy().value(),
            digest,
        };

        tpmt_tk_hash_check.try_into().map_err(|e| {
            debug!("{e:?}");
            Error::conversion::<TpmtTkHashCheck, HashcheckTicket>(None)
        })
    }
}

impl TryFrom<HashcheckTicket> for TpmtTkHashCheck {
    type Error = Error;

    fn try_from(hash_check_tk: HashcheckTicket) -> Result<Self> {
        Ok(Self::new(
            hash_check_tk.hierarchy().into(),
            hash_check_tk.digest().try_into()?,
        ))
    }
}

impl TryFrom<TpmSt> for StructureTag {
    type Error = Error;

    fn try_from(tag: TpmSt) -> Result<Self> {
        match tag {
            TpmSt::RSP_COMMAND => Ok(Self::RspCommand),
            TpmSt::NULL => Ok(Self::Null),
            TpmSt::NO_SESSIONS => Ok(Self::NoSessions),
            TpmSt::SESSIONS => Ok(Self::Sessions),
            TpmSt::ATTEST_NV => Ok(Self::AttestNv),
            TpmSt::ATTEST_COMMAND_AUDIT => Ok(Self::AttestCommandAudit),
            TpmSt::ATTEST_SESSION_AUDIT => Ok(Self::AttestSessionAudit),
            TpmSt::ATTEST_CERTIFY => Ok(Self::AttestCertify),
            TpmSt::ATTEST_QUOTE => Ok(Self::AttestQuote),
            TpmSt::ATTEST_TIME => Ok(Self::AttestTime),
            TpmSt::ATTEST_CREATION => Ok(Self::AttestCreation),
            TpmSt::ATTEST_NV_DIGEST => Ok(Self::AttestNvDigest),
            TpmSt::CREATION => Ok(Self::Creation),
            TpmSt::VERIFIED => Ok(Self::Verified),
            TpmSt::AUTH_SECRET => Ok(Self::AuthSecret),
            TpmSt::HASHCHECK => Ok(Self::Hashcheck),
            TpmSt::AUTH_SIGNED => Ok(Self::AuthSigned),
            TpmSt::FU_MANIFEST => Ok(Self::FuManifest),
            _ => Err(Error::conversion::<TpmSt, StructureTag>(Some(&tag))),
        }
    }
}
