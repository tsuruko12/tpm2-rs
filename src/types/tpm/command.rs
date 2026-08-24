use crate::{
    Error, Result,
    macros::{newtype, tpm_list_type},
    policy::PolicyCommand,
};

tpm_list_type!(TpmlCc(TpmCc));

newtype!(TpmCc(u32));

// constの一部はlinuxの方で定義するかも

impl TpmCc {
    const FIRST: u32 = 0x0000_011F;
    const LAST: u32 = 0x0000_01AA;

    pub(crate) const EVICT_CONTROL: Self = Self(0x0000_0120);
    pub(crate) const CREATE_PRIMARY: Self = Self(0x0000_0131);
    pub(crate) const DUPLICATE: Self = Self(0x0000_014B);
    pub(crate) const CREATE: Self = Self(0x0000_0153);
    pub(crate) const IMPORT: Self = Self(0x0000_0156);
    pub(crate) const LOAD: Self = Self(0x0000_0157);
    pub(crate) const RSA_DECRYPT: Self = Self(0x0000_0159);
    pub(crate) const SIGN: Self = Self(0x0000_015D);
    pub(crate) const UNSEAL: Self = Self(0x0000_015E);
    pub(crate) const FLUSH_CONTEXT: Self = Self(0x0000_0165);
    pub(crate) const POLICY_AUTH_VALUE: Self = Self(0x0000_016B);
    pub(crate) const POLICY_COMMAND_CODE: Self = Self(0x0000_016C);
    pub(crate) const POLICY_OR: Self = Self(0x0000_0171);
    pub(crate) const READ_PUBLIC: Self = Self(0x0000_0173);
    pub(crate) const RSA_ENCRYPT: Self = Self(0x0000_0174);
    pub(crate) const START_AUTH_SESSION: Self = Self(0x0000_0176);
    pub(crate) const GET_CAPABILITY: Self = Self(0x0000_017A);
    pub(crate) const GET_RANDOM: Self = Self(0x0000_017B);
    pub(crate) const PCR_READ: Self = Self(0x0000_017E);
    pub(crate) const POLICY_PCR: Self = Self(0x0000_017F);
    pub(crate) const POLICY_GET_DIGEST: Self = Self(0x0000_0189);
    pub(crate) const POLICY_PASSWORD: Self = Self(0x0000_018C);
}

impl From<PolicyCommand> for TpmCc {
    fn from(command: PolicyCommand) -> Self {
        match command {
            PolicyCommand::CreatePrimary => Self::CREATE_PRIMARY,
            PolicyCommand::Create => Self::CREATE,
            PolicyCommand::Load => Self::LOAD,
            PolicyCommand::Import => Self::IMPORT,
            PolicyCommand::Duplicate => Self::DUPLICATE,
            PolicyCommand::Sign => Self::SIGN,
            PolicyCommand::Decrypt => Self::RSA_DECRYPT,
            PolicyCommand::Unseal => Self::UNSEAL,
        }
    }
}

impl TryFrom<u32> for TpmCc {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        if (Self::FIRST..=Self::LAST).contains(&value) {
            Ok(Self(value))
        } else {
            Err(Error::conversion::<u32, TpmCc>(None))
        }
    }
}
