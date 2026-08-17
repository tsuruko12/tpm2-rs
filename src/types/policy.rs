use tracing::debug;

use crate::{Error, Result};
use super::{algorithm::HashAlgorithm, tpm::TpmlDigest};

const MAX_POLICY_OR_BRANCHES: usize = 8;

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    Pcr(PcrSelection),
    Command(PolicyCommand),
    AuthValue,
    Password,
    Or(Vec<Policy>),
    Sequence(Vec<Policy>),
}

// validate policy when key creation
// will change Result<Self> to Self later

// flatten like nesting Or
impl Policy {
    pub fn pcr(slots: &[PcrSlot]) -> Result<Self> {
        let selection = PcrSelection::new(HashAlgorithm::Sha256, slots)?;
        Ok(Self::Pcr(selection))
    }

    pub fn command(command: PolicyCommand) -> Self {
        Self::Command(command)
    }

    pub fn auth_value() -> Self {
        Self::AuthValue
    }

    pub fn password() -> Self {
        Self::Password
    }

    pub fn or(policies: &[Self]) -> Self {
        Self::Or(policies.to_vec())
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyCommand {
    CreatePrimary,
    Create,
    Load,
    Import,
    Duplicate,
    Sign,
    Decrypt,
    Unseal,
}

impl PolicyCommand {
    pub(crate) fn from_db(command: &str) -> Result<Self> {
        match command {
            "create_primary" => Ok(PolicyCommand::CreatePrimary),
            "create" => Ok(PolicyCommand::Create),
            "load" => Ok(PolicyCommand::Load),
            "import" => Ok(PolicyCommand::Import),
            "duplicate" => Ok(PolicyCommand::Duplicate),
            "sign" => Ok(PolicyCommand::Sign),
            "decrypt" => Ok(PolicyCommand::Decrypt),
            "unseal" => Ok(PolicyCommand::Unseal),
            _ => {
                debug!(%command, "invalid stored policy command");
                Err(Error::corrupted_store())
            }
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcrSlot {
    Slot0 = 0,
    Slot1 = 1,
    Slot2 = 2,
    Slot3 = 3,
    Slot4 = 4,
    Slot5 = 5,
    Slot6 = 6,
    Slot7 = 7,
    Slot8 = 8,
    Slot9 = 9,
    Slot10 = 10,
    Slot11 = 11,
    Slot12 = 12,
    Slot13 = 13,
    Slot14 = 14,
    Slot15 = 15,
    Slot16 = 16,
    Slot17 = 17,
    Slot18 = 18,
    Slot19 = 19,
    Slot20 = 20,
    Slot21 = 21,
    Slot22 = 22,
    Slot23 = 23,
}

impl PcrSlot {
    pub(crate) const MAX: u8 = Self::Slot23 as u8;
    pub(crate) const MASK: u32 = 0x00ff_ffff;
}

impl TryFrom<u8> for PcrSlot {
    type Error = crate::Error;

    fn try_from(value: u8) -> crate::Result<Self> {
        match value {
            0 => Ok(Self::Slot0),
            1 => Ok(Self::Slot1),
            2 => Ok(Self::Slot2),
            3 => Ok(Self::Slot3),
            4 => Ok(Self::Slot4),
            5 => Ok(Self::Slot5),
            6 => Ok(Self::Slot6),
            7 => Ok(Self::Slot7),
            8 => Ok(Self::Slot8),
            9 => Ok(Self::Slot9),
            10 => Ok(Self::Slot10),
            11 => Ok(Self::Slot11),
            12 => Ok(Self::Slot12),
            13 => Ok(Self::Slot13),
            14 => Ok(Self::Slot14),
            15 => Ok(Self::Slot15),
            16 => Ok(Self::Slot16),
            17 => Ok(Self::Slot17),
            18 => Ok(Self::Slot18),
            19 => Ok(Self::Slot19),
            20 => Ok(Self::Slot20),
            21 => Ok(Self::Slot21),
            22 => Ok(Self::Slot22),
            23 => Ok(Self::Slot23),
            _ => Err(Error::conversion::<u8, PcrSlot>(Some(&value))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrSelection {
    hash_alg: HashAlgorithm,
    slots: Vec<PcrSlot>,
}

impl PcrSelection {
    pub fn new(hash_alg: HashAlgorithm, slots: &[PcrSlot]) -> Result<Self> {
        if slots.is_empty() {
            return Err(Error::InvalidPolicy(
                "PCR selection must contain at least one slot",
            ));
        }

        let mut slots = slots.to_vec();
        slots.sort_unstable_by_key(|slot| *slot as u8);
        slots.dedup();

        Ok(Self { hash_alg, slots })
    }

    pub(crate) fn hash_alg(&self) -> HashAlgorithm {
        self.hash_alg
    }

    pub(crate) fn slots(&self) -> &[PcrSlot] {
        &self.slots
    }
}

#[derive(Clone)]
pub(crate) enum PolicyData {
    Pcr(PcrSelection),
    Command(PolicyCommand),
    AuthValue,
    Password,
    Or {
        branches: Vec<PolicyData>,
        branch_digests: Vec<TpmlDigest>,
        selected_branch: Option<usize>,
    },
    Sequence(Vec<PolicyData>),
}

impl std::fmt::Debug for PolicyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pcr(selection) => f.debug_tuple("Pcr").field(selection).finish(),
            Self::Command(command) => f.debug_tuple("Command").field(command).finish(),
            Self::AuthValue => f.write_str("AuthValue"),
            Self::Password => f.write_str("Password"),
            Self::Or {
                branches,
                selected_branch,
                ..
            } => f
                .debug_struct("Or")
                .field("branches", branches)
                .field("selected_branch", selected_branch)
                .finish_non_exhaustive(),
            Self::Sequence(steps) => f.debug_tuple("Sequence").field(steps).finish(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PolicyAuthKind {
    AuthValue,
    Password,
}

impl PolicyData {
    pub(crate) fn auth_kind(&self) -> Result<Option<PolicyAuthKind>> {
        match self {
            Self::Pcr(_) | Self::Command(_) => Ok(None),
            Self::AuthValue => Ok(Some(PolicyAuthKind::AuthValue)),
            Self::Password => Ok(Some(PolicyAuthKind::Password)),
            Self::Sequence(steps) => {
                for step in steps {
                    if let Some(kind) = step.auth_kind()? {
                        return Ok(Some(kind));
                    }
                }

                Ok(None)
            }
            Self::Or { .. } => {
                let (_, branch) = self.selected_or_branch()?;
                branch.auth_kind()
            }
        }
    }

    pub(crate) fn selected_or_branch(&self) -> Result<(&TpmlDigest, &Self)> {
        let Self::Or {
            branches,
            branch_digests,
            selected_branch,
        } = self
        else {
            return Err(Error::invalid_state("expected PolicyOR"));
        };

        let idx =
            (*selected_branch).ok_or(Error::InvalidPolicy("policy branch is not selected"))?;
        let digest_list = branch_digests
            .get(idx)
            .ok_or(Error::invalid_state(
                "policy branch digest count does not match branch count",
            ))?;
        let branch = branches.get(idx).ok_or(Error::invalid_state(
            "selected branch index should be in range",
        ))?;

        Ok((digest_list, branch))
    }
}

impl From<Policy> for PolicyData {
    fn from(policy: Policy) -> Self {
        match policy {
            Policy::AuthValue => Self::AuthValue,
            Policy::Password => Self::Password,
            Policy::Command(command) => Self::Command(command),
            Policy::Pcr(selection) => Self::Pcr(selection),
            Policy::Or(branches) => Self::Or {
                branches: branches.into_iter().map(Into::into).collect(),
                branch_digests: Vec::new(),
                selected_branch: None,
            },
            Policy::Sequence(steps) => Self::Sequence(steps.into_iter().map(Into::into).collect()),
        }
    }
}
