use tracing::debug;

use crate::{Error, Result, types::tpm::TpmsPcrSelection};
use super::{algorithm::HashAlgorithm, tpm::TpmlDigest};

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
    pub(crate) const SELECT_SIZE: usize = 3;
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

    pub(crate) fn select_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; PcrSlot::SELECT_SIZE];
        for &slot in &self.slots {
            let slot = slot as usize;
            bytes[slot / 8] |= 1 << (slot % 8);
        }

        bytes
    }
}

impl From<PcrSelection> for TpmsPcrSelection {
    fn from(pcr_selection: PcrSelection) -> Self {
        let hash = pcr_selection.hash_alg.into();
        let pcr_select = pcr_selection.select_bytes();

        Self::new(hash, pcr_select)
            .expect("PCR select size must not exceed 3 bytes")
    }
}

#[derive(Debug, Clone)]
pub(crate) enum PolicyData {
    Pcr(PcrSelection),
    Command(PolicyCommand),
    AuthValue,
    Password,
    Or {
        branches: Vec<PolicyData>,
        branch_digests: TpmlDigest,
        selected_branch: Option<SelectedBranch>,
    },
    Sequence(Vec<PolicyData>),
}

#[derive(Debug, Clone)]
pub(crate) struct SelectedBranch {
    branch: Policy,
    digests: TpmlDigest,
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
                Self::try_from(branch.clone())?.auth_kind()
            }
        }
    }

    pub(crate) fn selected_or_branch(&self) -> Result<(&TpmlDigest, &Policy)> {
        let Self::Or {
            selected_branch,
            ..
        } = self
        else {
            return Err(Error::invalid_state("expected PolicyOR"));
        };

        let SelectedBranch { branch, digests } = selected_branch
            .as_ref()
            .ok_or(Error::InvalidPolicy("policy branch is not selected"))?;

        Ok((digests, branch))
    }
}

impl TryFrom<Policy> for PolicyData {
    type Error = Error;

    fn try_from(policy: Policy) -> Result<Self> {
        normalize(policy)
    }
}

fn normalize(policy: Policy) -> Result<PolicyData> {
    match policy {
        Policy::AuthValue => Ok(PolicyData::AuthValue),
        Policy::Password => Ok(PolicyData::Password),
        Policy::Command(command) => Ok(PolicyData::Command(command)),
        Policy::Pcr(selection) => Ok(PolicyData::Pcr(selection)),
        Policy::Or(branches) => {
            let mut normalized_branches = Vec::new();
            normalize_or_branches(branches, &mut normalized_branches)?;

            if normalized_branches.len() < 2 {
                return Err(Error::InvalidPolicy(
                    "PolicyOR must contain at least 2 branches",
                ));
            }

            Ok(PolicyData::Or {
                branches: normalized_branches,
                branch_digests: TpmlDigest::default(),
                selected_branch: None,
            })
        }
        Policy::Sequence(steps) => {
            if steps.is_empty() {
                return Err(Error::InvalidPolicy(
                    "policy sequence must not be empty",
                ));
            }

            let mut normalized_steps = Vec::new();
            for step in steps {
                match normalize(step)? {
                    PolicyData::Sequence(nested_steps) => normalized_steps.extend(nested_steps),
                    step => normalized_steps.push(step),
                }
            }

            Ok(PolicyData::Sequence(normalized_steps))
        }
    }
}

fn normalize_or_branches(
    branches: Vec<Policy>,
    normalized_branches: &mut Vec<PolicyData>,
) -> Result<()> {
    if branches.is_empty() {
        return Err(Error::InvalidPolicy("PolicyOR must not be empty"));
    }

    for branch in branches {
        match branch {
            Policy::Or(branches) => normalize_or_branches(branches, normalized_branches)?,
            branch => normalized_branches.push(normalize(branch)?),
        }
    }

    Ok(())
}
