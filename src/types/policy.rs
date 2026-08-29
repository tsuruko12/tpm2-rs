use std::collections::HashSet;

use crate::{Error, Result};

use super::{
    algorithm::HashAlgorithm,
    tpm::{TpmCc, TpmlDigest, TpmsPcrSelection},
};

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    Pcr(PcrSelection),
    Command(PolicyCommand),
    AuthValue,
    Password,
    Or(Vec<PolicyBranch>),
    Sequence(Vec<Policy>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBranch {
    label: String,
    policy: Policy,
}

impl PolicyBranch {
    pub fn new(label: impl Into<String>, policy: Policy) -> Self {
        Self {
            label: label.into(),
            policy,
        }
    }
}

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

    pub fn or(branches: Vec<PolicyBranch>) -> Self {
        Self::Or(branches)
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyCommand {
    CreatePrimary,
    Create,
    Import,
    Duplicate,
    Sign,
    Decrypt,
}

impl TryFrom<TpmCc> for PolicyCommand {
    type Error = Error;

    fn try_from(command_code: TpmCc) -> Result<Self> {
        match command_code {
            TpmCc::CREATE => Ok(Self::Create),
            TpmCc::CREATE_PRIMARY => Ok(Self::CreatePrimary),
            TpmCc::DUPLICATE => Ok(Self::Duplicate),
            TpmCc::IMPORT => Ok(Self::Import),
            TpmCc::SIGN => Ok(Self::Sign),
            TpmCc::RSA_DECRYPT => Ok(Self::Decrypt),
            _ => Err(Error::conversion::<TpmCc, PolicyCommand>(Some(&command_code))),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        slots.sort_unstable();
        slots.dedup();

        Ok(Self { hash_alg, slots })
    }

    pub fn hash_alg(&self) -> HashAlgorithm {
        self.hash_alg
    }

    pub fn slots(&self) -> &[PcrSlot] {
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
        branches: Vec<PolicyBranchData>,
        branch_digests: TpmlDigest,
        selected_label: Option<String>,
    },
    Sequence(Vec<PolicyData>),
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyBranchData {
    pub(crate) label: String,
    pub(crate) policy: PolicyData,
}

struct PolicySelection {
    end: usize,
    policy: PolicyData,
    selected_or_count: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PolicyAuthKind {
    AuthValue,
    Password,
}

impl PolicyData {
    pub(crate) fn contains_or(&self) -> bool {
        match self {
            Self::Or { .. } => true,
            Self::Sequence(steps) => steps.iter().any(|step| step.contains_or()),
            _ => false,
        }
    }

    pub(crate) fn set_branch_digests(&mut self, digests: TpmlDigest) -> Result<&TpmlDigest> {
        let Self::Or { branch_digests, .. } = self else {
            return Err(Error::invalid_state("expected PolicyData::Or"));
        };

        *branch_digests = digests;

        Ok(branch_digests)
    }

    pub(crate) fn set_selected_labels(
        &mut self,
        labels: &HashSet<String>,
    ) -> Result<()> {
        let mut remaining = labels.clone();
        self.apply_selected_labels(&mut remaining)?;

        if !remaining.is_empty() {
            return Err(Error::invalid_param("invalid policy branch labels"));
        }

        Ok(())
    }

    fn apply_selected_labels(
        &mut self,
        remaining: &mut HashSet<String>,
    ) -> Result<()> {
        match self {
            Self::Or {
                branches,
                selected_label,
                ..
            } => {
                let branch = branches
                    .iter_mut()
                    .find(|branch| remaining.contains(branch.label.as_str()))
                    .ok_or_else(|| {
                        Error::invalid_param("policy branch was not selected")
                    })?;

                remaining.remove(branch.label.as_str());
                *selected_label = Some(branch.label.clone());

                branch.policy.apply_selected_labels(remaining)?;

                Ok(())
            }
            Self::Sequence(steps) => {
                for step in steps {
                    step.apply_selected_labels(remaining)?;
                }

                Ok(())
            }

            _ => Ok(()),
        }
    }

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
                let (_, branch) = self.selected_branch()?;
                branch.auth_kind()
            }
        }
    }

    pub(crate) fn selected_branch(&self) -> Result<(&TpmlDigest, &PolicyData)> {
        let Self::Or {
            branches,
            branch_digests,
            selected_label,
        } = self
        else {
            return Err(Error::invalid_state("expected PolicyData::Or"));
        };

        let selected_label = selected_label
            .as_deref()
            .ok_or(Error::InvalidPolicy("policy branch is not selected"))?;

        let branch = branches
            .iter()
            .find(|branch| branch.label == selected_label)
            .ok_or_else(|| {
                Error::invalid_state("selected policy branch is missing")
            })?;

        Ok((branch_digests, &branch.policy))
    }
}

#[cfg(test)]
mod set_selected_labels {
    use super::*;

    fn branch(label: &str, policy: Policy) -> PolicyBranch {
        PolicyBranch::new(label, policy)
    }

    fn labels(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn selects_a_labeled_policy_or_branch() {
        let mut policy = PolicyData::try_from(Policy::or(vec![
            branch("auth", Policy::auth_value()),
            branch("password", Policy::password()),
        ]))
        .expect("PolicyOR must normalize");

        policy
            .set_selected_labels(&labels(&["auth"]))
            .expect("configured branch must be selectable");

        let (_, selected_branch) = policy
            .selected_branch()
            .expect("selected branch must be available");
        assert!(matches!(selected_branch, PolicyData::AuthValue));
    }

    #[test]
    fn selects_each_policy_or() {
        let mut policy = PolicyData::try_from(Policy::Sequence(vec![
            Policy::or(vec![
                branch("auth", Policy::auth_value()),
                branch("password", Policy::password()),
            ]),
            Policy::or(vec![
                branch("sign", Policy::command(PolicyCommand::Sign)),
                branch("decrypt", Policy::command(PolicyCommand::Decrypt)),
            ]),
        ]))
        .expect("policy must normalize");

        policy
            .set_selected_labels(&labels(&["auth", "sign"]))
            .expect("configured sequence branch must be selectable");

        let PolicyData::Sequence(steps) = &policy else {
            panic!("policy must remain a sequence");
        };
        let (_, first_selected_branch) = steps[0]
            .selected_branch()
            .expect("first PolicyOR branch must be selected");
        let (_, second_selected_branch) = steps[1]
            .selected_branch()
            .expect("second PolicyOR branch must be selected");
        assert!(matches!(first_selected_branch, PolicyData::AuthValue));
        assert!(matches!(
            second_selected_branch,
            PolicyData::Command(PolicyCommand::Sign)
        ));
    }

    #[test]
    fn selects_nested_policy_or_branches() {
        let mut policy = PolicyData::try_from(Policy::or(vec![
            branch(
                "outer",
                Policy::Sequence(vec![
                    Policy::auth_value(),
                    Policy::or(vec![
                        branch("sign", Policy::command(PolicyCommand::Sign)),
                        branch("decrypt", Policy::command(PolicyCommand::Decrypt)),
                    ]),
                ]),
            ),
            branch("password", Policy::password()),
        ]))
        .expect("policy must normalize");

        policy
            .set_selected_labels(&labels(&["outer", "sign"]))
            .expect("nested branch path must be selectable");

        let (_, outer_branch) = policy
            .selected_branch()
            .expect("outer PolicyOR branch must be selected");
        let PolicyData::Sequence(steps) = outer_branch else {
            panic!("outer branch must remain a sequence");
        };
        let (_, inner_branch) = steps[1]
            .selected_branch()
            .expect("nested PolicyOR branch must be selected");
        assert!(matches!(
            inner_branch,
            PolicyData::Command(PolicyCommand::Sign)
        ));
    }

    #[test]
    fn rejects_a_missing_policy_or_selection() {
        let mut policy = PolicyData::try_from(Policy::Sequence(vec![
            Policy::or(vec![
                branch("auth", Policy::auth_value()),
                branch("password", Policy::password()),
            ]),
            Policy::or(vec![
                branch("sign", Policy::command(PolicyCommand::Sign)),
                branch("decrypt", Policy::command(PolicyCommand::Decrypt)),
            ]),
        ]))
        .expect("policy must normalize");

        let error = policy
            .set_selected_labels(&labels(&["auth"]))
            .expect_err("every PolicyOR must be selected");

        assert!(matches!(
            error,
            Error::InvalidParameter(message) if message == "policy branch was not selected"
        ));
    }

    #[test]
    fn rejects_a_label_not_in_the_next_policy_or() {
        let mut policy = PolicyData::try_from(Policy::or(vec![
            branch("auth", Policy::auth_value()),
            branch("password", Policy::password()),
        ]))
        .expect("PolicyOR must normalize");

        let error = policy
            .set_selected_labels(&labels(&["sign"]))
            .expect_err("unconfigured branch must be rejected");

        assert!(matches!(
            error,
            Error::InvalidParameter(message) if message == "policy branch was not selected"
        ));
    }

    #[test]
    fn rejects_extra_selected_labels() {
        let mut policy = PolicyData::try_from(Policy::or(vec![
            branch("auth", Policy::auth_value()),
            branch("password", Policy::password()),
        ]))
        .expect("PolicyOR must normalize");

        let error = policy
            .set_selected_labels(&labels(&["auth", "extra"]))
            .expect_err("extra branch labels must be rejected");

        assert!(matches!(
            error,
            Error::InvalidParameter(message) if message == "invalid policy branch labels"
        ));
    }
}

impl TryFrom<Policy> for PolicyData {
    type Error = Error;

    fn try_from(policy: Policy) -> Result<Self> {
        normalize(policy)
    }
}

fn normalize(policy: Policy) -> Result<PolicyData> {
    let mut labels = HashSet::new();
    normalize_inner(policy, &mut labels)
}

fn normalize_inner(
    policy: Policy,
    labels: &mut HashSet<String>,
) -> Result<PolicyData> {
    match policy {
        Policy::AuthValue => Ok(PolicyData::AuthValue),
        Policy::Password => Ok(PolicyData::Password),
        Policy::Command(command) => Ok(PolicyData::Command(command)),
        Policy::Pcr(selection) => Ok(PolicyData::Pcr(selection)),

        Policy::Or(branches) => {
            let mut normalized_branches = Vec::new();
            normalize_or_branches(branches, &mut normalized_branches, labels)?;

            if normalized_branches.len() < 2 {
                return Err(Error::InvalidPolicy(
                    "PolicyOR must contain at least 2 branches",
                ));
            }

            Ok(PolicyData::Or {
                branches: normalized_branches,
                branch_digests: TpmlDigest::default(),
                selected_label: None,
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
                match normalize_inner(step, labels)? {
                    PolicyData::Sequence(nested_steps) => {
                        normalized_steps.extend(nested_steps);
                    }
                    step => normalized_steps.push(step),
                }
            }

            Ok(PolicyData::Sequence(normalized_steps))
        }
    }
}

fn normalize_or_branches(
    branches: Vec<PolicyBranch>,
    normalized_branches: &mut Vec<PolicyBranchData>,
    labels: &mut HashSet<String>,
) -> Result<()> {
    if branches.is_empty() {
        return Err(Error::InvalidPolicy(
            "PolicyOR must not be empty",
        ));
    }

    for PolicyBranch { label, policy } in branches {
        match policy {
            Policy::Or(branches) => {
                normalize_or_branches(
                    branches,
                    normalized_branches,
                    labels,
                )?;
            }

            policy => {
                if !labels.insert(label.clone()) {
                    return Err(Error::InvalidPolicy(
                        "policy branch labels must be unique",
                    ));
                }

                normalized_branches.push(PolicyBranchData {
                    label,
                    policy: normalize_inner(policy, labels)?,
                });
            }
        }
    }

    Ok(())
}
