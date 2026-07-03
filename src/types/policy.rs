use crate::types::HashAlgorithm;

const MAX_POLICY_OR_BRANCHES: usize = 8;

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    AuthValue,
    Command(PolicyCommand),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcrSlot {
    Slot0,
    Slot1,
    Slot2,
    Slot3,
    Slot4,
    Slot5,
    Slot6,
    Slot7,
    Slot8,
    Slot9,
    Slot10,
    Slot11,
    Slot12,
    Slot13,
    Slot14,
    Slot15,
    Slot16,
    Slot17,
    Slot18,
    Slot19,
    Slot20,
    Slot21,
    Slot22,
    Slot23,
}

impl From<PcrSlot> for u32 {
    fn from(value: PcrSlot) -> Self {
        match value {
            PcrSlot::Slot0 => 0,
            PcrSlot::Slot1 => 1,
            PcrSlot::Slot2 => 2,
            PcrSlot::Slot3 => 3,
            PcrSlot::Slot4 => 4,
            PcrSlot::Slot5 => 5,
            PcrSlot::Slot6 => 6,
            PcrSlot::Slot7 => 7,
            PcrSlot::Slot8 => 8,
            PcrSlot::Slot9 => 9,
            PcrSlot::Slot10 => 10,
            PcrSlot::Slot11 => 11,
            PcrSlot::Slot12 => 12,
            PcrSlot::Slot13 => 13,
            PcrSlot::Slot14 => 14,
            PcrSlot::Slot15 => 15,
            PcrSlot::Slot16 => 16,
            PcrSlot::Slot17 => 17,
            PcrSlot::Slot18 => 18,
            PcrSlot::Slot19 => 19,
            PcrSlot::Slot20 => 20,
            PcrSlot::Slot21 => 21,
            PcrSlot::Slot22 => 22,
            PcrSlot::Slot23 => 23,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PcrSelection {
    hash: HashAlgorithm,
    slots: Vec<PcrSlot>,
}

impl PcrSelection {
    pub(crate) fn new(hash: HashAlgorithm, slots: &[PcrSlot]) -> Self {
        Self {
            hash,
            slots: slots.to_vec(),
        }
    }

    pub(crate) fn hash(&self) -> HashAlgorithm {
        self.hash
    }

    pub(crate) fn slots(&self) -> &[PcrSlot] {
        &self.slots
    }
}