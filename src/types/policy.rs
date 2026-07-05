use crate::types::{HashAlgorithm, TpmiAlgHash};

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
            _ => Err(crate::Error::Internal("unsupported PCR slot")),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TpmlPcrSelection {
    items: Vec<TpmsPcrSelection>,
}

impl TpmlPcrSelection {
    pub(crate) fn new(items: Vec<TpmsPcrSelection>) -> Self {
        Self { items }
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TpmsPcrSelection {
    hash: TpmiAlgHash,
    pcr_select: Vec<u8>,
}

impl TpmsPcrSelection {
    pub(crate) fn new(hash: TpmiAlgHash, pcr_select: Vec<u8>) -> Self {
        Self { hash, pcr_select }
    }

    pub(crate) fn hash(&self) -> TpmiAlgHash {
        self.hash
    }

    pub(crate) fn pcr_select(&self) -> &[u8] {
        &self.pcr_select
    }

    pub(crate) fn size_of_select(&self) -> usize {
        self.pcr_select.len()
    }
}
