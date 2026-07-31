use tss_esapi::constants::CommandCode;
use tss_esapi::structures::{
    PcrSelectSize, PcrSelection as EsapiPcrSelection, PcrSelectionList, PcrSlot as EsapiPcrSlot,
};

use crate::error::BoxError;
use crate::types::PolicyCommand;
use crate::{
    Error, Result,
    types::{PcrSlot, TpmiAlgHash, TpmlPcrSelection, TpmsPcrSelection},
};

impl From<PolicyCommand> for CommandCode {
    fn from(command: PolicyCommand) -> Self {
        match command {
            PolicyCommand::CreatePrimary => Self::CreatePrimary,
            PolicyCommand::Create => Self::Create,
            PolicyCommand::Load => Self::Load,
            PolicyCommand::Import => Self::Import,
            PolicyCommand::Duplicate => Self::Duplicate,
            PolicyCommand::Sign => Self::Sign,
            PolicyCommand::Decrypt => Self::RsaDecrypt,
            PolicyCommand::Unseal => Self::Unseal,
        }
    }
}

impl From<PcrSlot> for EsapiPcrSlot {
    fn from(slot: PcrSlot) -> Self {
        match slot {
            PcrSlot::Slot0 => Self::Slot0,
            PcrSlot::Slot1 => Self::Slot1,
            PcrSlot::Slot2 => Self::Slot2,
            PcrSlot::Slot3 => Self::Slot3,
            PcrSlot::Slot4 => Self::Slot4,
            PcrSlot::Slot5 => Self::Slot5,
            PcrSlot::Slot6 => Self::Slot6,
            PcrSlot::Slot7 => Self::Slot7,
            PcrSlot::Slot8 => Self::Slot8,
            PcrSlot::Slot9 => Self::Slot9,
            PcrSlot::Slot10 => Self::Slot10,
            PcrSlot::Slot11 => Self::Slot11,
            PcrSlot::Slot12 => Self::Slot12,
            PcrSlot::Slot13 => Self::Slot13,
            PcrSlot::Slot14 => Self::Slot14,
            PcrSlot::Slot15 => Self::Slot15,
            PcrSlot::Slot16 => Self::Slot16,
            PcrSlot::Slot17 => Self::Slot17,
            PcrSlot::Slot18 => Self::Slot18,
            PcrSlot::Slot19 => Self::Slot19,
            PcrSlot::Slot20 => Self::Slot20,
            PcrSlot::Slot21 => Self::Slot21,
            PcrSlot::Slot22 => Self::Slot22,
            PcrSlot::Slot23 => Self::Slot23,
        }
    }
}

impl TryFrom<TpmsPcrSelection> for EsapiPcrSelection {
    type Error = Error;

    fn try_from(pcr_selection: TpmsPcrSelection) -> Result<Self> {
        convert_pcr_selection(&pcr_selection)
            .map_err(|_| Error::conversion::<TpmsPcrSelection, EsapiPcrSelection>(None))
    }
}

fn convert_pcr_selection(
    pcr_selection: &TpmsPcrSelection,
) -> std::result::Result<EsapiPcrSelection, BoxError> {
    let size_of_select = PcrSelectSize::try_parse_usize(pcr_selection.size_of_select())?;
    let selected_pcr_slots = pcr_select_to_slots(pcr_selection.pcr_select())?;
    let hash = pcr_selection.hash().try_into()?;

    Ok(EsapiPcrSelection::create(
        hash,
        size_of_select,
        &selected_pcr_slots,
    )?)
}

impl From<EsapiPcrSelection> for TpmsPcrSelection {
    fn from(pcr_selection: EsapiPcrSelection) -> Self {
        let hash = TpmiAlgHash::from(pcr_selection.hashing_algorithm());
        let pcr_select =
            pcr_slots_to_select(&pcr_selection.selected(), pcr_selection.size_of_select());

        Self::new(hash, pcr_select)
    }
}

impl From<PcrSelectionList> for TpmlPcrSelection {
    fn from(pcr_selection_list: PcrSelectionList) -> Self {
        let items = pcr_selection_list
            .get_selections()
            .iter()
            .cloned()
            .map(|selection| TpmsPcrSelection::from(selection))
            .collect::<Vec<_>>();

        items.into()
    }
}

pub(super) fn pcr_select_to_slots(bytes: &[u8]) -> Result<Vec<EsapiPcrSlot>> {
    let mut slots = Vec::new();

    for (byte_idx, &byte) in bytes.iter().enumerate() {
        for bit_idx in 0..8 {
            if byte & (1 << bit_idx) != 0 {
                let slot_idx = (byte_idx * 8 + bit_idx) as u8;
                slots.push(PcrSlot::try_from(slot_idx)?.into());
            }
        }
    }

    Ok(slots)
}

pub(super) fn pcr_slots_to_select(
    slots: &[EsapiPcrSlot],
    size_of_select: PcrSelectSize,
) -> Vec<u8> {
    let bitmap = slots
        .iter()
        .fold(0, |bitmap, slot| bitmap | u32::from(*slot));

    bitmap.to_le_bytes()[..size_of_select.as_usize()].to_vec()
}
