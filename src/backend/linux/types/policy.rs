use tss_esapi::structures::{
    PcrSelectSize, PcrSelection, PcrSelectionList, PcrSlot as EsapiPcrSlot,
};

use crate::{
    Error, Result,
    types::{PcrSlot, TpmAlgId, TpmlPcrSelection, TpmsPcrSelection},
};

impl From<PcrSlot> for EsapiPcrSlot {
    fn from(value: PcrSlot) -> Self {
        match value {
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

impl TryFrom<TpmsPcrSelection> for PcrSelection {
    type Error = Error;

    fn try_from(value: TpmsPcrSelection) -> Result<Self> {
        let select_size = u8::try_from(value.size_of_select())
            .map_err(|_| Error::Internal("invalid PCR select size"))?;
        let size_of_select = PcrSelectSize::try_from(select_size)
            .map_err(|_| Error::Internal("invalid PCR select size"))?;
        let selected_pcr_slots = pcr_select_to_slots(value.pcr_select())?;

        Self::create(
            value.hash().try_into()?,
            size_of_select,
            &selected_pcr_slots,
        )
        .map_err(|_| Error::Internal("invalid PCR selection"))
    }
}

impl From<PcrSelection> for TpmsPcrSelection {
    fn from(value: PcrSelection) -> Self {
        let hash = TpmAlgId::from(value.hashing_algorithm());
        let pcr_select = pcr_slots_to_select_bytes(&value.selected());

        Self::new(hash, pcr_select)
    }
}

impl From<PcrSelectionList> for TpmlPcrSelection {
    fn from(value: PcrSelectionList) -> Self {
        let items = value
            .get_selections()
            .iter()
            .cloned()
            .map(|selection| TpmsPcrSelection::from(selection))
            .collect();

        Self::new(items)
    }
}

pub(super) fn pcr_select_to_slots(bytes: &[u8]) -> Result<Vec<EsapiPcrSlot>> {
    let mut slots = Vec::new();

    for (byte_idx, byte) in bytes.iter().enumerate() {
        for bit_idx in 0..8 {
            if *byte & (1u8 << bit_idx) == 0 {
                continue;
            }

            let slot_idx = (byte_idx * 8 + bit_idx) as u8;
            slots.push(PcrSlot::try_from(slot_idx)?.into());
        }
    }

    Ok(slots)
}

fn pcr_slots_to_select_bytes(slots: &[EsapiPcrSlot]) -> Vec<u8> {
    let mut bitmap = 0u32;

    for slot in slots {
        bitmap |= u32::from(*slot);
    }

    let bytes = bitmap.to_le_bytes();

    let size = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map(|idx| idx + 1)
        .unwrap_or(0);

    bytes[..size].to_vec()
}
