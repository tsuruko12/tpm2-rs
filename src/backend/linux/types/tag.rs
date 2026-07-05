use tracing::error;
use tss_esapi::{
    constants::{PcrPropertyTag, PropertyTag},
    structures::{
        PcrSelectSize, TaggedPcrPropertyList, TaggedPcrSelect as EsapiTaggedPcrSelect,
        TaggedProperty as EsapiTaggedProperty, TaggedTpmPropertyList,
    },
    tss2_esys::TPMS_TAGGED_PCR_SELECT,
};

use super::policy::pcr_select_to_slots;
use crate::{
    Error, Result,
    types::{
        TpmPt, TpmPtPcr, TpmlTaggedPcrProperty, TpmlTaggedTpmProperty, TpmsTaggedPcrSelect,
        TpmsTaggedProperty,
    },
};

impl TryFrom<TpmsTaggedProperty> for EsapiTaggedProperty {
    type Error = Error;

    fn try_from(value: TpmsTaggedProperty) -> Result<Self> {
        let property = PropertyTag::try_from(value.property() as u32).map_err(|_| {
            error!(value = ?value, "failed to convert to ESAPI value");
            Error::Internal("failed to convert tagged property to ESAPI value")
        })?;

        Ok(Self::new(property, value.value()))
    }
}

impl TryFrom<TpmsTaggedPcrSelect> for EsapiTaggedPcrSelect {
    type Error = Error;

    fn try_from(value: TpmsTaggedPcrSelect) -> Result<Self> {
        let tag = PcrPropertyTag::try_from(value.tag() as u32).map_err(|_| {
            error!(value = ?value, "failed to convert to ESAPI value");
            Error::Internal("failed to convert pcr property tag to ESAPI value")
        })?;
        let select_size = u8::try_from(value.pcr_select().len())
            .map_err(|_| Error::Internal("invalid PCR select size"))?;
        let size_of_select = PcrSelectSize::try_from(select_size)
            .map_err(|_| Error::Internal("invalid PCR select size"))?;
        let selected_pcr_slots = pcr_select_to_slots(value.pcr_select())?;

        Self::create(tag, size_of_select, &selected_pcr_slots)
            .map_err(|_| Error::Internal("invalid tagged PCR selection"))
    }
}

impl TryFrom<TaggedTpmPropertyList> for TpmlTaggedTpmProperty {
    type Error = Error;

    fn try_from(value: TaggedTpmPropertyList) -> Result<Self> {
        let items = value
            .into_iter()
            .map(|item| {
                let property = TpmPt::try_from(u32::from(item.property()))?;
                Ok(TpmsTaggedProperty::new(property, item.value()))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self::new(items))
    }
}

impl TryFrom<TaggedPcrPropertyList> for TpmlTaggedPcrProperty {
    type Error = Error;

    fn try_from(value: TaggedPcrPropertyList) -> Result<Self> {
        let items = value
            .into_iter()
            .map(tpms_tagged_pcr_select_from_esapi)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self::new(items))
    }
}

fn tpms_tagged_pcr_select_from_esapi(value: EsapiTaggedPcrSelect) -> Result<TpmsTaggedPcrSelect> {
    let raw: TPMS_TAGGED_PCR_SELECT = value.into();
    let size = usize::from(raw.sizeofSelect);
    let pcr_select = raw
        .pcrSelect
        .get(..size)
        .ok_or(Error::Internal("invalid PCR select size"))?
        .to_vec();

    Ok(TpmsTaggedPcrSelect::new(
        TpmPtPcr::try_from(raw.tag)?,
        pcr_select,
    ))
}
