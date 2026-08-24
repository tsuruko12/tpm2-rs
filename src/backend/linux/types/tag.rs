use tracing::debug;
use tss_esapi::{
    constants::{PcrPropertyTag, PropertyTag},
    structures::{
        PcrSelectSize, TaggedPcrPropertyList, TaggedPcrSelect, TaggedProperty,
        TaggedTpmPropertyList,
    },
};

use super::policy;
use crate::{
    Error, Result,
    error::BoxError,
    types::tpm::{
        TpmPt, TpmPtPcr, TpmlTaggedPcrProperty, TpmlTaggedTpmProperty, TpmsTaggedPcrSelect,
        TpmsTaggedProperty,
    },
};

impl TryFrom<TpmsTaggedProperty> for TaggedProperty {
    type Error = Error;

    fn try_from(tagged_prop: TpmsTaggedProperty) -> Result<Self> {
        let property = PropertyTag::try_from(tagged_prop.property() as u32)
            .map_err(|_| Error::conversion::<TpmsTaggedProperty, TaggedProperty>(None))?;

        Ok(Self::new(property, tagged_prop.value()))
    }
}

impl TryFrom<TpmsTaggedPcrSelect> for TaggedPcrSelect {
    type Error = Error;

    fn try_from(tagged_pcr_select: TpmsTaggedPcrSelect) -> Result<Self> {
        convert_tagged_pcr_select(&tagged_pcr_select).map_err(|e| {
            debug!("{e}");
            Error::conversion::<TpmsTaggedPcrSelect, TaggedPcrSelect>(None)
        })
    }
}

fn convert_tagged_pcr_select(
    tagged_pcr_select: &TpmsTaggedPcrSelect,
) -> std::result::Result<TaggedPcrSelect, BoxError> {
    let tag = PcrPropertyTag::try_from(tagged_pcr_select.tag() as u32)?;
    let size_of_select = PcrSelectSize::try_parse_usize(tagged_pcr_select.pcr_select().len())?;
    let selected_pcr_slots = policy::pcr_select_to_slots(tagged_pcr_select.pcr_select())?;

    Ok(TaggedPcrSelect::create(
        tag,
        size_of_select,
        &selected_pcr_slots,
    )?)
}

impl TryFrom<TaggedTpmPropertyList> for TpmlTaggedTpmProperty {
    type Error = Error;

    fn try_from(prop_list: TaggedTpmPropertyList) -> Result<Self> {
        let items = prop_list
            .into_iter()
            .map(|item| {
                let property = TpmPt::try_from(u32::from(item.property()))?;
                Ok(TpmsTaggedProperty::new(property, item.value()))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self::from(items))
    }
}

impl TryFrom<TaggedPcrPropertyList> for TpmlTaggedPcrProperty {
    type Error = Error;

    fn try_from(prop_list: TaggedPcrPropertyList) -> Result<Self> {
        let items = prop_list
            .into_iter()
            .map(TpmsTaggedPcrSelect::try_from)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self::from(items))
    }
}

impl TryFrom<TaggedPcrSelect> for TpmsTaggedPcrSelect {
    type Error = Error;

    fn try_from(tagged_pcr_select: TaggedPcrSelect) -> Result<Self> {
        let tag = tagged_pcr_select.pcr_property_tag().try_into()?;
        let pcr_select = policy::pcr_slots_to_select(
            &tagged_pcr_select.selected_pcrs(),
            tagged_pcr_select.size_of_select(),
        );

        Ok(Self::new(tag, pcr_select))
    }
}

impl TryFrom<PcrPropertyTag> for TpmPtPcr {
    type Error = Error;

    fn try_from(tag: PcrPropertyTag) -> Result<Self> {
        (tag as u32).try_into()
    }
}
