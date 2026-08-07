use tss_esapi::{
    attributes::{ObjectAttributes, SessionAttributes},
    structures::CommandCodeAttributesList,
};

use crate::{
    Error, Result,
    types::{TpmaObject, TpmaSession, TpmlCca},
};

impl TryFrom<CommandCodeAttributesList> for TpmlCca {
    type Error = Error;

    fn try_from(cca_list: CommandCodeAttributesList) -> Result<Self> {
        let items = cca_list
            .into_iter()
            .map(|item| item.0.try_into())
            .collect::<Result<Vec<_>>>()?;

        Ok(items.into())
    }
}

impl From<TpmaSession> for SessionAttributes {
    fn from(session_attrs: TpmaSession) -> Self {
        session_attrs.bits().into()
    }
}

impl From<ObjectAttributes> for TpmaObject {
    fn from(obj_attrs: ObjectAttributes) -> Self {
        Self::from_bits_retain(obj_attrs.0)
    }
}
