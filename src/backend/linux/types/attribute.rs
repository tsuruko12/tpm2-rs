use tss_esapi::structures::CommandCodeAttributesList;

use crate::types::{TpmaCc, TpmlCca};

impl From<CommandCodeAttributesList> for TpmlCca {
    fn from(value: CommandCodeAttributesList) -> Self {
        let items = value
            .into_iter()
            .map(|item| TpmaCc::new(item.into()))
            .collect();

        Self::new(items)
    }
}
