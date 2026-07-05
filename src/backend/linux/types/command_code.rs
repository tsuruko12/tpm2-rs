use tss_esapi::{constants::CommandCode, structures::CommandCodeList};

use crate::{
    Error, Result,
    types::{TpmCc, TpmlCc},
};

impl From<CommandCodeList> for TpmlCc {
    fn from(value: CommandCodeList) -> Self {
        let items = value
            .into_inner()
            .into_iter()
            .map(|v| u32::from(v))
            .collect();

        Self::new(items)
    }
}

pub(crate) fn to_command_code(value: TpmCc) -> Result<CommandCode> {
    CommandCode::try_from(value).map_err(|_| {
        tracing::error!(value = ?value, "failed to convert to ESAPI value");
        Error::Internal("failed to convert command code to ESAPI value")
    })
}
