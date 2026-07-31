use tss_esapi::{constants::CommandCode, structures::CommandCodeList};

use crate::{
    Error, Result,
    types::{TpmCc, TpmlCc},
};

impl TryFrom<CommandCodeList> for TpmlCc {
    type Error = Error;

    fn try_from(cc_list: CommandCodeList) -> Result<Self> {
        let items = cc_list
            .into_inner()
            .into_iter()
            .map(|v| u32::from(v).try_into())
            .collect::<Result<Vec<_>>>()?;

        Ok(items.into())
    }
}

impl TryFrom<TpmCc> for CommandCode {
    type Error = Error;

    fn try_from(cc: TpmCc) -> Result<Self> {
        cc.raw()
            .try_into()
            .map_err(|_| Error::conversion::<TpmCc, CommandCode>(None))
    }
}
