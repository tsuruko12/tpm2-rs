use tss_esapi::{handles::TpmHandle as EsapiTpmHandle, structures::HandleList};

use crate::{
    Error, Result,
    types::{TpmHandle, TpmlHandle},
};

impl From<HandleList> for TpmlHandle {
    fn from(handle_list: HandleList) -> Self {
        let items = handle_list
            .into_inner()
            .into_iter()
            .map(|handle| TpmHandle::new(handle.into()))
            .collect::<Vec<_>>();

        items.into()
    }
}

impl TryFrom<TpmHandle> for EsapiTpmHandle {
    type Error = Error;

    fn try_from(handle: TpmHandle) -> Result<Self> {
        handle
            .raw()
            .try_into()
            .map_err(|_| Error::conversion::<TpmHandle, EsapiTpmHandle>(None))
    }
}
