use tss_esapi::structures::HandleList;

use crate::types::{TpmHandle, TpmlHandle};

impl From<HandleList> for TpmlHandle {
    fn from(value: HandleList) -> Self {
        let items = value
            .into_inner()
            .into_iter()
            .map(|handle| TpmHandle::new(handle.into()))
            .collect();

        Self::new(items)
    }
}
