use windows_sys::Win32::Foundation::{
    TBS_E_BAD_PARAMETER, TBS_E_INTERNAL_ERROR, TBS_E_IOERROR, TBS_E_SERVICE_DISABLED,
    TBS_E_SERVICE_NOT_RUNNING, TBS_E_SERVICE_START_PENDING, TBS_E_TPM_NOT_FOUND,
};

use crate::error::Error;

#[derive(thiserror::Error, Debug)]
pub(crate) enum TbsError {
    #[error("TBS service is disabled")]
    ServiceDisabled,
    #[error("TBS service is not running and could not be started")]
    ServiceNotRunning,
    #[error("TBS service has been started but is not yet running")]
    ServiceStartPending,
    #[error("TPM was not found on this computer")]
    TpmNotFound,
    #[error("TBS communication with the TPM failed")]
    IoError,
    #[error("TBS internal software error occurred")]
    Internal,
}

impl TbsError {
    fn connect(code: u32) -> Self {
        match code as i32 {
            TBS_E_SERVICE_DISABLED => Self::ServiceDisabled,
            TBS_E_SERVICE_NOT_RUNNING => Self::ServiceNotRunning,
            TBS_E_SERVICE_START_PENDING => Self::ServiceStartPending,
            TBS_E_TPM_NOT_FOUND => Self::TpmNotFound,
            _ => unimplemented!(""),
        }
    }

    fn failure(code: u32) -> Self {
        match code as i32 {
            TBS_E_IOERROR => Self::IoError,
            _ => unimplemented!(""),
        }
    }
}

impl Error {
    pub(super) fn from_tbs_rc(code: u32) -> Self {
        match code as i32 {
            TBS_E_SERVICE_DISABLED
            | TBS_E_SERVICE_NOT_RUNNING
            | TBS_E_SERVICE_START_PENDING
            | TBS_E_TPM_NOT_FOUND => Self::connect(TbsError::connect(code)),
            TBS_E_BAD_PARAMETER => Self::invalid_param("invaid parameters"),
            TBS_E_IOERROR => Self::failure(TbsError::failure(code)),
            TBS_E_INTERNAL_ERROR => Self::failure(TbsError::Internal),
            _ => {
                tracing::error!(code, "internal error");
                Self::Internal("unexpected error occured")
            }
        }
    }
}
