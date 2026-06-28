use std::{ffi::c_void, ptr};

use windows_sys::Win32::System::TpmBaseServices::{
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS, 
    TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0, TBS_SUCCESS, TPM_VERSION_20, 
    Tbsi_Context_Create, Tbsip_Context_Close, Tbsip_Submit_Command,
};

use super::Context;
use crate::{
    commands::Command, 
    data::MetadataStore, 
    error::{Error, Result}, 
    types::AuthorizationCache,
};

const MAX_RESPONSE_SIZE: usize = 4096;

impl Drop for Context {
    fn drop(&mut self) {
        if let Err(err) = self.close() {
            tracing::debug!(err = %err, "failed to close context handle");
        }

        self.handle = ptr::null_mut();
    }
}

impl Context {
    pub(crate) fn create_context() -> Result<Self> {
        let mut handle = ptr::null_mut();
        let ctx_params2 = TBS_CONTEXT_PARAMS2 {
            version: TPM_VERSION_20,
            Anonymous: TBS_CONTEXT_PARAMS2_0 { asUINT32: 4 },
        };

        let status = unsafe {
            Tbsi_Context_Create(
                &ctx_params2 as *const TBS_CONTEXT_PARAMS2 as *const TBS_CONTEXT_PARAMS,
                &mut handle,
            )
        };

        if status != TBS_SUCCESS {
            return Err(Error::from_tbs_rc(status));
        }

        Ok(Self {
            handle,
            store: MetadataStore::new()?,
            authorization_cache: AuthorizationCache::default(),
        })
    }

    pub(crate) fn submit(&mut self, command: Command) -> Result<Vec<u8>> {
        let command_bytes = command.marshal();
        let mut response = vec![0u8; MAX_RESPONSE_SIZE];
        let mut response_len = response.len() as u32;

        let status = unsafe {
            Tbsip_Submit_Command(
                self.handle as *const c_void,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command_bytes.as_ptr(),
                command_bytes.len() as u32,
                response.as_mut_ptr(),
                &mut response_len,
            )
        };

        if status != TBS_SUCCESS {
            return Err(Error::from_tbs_rc(status));
        }

        response.truncate(response_len as usize);

        Ok(response)
    }

    fn close(&mut self) -> Result<()> {
        let status = unsafe { Tbsip_Context_Close(self.handle) };

        if status != TBS_SUCCESS {
            return Err(Error::from_tbs_rc(status));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::context::Context;

    #[test]
    fn connect_to_tbs() {
        let _ = Context::create_context().expect("failed to create TBS context");
    }
}
