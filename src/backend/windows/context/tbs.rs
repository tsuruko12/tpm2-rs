use std::{ffi::c_void, ptr};

use windows_sys::Win32::System::TpmBaseServices::{
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS, 
    TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0, TBS_SUCCESS, TPM_VERSION_20, 
    Tbsi_Context_Create, Tbsip_Context_Close, Tbsip_Submit_Command,
};

use super::{
    Command, Context, TpmRc, TpmSt, Uint32, TPM_HEADER_SIZE, TPM_RC_SUCCESS,
};
use crate::{
    db::MetadataStore, 
    error::{Error, Result}, 
    types::AuthorizationCache,
};

const TBS_RESPONSE_BUFFER_SIZE: usize = 256 * 1024;

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
        let command_len = u32::try_from(command_bytes.len())
            .map_err(|_| Error::Internal("TPM command length exceeds u32"))?;

        let mut response = vec![0u8; TBS_RESPONSE_BUFFER_SIZE];
        let mut response_len = response.len() as u32;

        let status = unsafe {
            Tbsip_Submit_Command(
                self.handle as *const c_void,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command_bytes.as_ptr(),
                command_len,
                response.as_mut_ptr(),
                &mut response_len,
            )
        };

        if status != TBS_SUCCESS {
            return Err(Error::from_tbs_rc(status));
        }

        response.truncate(response_len as usize);

        unmarshal_response_body(&response)
    }

    fn close(&mut self) -> Result<()> {
        let status = unsafe { Tbsip_Context_Close(self.handle) };

        if status != TBS_SUCCESS {
            return Err(Error::from_tbs_rc(status));
        }

        Ok(())
    }
}

fn unmarshal_response_body(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < TPM_HEADER_SIZE {
        return Err(Error::Internal("TPM response must be at least 10 bytes"));
    }

    let tag = TpmSt::from_be_bytes(bytes[0..2].try_into().unwrap());
    let response_size = Uint32::from_be_bytes(bytes[2..6].try_into().unwrap()) as usize;
    let response_code = TpmRc::from_be_bytes(bytes[6..TPM_HEADER_SIZE].try_into().unwrap());

    tracing::debug!(
        tag = format_args!("{:#06X}", tag),
        response_size,
        response_code = format_args!("{:#05X}", response_code),
        "unmarshalled TPM response header"
    );

    if response_size != bytes.len() {
        return Err(Error::Internal("unexpected TPM response size"));
    }

    ensure_success(response_code)?;

    Ok(bytes[TPM_HEADER_SIZE..response_size].to_vec())
}

fn ensure_success(response_code: TpmRc) -> Result<()> {
    if response_code == TPM_RC_SUCCESS {
        Ok(())
    } else {
        Err(Error::from_rc(response_code))
    }
}

#[cfg(test)]
mod tests {
    use crate::context::Context;

    #[test]
    fn connect_to_tbs() {
        let _ = Context::connect().expect("failed to create TBS context");
    }
}
