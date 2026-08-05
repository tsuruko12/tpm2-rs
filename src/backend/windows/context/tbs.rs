use std::{ffi::c_void, ptr};

use tracing::{debug, error};
use windows_sys::Win32::System::TpmBaseServices::{
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS,
    TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0, TBS_SUCCESS, TPM_VERSION_20, Tbsi_Context_Create,
    Tbsip_Context_Close, Tbsip_Submit_Command,
};

use super::super::{
    codec::{TpmMarshal, TpmUnmarshal},
    commands::{Command, TPM_HEADER_SIZE, TpmiStCommandTag},
    types::TpmRc,
};
use super::Context;
use crate::{
    backend::windows::commands::ResponseHeader,
    error::{Error, Result},
};

const TBS_RESPONSE_BUFFER_SIZE: usize = 256 * 1024;

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
            sessions: [None, None, None],
        })
    }

    pub(super) fn submit(&mut self, command: Command<'_>) -> Result<Vec<u8>> {
        let header = command.header();
        let expected_tag = header.tag();
        let command_code = header.command_code();

        debug!(?command_code, ?expected_tag, "submitting TPM command");

        let mut command_bytes = Vec::new();
        command.marshal(&mut command_bytes)?;
        let command_len = u32::try_from(command_bytes.len())
            .map_err(|_| Error::invalid_state("TPM command length exceeds u32"))?;

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

        get_response_body(&response, expected_tag)
    }

    pub(super) fn close(&mut self) -> Result<()> {
        let status = unsafe { Tbsip_Context_Close(self.handle) };

        if status != TBS_SUCCESS {
            return Err(Error::from_tbs_rc(status));
        }

        Ok(())
    }
}

fn get_response_body(response: &[u8], expected_tag: TpmiStCommandTag) -> Result<Vec<u8>> {
    let response_len = response.len();

    if response_len < TPM_HEADER_SIZE {
        error!(actual_size = response.len(), "response header is too short");
        return Err(Error::InvalidData);
    }

    let mut remaining = response;
    let header = ResponseHeader::unmarshal(&mut remaining)?;

    if header.response_size() as usize != response_len {
        error!(
            declared_size = header.response_size(),
            remaining_size = response_len,
            "response size mismatch"
        );
        return Err(Error::InvalidData);
    }

    ensure_success(header.response_code())?;

    if expected_tag != header.tag() {
        error!(
            expected_tag = ?expected_tag,
            returned_tag = ?header.tag(),
            "unexpected TPM response tag"
        );
        return Err(Error::InvalidData);
    }

    Ok(remaining.to_vec())
}

fn ensure_success(response_code: TpmRc) -> Result<()> {
    if response_code == TpmRc::SUCCESS {
        Ok(())
    } else {
        Err(Error::from_rc(response_code))
    }
}
