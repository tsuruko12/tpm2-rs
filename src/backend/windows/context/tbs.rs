mod crypto;

use std::{ffi::c_void, ptr};

use tracing::debug;
use windows_sys::Win32::{
    Foundation::TBS_E_INSUFFICIENT_BUFFER,
    System::TpmBaseServices::{
        TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS,
        TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0, TBS_SUCCESS, TPM_VERSION_20,
        Tbsi_Context_Create, Tbsip_Context_Close, Tbsip_Submit_Command,
    },
};

use self::crypto::{
    CpHashData, compute_hmac, decrypt_parameter, encrypt_parameter, verify_response_hmac,
};
use super::super::types::TpmiShAuthSession;
use super::{
    Command, CommandResources, Context, Response, ResponseBody, TpmsAuthCommand, TpmsAuthResponse,
};
use crate::{
    error::{Error, Result}, types::tpm::{TPM2B_SIZE_BYTES, TpmCc, TpmHandle, TpmMarshal, TpmaSession},
};

const INIT_TBS_RESPONSE_SIZE: usize = 4096;
const MAX_RETRY_COUNT: usize = 3;

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

        Ok(Self { handle })
    }

    pub(super) fn submit(
        &mut self,
        command: &mut Command<'_>,
        response_handle_count: usize,
        resources: &mut CommandResources,
    ) -> Result<ResponseBody> {
        if !command.authorization_area().is_empty() {
            self.prepare_command_authorization_area(command, resources)?;
        }

        let header = command.header();
        let expected_tag = header.tag();
        let command_code = header.command_code();

        let mut command_bytes = Vec::new();
        command.marshal(&mut command_bytes)?;
        let command_len = u32::try_from(command_bytes.len())
            .map_err(|_| Error::invalid_state("TPM command length exceeds u32::MAX"))?;

        let mut response_bytes = vec![0u8; INIT_TBS_RESPONSE_SIZE];
        let mut response_len = response_bytes.len() as u32;

        debug!(?command_code, ?expected_tag, "submitting TPM command");

        let mut retry_count = 0;

        let response = loop {
            let status = unsafe {
                Tbsip_Submit_Command(
                    self.handle as *const c_void,
                    TBS_COMMAND_LOCALITY_ZERO,
                    TBS_COMMAND_PRIORITY_NORMAL,
                    command_bytes.as_ptr(),
                    command_len,
                    response_bytes.as_mut_ptr(),
                    &mut response_len,
                )
            };
            if status != TBS_SUCCESS {
                if status == TBS_E_INSUFFICIENT_BUFFER as u32 {
                    response_bytes.resize(response_len as usize, 0);
                    continue;
                }
                return Err(Error::from_tbs_rc(status));
            }

            response_bytes.truncate(response_len as usize);

            match Response::parse(&mut response_bytes.as_slice(), response_handle_count) {
                Ok(response) => break response,
                Err(err) => {
                    if matches!(err, Error::Busy(_)) && retry_count < MAX_RETRY_COUNT {
                        retry_count += 1;
                        response_bytes.resize(INIT_TBS_RESPONSE_SIZE, 0);
                        response_len = response_bytes.len() as u32;

                        continue;
                    }
                    return Err(err);
                }
            }
        };

        debug!(?response.header, "TPM response header");

        let mut response_body = response.body;

        process_response_authorization_area(
            command_code,
            command.authorization_area(),
            &response.authorization_area,
            &mut response_body.parameters,
            resources,
        )?;

        Ok(response_body)
    }

    fn prepare_command_authorization_area(
        &mut self,
        command: &mut Command<'_>,
        resources: &mut CommandResources,
    ) -> Result<()> {
        let mut handle_names = None;

        for auth_command_idx in 0..command.authorization_area().len() {
            let (session_handle, nonce_caller, session_attrs) = {
                let auth = &command.authorization_area()[auth_command_idx];
                (
                    auth.session_handle(),
                    auth.nonce().clone(),
                    auth.session_attributes(),
                )
            };
            if session_handle == TpmiShAuthSession::RS_PW
                || !session_attrs.contains(TpmaSession::DECRYPT)
            {
                continue;
            }

            let session_state = resources.get_session_state(session_handle)?;
            encrypt_parameter(
                &session_state.session_value,
                nonce_caller.as_bytes(),
                session_state.nonce_tpm.as_bytes(),
                tpm2b_buffer_mut(command.parameters_mut())?,
            )?;
        }

        for auth_command_idx in 0..command.authorization_area().len() {
            let (session_handle, nonce_caller, session_attrs) = {
                let auth = &command.authorization_area()[auth_command_idx];
                (
                    auth.session_handle(),
                    auth.nonce().clone(),
                    auth.session_attributes(),
                )
            };
            if session_handle == TpmiShAuthSession::RS_PW {
                continue;
            }

            let session_state = resources.get_session_state(session_handle)?;

            if session_state.uses_hmac {
                if handle_names.is_none() {
                    handle_names = Some(self.resolve_handle_names(command.handles())?);
                }

                let cp_hash_data = CpHashData {
                    command_code: command.header().command_code(),
                    handle_names: handle_names.as_deref().unwrap(),
                    parameters: command.parameters(),
                };

                let hmac = compute_hmac(
                    &session_state.session_value,
                    &cp_hash_data,
                    nonce_caller.as_bytes(),
                    session_state.nonce_tpm.as_bytes(),
                    session_attrs,
                )?;

                command.authorization_area_mut()[auth_command_idx].set_hmac(hmac);
            }
        }

        Ok(())
    }

    fn resolve_handle_names(&mut self, handles: &[TpmHandle]) -> Result<Vec<Vec<u8>>> {
        let mut handle_names = Vec::new();
        for handle in handles {
            if handle.is_hierarchy_handle() {
                handle_names.push(handle.value().to_be_bytes().to_vec());
            } else {
                handle_names.push(self.read_obj_name((*handle).try_into()?)?.into_bytes());
            }
        }

        Ok(handle_names)
    }

    pub(super) fn close(&mut self) -> Result<()> {
        let status = unsafe { Tbsip_Context_Close(self.handle) };
        if status != TBS_SUCCESS {
            return Err(Error::from_tbs_rc(status));
        }

        Ok(())
    }
}

fn process_response_authorization_area(
    command_code: TpmCc,
    auth_commands: &[TpmsAuthCommand],
    auth_responses: &[TpmsAuthResponse],
    parameters: &mut [u8],
    resources: &mut CommandResources,
) -> Result<()> {
    ensure_matching_auth_count(auth_commands, auth_responses)?;

    for (auth_command, auth_response) in auth_commands.iter().zip(auth_responses) {
        let session_handle = auth_command.session_handle();
        if session_handle == TpmiShAuthSession::RS_PW {
            continue;
        }

        let session_state = resources.get_session_state(session_handle)?;
        if session_state.uses_hmac {
            verify_response_hmac(
                &session_state.session_value,
                command_code,
                parameters,
                auth_command.nonce().as_bytes(),
                auth_response,
            )?;
        }
    }

    apply_response_session_attrs(parameters, auth_commands, auth_responses, resources)?;

    Ok(())
}

fn apply_response_session_attrs(
    parameters: &mut [u8],
    auth_commands: &[TpmsAuthCommand],
    auth_responses: &[TpmsAuthResponse],
    resources: &mut CommandResources,
) -> Result<()> {
    for (auth_command, auth_response) in auth_commands.iter().zip(auth_responses) {
        let session_handle = auth_command.session_handle();
        if session_handle == TpmiShAuthSession::RS_PW {
            continue;
        }

        let session_state = resources.get_session_state_mut(session_handle)?;
        if auth_command
            .session_attributes()
            .contains(TpmaSession::ENCRYPT)
        {
            decrypt_parameter(
                &session_state.session_value,
                auth_response.nonce.as_bytes(),
                auth_command.nonce().as_bytes(),
                tpm2b_buffer_mut(parameters)?,
            )?;
        }
        if auth_response
            .session_attributes
            .contains(TpmaSession::CONTINUE_SESSION)
        {
            session_state.update_nonce(auth_response.nonce.clone());
        } else {
            resources.clear_session(session_handle);
        }
    }

    Ok(())
}

fn ensure_matching_auth_count(
    auth_commands: &[TpmsAuthCommand],
    auth_responses: &[TpmsAuthResponse],
) -> Result<()> {
    if auth_commands.len() != auth_responses.len() {
        debug!(
            expected_count = auth_commands.len(),
            returned = auth_responses.len(),
            "response authorization count mismatch"
        );
        return Err(Error::InvalidData);
    }

    Ok(())
}

fn tpm2b_buffer_mut(input: &mut [u8]) -> Result<&mut [u8]> {
    if input.len() < TPM2B_SIZE_BYTES {
        debug!(
            bytes_len = input.len(),
            "insufficient bytes for TPM2B size field"
        );
        return Err(Error::InvalidData);
    }

    let size = u16::from_be_bytes([input[0], input[1]]) as usize;
    let end = TPM2B_SIZE_BYTES + size;

    if input.len() < end {
        debug!(
            bytes_len = input.len(),
            "insufficient bytes for TPM2B buffer field"
        );
        return Err(Error::InvalidData);
    }

    Ok(&mut input[TPM2B_SIZE_BYTES..end])
}
