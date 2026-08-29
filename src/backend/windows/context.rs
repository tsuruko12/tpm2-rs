mod capability;
mod handle;
mod key;
mod provision;
mod random;
mod response;
mod session;
mod tbs;

use std::{ffi::c_void, ptr};

use zeroize::Zeroizing;

use super::types::{Tpm2bNonce, TpmiShAuthSession, TpmiShHmac};
use crate::{Error, Result, types::{LoadedObjectHandle, tpm::TpmiDhObject}};

use self::response::{
    CreatePrimaryResponse, CreateResponse, GetCapabilityResponse, GetRandomResponse, LoadResponse,
    PcrReadResponse, PolicyGetDigestResponse, ReadPublicResponse, RsaEncryptResponse,
    StartAuthSessionResponse,
};
use super::commands::{
    Command, Response, ResponseBody, TpmsAuthCommand, TpmsAuthResponse,
};

type ContextHandle = *mut c_void;

#[derive(Debug)]
pub(crate) struct Context {
    handle: ContextHandle,
}

type SessionSlots = [Option<TpmiShAuthSession>; 3];
type SessionStates = [Option<SessionState>; 3];

#[derive(Debug, Default, Clone)]
struct CommandResources {
    session_handles: SessionSlots,
    session_states: SessionStates,
    transient_handles: Vec<TpmiDhObject>,
}

#[derive(Debug, Clone)]
struct SessionState {
    session_value: Zeroizing<Vec<u8>>,
    nonce_tpm: Tpm2bNonce,
    uses_hmac: bool,
}

impl SessionState {
    fn update_nonce(&mut self, nonce_tpm: Tpm2bNonce) {
        self.nonce_tpm = nonce_tpm;
    }
}

impl CommandResources {
    fn session_handles(&self) -> SessionSlots {
        self.session_handles
    }

    fn session_states(&self) -> &SessionStates {
        &self.session_states
    }

    fn add_session_handle(&mut self, handle: TpmiShAuthSession) -> Result<()> {
        let slot = self
            .session_handles
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| Error::invalid_state("no available session handle slots"))?;

        *slot = Some(handle);

        Ok(())
    }

    fn add_session_state(&mut self, state: SessionState) -> Result<()> {
        let slot = self
            .session_states
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| Error::invalid_state("no available session state slots"))?;

        *slot = Some(state);

        Ok(())
    }

    fn track_loaded_handle(&mut self, loaded_handle: LoadedObjectHandle) {
        if !loaded_handle.is_persistent() {
            self.add_transient_handle(loaded_handle.inner().into());
        }
    }

    fn add_transient_handle(&mut self, handle: TpmiDhObject) {
        self.transient_handles.push(handle);
    }

    fn get_session_state(&self, session_handle: TpmiShAuthSession) -> Result<&SessionState> {
        let idx = self.session_state_idx(session_handle)?;
        self.session_states[idx].as_ref().ok_or_else(|| {
            Error::invalid_state("session handle must have a corresponding session state")
        })
    }

    fn get_session_state_mut(
        &mut self,
        session_handle: TpmiShAuthSession,
    ) -> Result<&mut SessionState> {
        let idx = self.session_state_idx(session_handle)?;
        self.session_states[idx].as_mut().ok_or_else(|| {
            Error::invalid_state("session handle must have a corresponding session state")
        })
    }

    fn session_state_idx(&self, session_handle: TpmiShAuthSession) -> Result<usize> {
        self.session_handles
            .iter()
            .position(|handle| *handle == Some(session_handle))
            .ok_or_else(|| Error::invalid_state("session handle must be tracked"))
    }

    fn find_hmac_session(&self) -> Option<(TpmiShAuthSession, &SessionState)> {
        self.session_handles
            .iter()
            .zip(self.session_states.iter())
            .find_map(|(handle, state)| match (*handle, state.as_ref()) {
                (Some(handle), Some(state)) if TpmiShHmac::try_from(handle).is_ok() => Some((handle, state)),
                _ => None,
            })
    }

    fn clear_session(&mut self, target: TpmiShAuthSession) {
        if let Some(idx) = self
            .session_handles
            .iter()
            .position(|handle| *handle == Some(target))
        {
            self.session_handles[idx] = None;
            self.session_states[idx] = None;
        }
    }

    fn clear_sessions(&mut self) {
        self.session_handles.fill(None);
        self.session_states.fill(None);
    }
}

// TODO: rename to cleanup_on_err
impl Context {
    fn cleanup_on_error<T>(
        &mut self,
        result: Result<T>,
        resources: &mut CommandResources,
    ) -> Result<T> {
        match result {
            Ok(value) => Ok(value),
            Err(e) => {
                resources.cleanup(self);
                Err(e)
            }
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if let Err(e) = self.close() {
            tracing::debug!(err = ?e, "failed to close TBS context handle");
        }

        self.handle = ptr::null_mut();
    }
}
