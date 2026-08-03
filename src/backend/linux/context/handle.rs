use tracing::debug;
use tss_esapi::{
    constants::Tss2ResponseCodeKind,
    handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, SessionHandle},
    interface_types::{resource_handles::Provision, session_handles::PolicySession},
};

use crate::{
    Error, Result,
    types::{Authorization, TpmaSession},
};

use super::Context;

// memo: ensure sessions are fushed when proccessing fails
impl Context {
    pub(crate) fn evict_control(
        &mut self,
        handle: ObjectHandle,
        persistent_handle: &mut PersistentTpmHandle,
        owner_authorization: &Authorization,
        session_salt_key: Option<KeyHandle>,
        search_end: Option<PersistentTpmHandle>,
    ) -> Result<ObjectHandle> {
        let sessions = self.prepare_sessions(
            ObjectHandle::Owner,
            owner_authorization,
            TpmaSession::empty(),
            session_salt_key,
        )?;

        let result = loop {
            match self.ctx.execute_with_sessions(sessions, |ctx| {
                ctx.evict_control(Provision::Owner, handle, (*persistent_handle).into())
            }) {
                Ok(handle) => break Ok(handle),
                Err(e) => {
                    if is_nv_defined_err(e) {
                        let handle_raw = u32::from(*persistent_handle);

                        if let Some(end) = search_end {
                            let handle = handle_raw + 1;

                            if handle > end.into() {
                                break Err(Error::PersistentHandleInUse(handle_raw));
                            }

                            *persistent_handle = PersistentTpmHandle::new(handle)
                                .expect("handle must be in the persistent range");

                            continue;
                        }
                        break Err(Error::PersistentHandleInUse(handle_raw));
                    }
                    break Err(Error::from_tss_err(e));
                }
            }
        };

        match result {
            Ok(handle) => {
                self.clear_sessions();
                Ok(handle)
            }
            Err(err) => {
                let _ = self.flush_sessions();
                Err(err)
            }
        }
    }

    pub(super) fn flush_sessions(&mut self) -> Result<()> {
        for idx in 0..self.sessions.len() {
            if let Some(handle) = self.sessions[idx] {
                if let Err(err) = self.flush_context(SessionHandle::from(handle)) {
                    debug!(handle = ?handle, "failed to flush TPM session");
                    return Err(err);
                }
                self.sessions[idx] = None;
            }
        }

        Ok(())
    }

    pub(super) fn clear_sessions(&mut self) {
        self.sessions.fill(None);
    }

    pub(super) fn clear_policy_session(&mut self) {
        for idx in 0..self.sessions.len() {
            if let Some(handle) = self.sessions[idx] {
                if PolicySession::try_from(handle).is_ok() {
                    self.sessions[idx] = None;
                }
            }
        }
    }

    pub(super) fn release_handle(
        &mut self,
        handle: impl Into<ObjectHandle>,
        is_persistent: bool,
    ) -> Result<()> {
        if is_persistent {
            if let Err(err) = self.ctx.tr_close(&mut handle.into()) {
                debug!("failed to close ESAPI handle");
                return Err(Error::from_tss_err(err));
            }
        } else {
            if let Err(err) = self.flush_context(handle) {
                debug!("failed to flush TPM handle");
                return Err(err);
            }
        }

        Ok(())
    }

    fn flush_context(&mut self, handle: impl Into<ObjectHandle>) -> Result<()> {
        self.ctx.flush_context(handle.into()).map_err(Error::from_tss_err)
    }
}

fn is_nv_defined_err(err: tss_esapi::Error) -> bool {
    matches!(
        err,
        tss_esapi::Error::Tss2Error(response_code)
            if response_code.kind()
                == Some(Tss2ResponseCodeKind::NvDefined)
    )
}
