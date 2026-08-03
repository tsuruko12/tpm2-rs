mod capability;
mod handle;
mod key;
mod provision;
mod random;
mod session;
mod tbs;

use std::{ffi::c_void, ptr};

use crate::{Error, Result, types::TpmiDhObject};
use super::types::TpmiShAuthSession;

type ContextHandle = *mut c_void;

#[derive(Debug)]
pub(crate) struct Context {
    handle: ContextHandle,
    sessions: [Option<TpmiShAuthSession>; 3],
}

type SessionSlots = [Option<TpmiShAuthSession>; 3];

#[derive(Debug, Default, Clone)]
struct CommandResources {
    sessions: SessionSlots,
    transient_handles: Vec<TpmiDhObject>,
}

impl CommandResources {
    fn sessions(&self) -> &SessionSlots {
        &self.sessions
    }

    fn add_session(&mut self, session: TpmiShAuthSession) -> Result<()> {
        let slot = self
            .sessions
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| Error::invalid_state("no available session slots"))?;

        *slot = Some(session);

        Ok(())
    }

    fn add_transient_handle(&mut self, handle: TpmiDhObject) {
        self.transient_handles.push(handle);
    }

    fn find_hmac_session(&self) -> Option<TpmiShAuthSession> {
        self.sessions
            .iter()
            .flatten()
            .copied()
            .find(|session| session.is_hmac_session())
    }

    fn clear_policy_session(&mut self) {
        for session in self.sessions.iter_mut() {
            if let Some(handle) = session {
                if handle.is_policy_session() {
                    *session = None;
                    return;
                }
            }
        }
    }

    fn clear_sessions(&mut self) {
        self.sessions.fill(None);
    }
}

impl Context {
    fn finish_command<T>(
        &mut self,
        result: Result<T>,
        resources: &mut CommandResources,
    ) -> Result<T> {
        match result {
            Ok(value) => {
                self.flush_sessions(&mut resources.sessions)?;
                Ok(value)
            },
            Err(e) => {
                let _ = self.cleanup_resources(resources);
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
