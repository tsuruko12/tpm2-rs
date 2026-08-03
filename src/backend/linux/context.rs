mod capability;
mod handle;
mod key;
mod provision;
mod random;
mod session;
mod tcti;

use tss_esapi::{
    Context as EsapiContext,
    handles::ObjectHandle,
    interface_types::session_handles::{AuthSession, PolicySession},
    structures::Auth,
};

use crate::{Error, Result};

type SessionSlotArray = [Option<AuthSession>; 3];

type SessionSlots = (
    Option<AuthSession>,
    Option<AuthSession>,
    Option<AuthSession>,
);

#[derive(Debug)]
pub(crate) struct Context {
    ctx: EsapiContext,
}

#[derive(Debug, Default, Clone)]
struct CommandResources {
    sessions: SessionSlotArray,
    transient_handles: Vec<ObjectHandle>,
    persistent_handles: Vec<ObjectHandle>,
}

impl CommandResources {
    fn sessions(&self) -> &SessionSlotArray {
        &self.sessions
    }

    fn session_slots(&self) -> SessionSlots {
        (self.sessions[0], self.sessions[1], self.sessions[2])
    }

    fn add_session(&mut self, session: AuthSession) -> Result<()> {
        let slot = self
            .sessions
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| Error::invalid_state("no available session slots"))?;

        *slot = Some(session);

        Ok(())
    }

    fn add_transient_handle(&mut self, handle: impl Into<ObjectHandle>) {
        self.transient_handles.push(handle.into());
    }

    fn add_persistent_handle(&mut self, handle: impl Into<ObjectHandle>) {
        self.persistent_handles.push(handle.into());
    }

    fn find_hmac_session(&self) -> Option<AuthSession> {
        self.sessions
            .iter()
            .flatten()
            .copied()
            .find(|session| matches!(session, AuthSession::HmacSession(_)))
    }

    fn clear_policy_session(&mut self) {
        for session in self.sessions.iter_mut() {
            if let Some(handle) = session {
                if PolicySession::try_from(*handle).is_ok() {
                    *session = None;
                    return;
                }
            }
        }
    }

    fn clear_password_session(&mut self) {
        for session in self.sessions.iter_mut() {
            if let Some(handle) = session {
                if *handle == AuthSession::Password {
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

fn auth_from_bytes(bytes: &[u8]) -> Result<Auth> {
    bytes
        .try_into()
        .map_err(|_| Error::invalid_state("auth value exceeds the nameAlg digest size"))
}
