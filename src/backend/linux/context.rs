mod capability;
mod handle;
mod key;
mod provision;
mod random;
mod session;
mod tcti;

use tracing::debug;
use tss_esapi::{
    Context as EsapiContext,
    handles::ObjectHandle,
    interface_types::session_handles::AuthSession,
};

use crate::{Error, Result, types::LoadedObjectHandle};

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
    fn session_slots(&self) -> SessionSlots {
        debug!(sessions = ?self.sessions);
        (self.sessions[0], self.sessions[1], self.sessions[2])
    }

    fn has_no_sessions(&self) -> bool {
        self.sessions
            .iter()
            .all(|session| session.is_none())
    }

    fn add_session(&mut self, session: AuthSession) -> Result<()> {
        let slot = self.sessions
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| Error::invalid_state("no available session slots"))?;

        *slot = Some(session);

        Ok(())
    }

    fn add_handle(&mut self, loaded_handle: LoadedObjectHandle) {
        if loaded_handle.is_persistent() {
            self.add_persistent_handle(loaded_handle.inner().into());
        } else {
            self.add_transient_handle(loaded_handle.inner().into());
        }
    }

    fn add_transient_handle(&mut self, handle: ObjectHandle) {
        self.transient_handles.push(handle);
    }

    fn add_persistent_handle(&mut self, handle: ObjectHandle) {
        self.persistent_handles.push(handle);
    }

    fn find_hmac_session(&self) -> Option<AuthSession> {
        self.find_session(SessionKind::Hmac)
    }

    fn find_password_session(&self) -> Option<AuthSession> {
        self.find_session(SessionKind::Password)
    }

    fn find_policy_session(&self) -> Option<AuthSession> {
        self.find_session(SessionKind::Policy)
    }

    fn find_session(&self, kind: SessionKind) -> Option<AuthSession> {
        self.sessions.iter().flatten().copied().find(|session| {
            matches!(
                (kind, session),
                (SessionKind::Hmac, AuthSession::HmacSession(_))
                    | (SessionKind::Policy, AuthSession::PolicySession(_))
                    | (SessionKind::Password, AuthSession::Password)
            )
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum SessionKind {
    Hmac,
    Policy,
    Password,
}

impl Context {
    fn finalize_command<T>(
        &mut self,
        result: Result<T>,
        resources: &mut CommandResources,
    ) -> Result<T> {
        match result {
            Ok(value) => {
                resources.flush_sessions(self)?;
                Ok(value)
            },
            Err(e) => {
                let _ = resources.cleanup(self);
                Err(e)
            }
        }
    }
}
