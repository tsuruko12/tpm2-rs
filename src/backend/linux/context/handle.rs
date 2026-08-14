use tracing::debug;
use tss_esapi::{
    constants::Tss2ResponseCodeKind,
    handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, SessionHandle},
    interface_types::{resource_handles::Provision, session_handles::{AuthSession, PolicySession}},
};

use crate::{Error, Result, types::{Authorization, TpmaSession}};
use super::{Context, CommandResources, SessionSlotArray};

impl Context {
    pub(super) fn evict_control(
        &mut self,
        resources: &mut CommandResources,
        obj_handle: ObjectHandle,
        persistent_handle: &mut PersistentTpmHandle,
        owner_authorization: &Authorization,
        session_salt_key: Option<KeyHandle>,
        search_end: Option<PersistentTpmHandle>,
    ) -> Result<ObjectHandle> {
        let result = (|| {
            self.prepare_sessions(
                resources,
                Some((ObjectHandle::Owner, owner_authorization)),
                TpmaSession::empty().with_continue_session(),
                session_salt_key,
            )?;

            loop {
                match self.ctx.execute_with_sessions(resources.session_slots(), |ctx| {
                    ctx.evict_control(Provision::Owner, obj_handle, (*persistent_handle).into())
                }) {
                    Ok(handle) => break Ok(handle),
                    Err(e) => {
                        if is_nv_defined_err(e) {
                            let handle_raw = u32::from(*persistent_handle);

                            if let Some(end) = search_end {
                                let next_handle = handle_raw + 1;

                                if next_handle > end.into() {
                                    break Err(Error::PersistentHandleInUse(handle_raw));
                                }

                                *persistent_handle = PersistentTpmHandle::new(next_handle)
                                    .expect("handle must be in the persistent range");

                                continue;
                            }
                            break Err(Error::PersistentHandleInUse(handle_raw));
                        }
                        break Err(Error::from_tss_err(e));
                    }
                }
            }
        })();

        self.finish_command(result, resources)
    }

    fn flush_sessions(&mut self, sessions: &mut SessionSlotArray) -> Result<()> {
        let mut first_err = None;

        for session in sessions {
            let Some(handle) = *session else {
                continue;
            };

            if handle != AuthSession::Password {
                if let Err(e) = self.flush_context(SessionHandle::from(handle).into()) {
                    first_err.get_or_insert(e);
                    debug!(?handle, "failed to flush TPM session");

                    continue;
                }       
            }

            *session = None;
        }

        first_err.map_or(Ok(()), Err)
    }

    pub(super) fn flush_handle(&mut self, handle: &mut ObjectHandle) -> Result<()> {
        if *handle == ObjectHandle::None {
            return Ok(());
        }

        self
            .flush_context(*handle)
            .inspect_err(|_| debug!("failed to flush TPM handle"))?;

        *handle = ObjectHandle::None;

        Ok(())
    }

   fn flush_handles(&mut self, handles: &mut Vec<ObjectHandle>) -> Result<()> {
        let mut first_err = None;

        for handle in handles.iter_mut() {
            if let Err(e) = self.flush_handle(handle) {
                first_err.get_or_insert(e);
            }
        }

        first_err.map_or(Ok(()), Err)
    }

    fn close_handles(&mut self, handles: &mut Vec<ObjectHandle>) -> Result<()> {
        let mut first_err = None;

        for handle in handles.iter_mut() {
            if let Err(e) = self.close_handle(handle) {
                first_err.get_or_insert(e);

                debug!("failed to close ESAPI handle");
            }
        }

        first_err.map_or(Ok(()), Err)
    }

    pub(super) fn close_handle(&mut self, handle: &mut ObjectHandle) -> Result<()> {
        if *handle == ObjectHandle::None {
            return Ok(());
        }

        if let Err(e) = self.ctx.tr_close(handle) {
            debug!("failed to close ESAPI handle");
            return Err(Error::from_tss_err(e));
        } 

        Ok(())
    }

    fn flush_policy_session(&mut self, sessions: &mut SessionSlotArray) -> Result<()> {
        for session in sessions.iter_mut() {
            let Some(handle) = *session else {
                continue;
            };

            if PolicySession::try_from(handle).is_ok() {
                self.flush_context(SessionHandle::from(handle).into())?;
                *session = None;
                
                return Ok(());
            }
        }

        Ok(())
    }

    fn flush_context(&mut self, flush_handle: ObjectHandle) -> Result<()> {
        self.ctx.flush_context(flush_handle).map_err(Error::from_tss_err)
    }
}

impl CommandResources {
    pub(super) fn release_handle(
        &mut self, 
        ctx: &mut Context, 
        target: ObjectHandle, 
        is_persistent: bool
    ) -> Result<()> {
        if is_persistent {
            self.close_handle(ctx, target)
        } else {
            self.flush_handle(ctx, target)
        }
    }

    pub(super) fn flush_handle(
        &mut self,
        ctx: &mut Context,
        target: ObjectHandle,
    ) -> Result<()> {
        let handle = self
            .transient_handles
            .iter_mut()
            .find(|handle| **handle == target)
            .expect("transient handle must be tracked in command resources");

        ctx.flush_handle(handle)
    }

    pub(super) fn close_handle(
        &mut self,
        ctx: &mut Context,
        target: ObjectHandle,
    ) -> Result<()> {
        let handle = self
            .persistent_handles
            .iter_mut()
            .find(|handle| **handle == target)
            .expect("persistent handle must be tracked in command resources");

        ctx.close_handle(handle)
    }

    pub(super) fn flush_sessions(&mut self, ctx: &mut Context) -> Result<()> {
        ctx.flush_sessions(&mut self.sessions)
    }

    pub(super) fn flush_policy_session(&mut self, ctx: &mut Context) -> Result<()> {
        ctx.flush_policy_session(&mut self.sessions)
    }

    pub(super) fn flush_handles(&mut self, ctx: &mut Context) -> Result<()> {
        ctx.flush_handles(&mut self.transient_handles)
    }

    pub(super) fn close_handles(&mut self, ctx: &mut Context) -> Result<()> {
        ctx.close_handles(&mut self.persistent_handles)
    }

    pub(super) fn release(&mut self, ctx: &mut Context) -> Result<()> {
        self.close_handles(ctx)?;
        self.flush_handles(ctx)?;
        ctx.flush_sessions(&mut self.sessions)
    }

    pub(super) fn cleanup(&mut self, ctx: &mut Context) {
        let _ = self.close_handles(ctx);
        let _ = self.flush_handles(ctx);
        let _ = ctx.flush_sessions(&mut self.sessions);
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
