use tracing::debug;
use tss_esapi::{
    constants::Tss2ResponseCodeKind,
    handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, SessionHandle},
    interface_types::{resource_handles::Provision, session_handles::{AuthSession, PolicySession}},
};

use crate::{Error, Result, types::{Authorization, LoadedObjectHandle, tpm::TpmaSession}};
use super::{Context, CommandResources, SessionSlotArray};

impl Context {
    pub(super) fn evict_control(
        &mut self,
        resources: &mut CommandResources,
        obj_handle: ObjectHandle,
        persistent_handle: &mut PersistentTpmHandle,
        owner_authorization: &Authorization,
        session_salt_handle: Option<KeyHandle>,
        search_end: Option<PersistentTpmHandle>,
    ) -> Result<ObjectHandle> {
        let result = (|| {
            self.prepare_sessions(
                resources,
                TpmaSession::empty().with_continue_session(),
                Some((ObjectHandle::Owner, owner_authorization)),
                session_salt_handle,
            )?;

            loop {
                match self.ctx.execute_with_sessions(resources.session_slots(), |ctx| {
                    ctx.evict_control(Provision::Owner, obj_handle, (*persistent_handle).into())
                }) {
                    Ok(handle) => break Ok(handle),
                    Err(e) => {
                        if is_nv_defined_err(e) {
                            let handle_value = u32::from(*persistent_handle);

                            if let Some(end) = search_end {
                                let next_handle = handle_value + 1;

                                if next_handle > end.into() {
                                    break Err(Error::PersistentHandleInUse(handle_value));
                                }

                                *persistent_handle = PersistentTpmHandle::new(next_handle)
                                    .expect("handle must be in the persistent range");

                                continue;
                            }
                            break Err(Error::PersistentHandleInUse(handle_value));
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

    pub(crate) fn release_handle(&mut self, obj_handle: LoadedObjectHandle) -> Result<()> {
        match obj_handle {
            LoadedObjectHandle::Persistent(handle) => self.close_handle(&mut handle.into()),
            LoadedObjectHandle::Transient(handle) => self.flush_handle(&mut handle.into()),
        }
    }

    fn flush_handle(&mut self, handle: &mut ObjectHandle) -> Result<()> {
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
            }
        }

        first_err.map_or(Ok(()), Err)
    }

    fn close_handle(&mut self, handle: &mut ObjectHandle) -> Result<()> {
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
    pub(super) fn release_all_handles(&mut self, ctx: &mut Context) -> Result<()> {
        self.close_all_handles(ctx)?;
        self.flush_all_handles(ctx)?;

        Ok(())
    }

    pub(super) fn release_handle(
        &mut self, 
        ctx: &mut Context, 
        target: LoadedObjectHandle, 
    ) -> Result<()> {
        match target {
            LoadedObjectHandle::Persistent(handle) => self.close_handle(ctx, handle.into()),
            LoadedObjectHandle::Transient(handle) => self.flush_handle(ctx, handle.into()),
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

    pub(super) fn flush_all_handles(&mut self, ctx: &mut Context) -> Result<()> {
        ctx.flush_handles(&mut self.transient_handles)
    }

    pub(super) fn close_all_handles(&mut self, ctx: &mut Context) -> Result<()> {
        ctx.close_handles(&mut self.persistent_handles)
    }

    pub(super) fn release(&mut self, ctx: &mut Context) -> Result<()> {
        self.close_all_handles(ctx)?;
        self.flush_all_handles(ctx)?;
        ctx.flush_sessions(&mut self.sessions)
    }

    pub(super) fn cleanup(&mut self, ctx: &mut Context) {
        let _ = self.close_all_handles(ctx);
        let _ = self.flush_all_handles(ctx);
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
