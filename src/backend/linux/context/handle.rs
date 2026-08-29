use tracing::debug;
use tss_esapi::{
    constants::Tss2ResponseCodeKind,
    handles::{ObjectHandle, PersistentTpmHandle, SessionHandle},
    interface_types::{resource_handles::Provision, session_handles::AuthSession},
};

use crate::{Error, Result, types::{Authorization, LoadedObjectHandle, tpm::{TpmaSession, TpmiDhPersistent}}};
use super::{Context, CommandResources, SessionSlotArray};

impl Context {
    pub(crate) fn persist_handle(
        &mut self,
        transient_handle: ObjectHandle,
        persistent_handle: TpmiDhPersistent,
        owner_authorization: &Authorization,
        session_salt_handle: ObjectHandle,
        search_end: Option<TpmiDhPersistent>,
    ) -> Result<(LoadedObjectHandle, TpmiDhPersistent)> {
        let mut resources = CommandResources::default();
        resources.add_transient_handle(transient_handle);
        resources.add_persistent_handle(session_salt_handle);

        let result = (|| {
            let (obj_handle, persistent_handle) = self.evict_control(
                transient_handle, 
                persistent_handle, 
                owner_authorization, 
                Some(session_salt_handle), 
                search_end,
            )?;
            let _ = resources.flush_handle(self, transient_handle);

            Ok((LoadedObjectHandle::Persistent(obj_handle), persistent_handle))
        })();

        match result {
            Ok(value) => {
                let _ = resources.flush_sessions(self);
                Ok(value)
            }
            Err(e) => {
                resources.cleanup(self);
                Err(e)
            }
        }
    }

    pub(crate) fn evict_control(
        &mut self,
        object_handle: ObjectHandle,
        mut persistent_handle: TpmiDhPersistent,
        owner_authorization: &Authorization,
        session_salt_handle: Option<ObjectHandle>,
        search_end: Option<TpmiDhPersistent>,
    ) -> Result<(ObjectHandle, TpmiDhPersistent)> {
        let mut resources = CommandResources::default();

        let result = (|| {
            self.prepare_sessions(
                &mut resources,
                TpmaSession::empty(),
                Some((ObjectHandle::Owner, owner_authorization)),
                session_salt_handle.map(Into::into),
            )?;

            loop {
                let handle_value = persistent_handle.value();
                let persistent_tpm_handle = PersistentTpmHandle::new(handle_value)
                    .expect("handle must be in the persistent range");

                match self.ctx.execute_with_sessions(resources.session_slots(), |ctx| {
                    ctx.evict_control(
                        Provision::Owner, 
                        object_handle, 
                        persistent_tpm_handle.into(),
                    )
                }) {
                    Ok(obj_handle) => break Ok((obj_handle, persistent_handle)),
                    Err(e) => {
                        if is_nv_defined_err(e) {
                            if let Some(end) = search_end {
                                let next_handle = handle_value + 1;
                                if next_handle > end.value() {
                                    break Err(Error::PersistentHandleInUse(handle_value));
                                }

                                persistent_handle = TpmiDhPersistent::try_from(next_handle)
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

        match result {
            Ok(value) => {
                let _ = resources.flush_sessions(self);
                Ok(value)
            }
            Err(e) => {
                resources.cleanup(self);
                Err(e)
            }
        }
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

        *handle = ObjectHandle::Null;

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

    pub(super) fn flush_all_handles(&mut self, ctx: &mut Context) -> Result<()> {
        ctx.flush_handles(&mut self.transient_handles)
    }

    pub(super) fn close_all_handles(&mut self, ctx: &mut Context) -> Result<()> {
        ctx.close_handles(&mut self.persistent_handles)
    }

    pub(super) fn release(&mut self, ctx: &mut Context) -> Result<()> {
        let mut first_err = None;

        if let Err(e) = self.close_all_handles(ctx) {
            first_err = Some(e);
        }

        if let Err(e) = self.flush_all_handles(ctx) {
            first_err.get_or_insert(e);
        }

        if let Err(e) = ctx.flush_sessions(&mut self.sessions) {
            first_err.get_or_insert(e);
        }

        first_err.map_or(Ok(()), Err)
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
