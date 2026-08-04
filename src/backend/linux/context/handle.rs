use tracing::debug;
use tss_esapi::{
    constants::Tss2ResponseCodeKind,
    handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, SessionHandle},
    interface_types::{resource_handles::Provision, session_handles::AuthSession},
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
                TpmaSession::empty(),
                session_salt_key,
            )?;

            loop {
                match self.ctx.execute_with_sessions(resources.session_slots(), |ctx| {
                    ctx.evict_control(Provision::Owner, obj_handle, (*persistent_handle).into())
                }) {
                    Ok(handle) => {
                        resources.clear_sessions();
                        break Ok(handle)
                    },
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

    pub(super) fn release_resources(&mut self, resources: &mut CommandResources) -> Result<()> {
        if !resources.persistent_handles.is_empty() {
            self.close_handles(&mut resources.persistent_handles)?;
        }

        if !resources.transient_handles.is_empty() {
            self.flush_handles(&mut resources.transient_handles)?;
        }
        
        self.flush_sessions(&mut resources.sessions)?;

        Ok(())   
    }

    pub(super) fn cleanup_resources(&mut self, resources: &mut CommandResources) {
        if !resources.persistent_handles.is_empty() {
            let _ = self.close_handles(&mut resources.persistent_handles);
        }

        if !resources.transient_handles.is_empty() {
            let _ = self.flush_handles(&mut resources.transient_handles);
        }

        let _ = self.flush_sessions(&mut resources.sessions);
    }

    pub(super) fn flush_sessions(&mut self, sessions: &mut SessionSlotArray) -> Result<()> {
        let mut first_err = None;

        for session in sessions {
            let Some(handle) = *session else {
                continue;
            };

            if handle != AuthSession::Password {
                if let Err(e) = self.flush_context(SessionHandle::from(handle)) {
                    first_err.get_or_insert(e);
                    debug!(?handle, "failed to flush TPM session");

                    continue;
                }       
            }

            *session = None;
        }

        first_err.map_or(Ok(()), Err)
    }

    pub(super) fn flush_handles(&mut self, handles: &mut Vec<ObjectHandle>) -> Result<()> {
        let mut first_err = None;
        let mut remaining = Vec::new();

        while let Some(handle) = handles.pop() {
            if let Err(e) = self.flush_context(handle) {
                first_err.get_or_insert(e);
                remaining.push(handle);

                debug!("failed to flush TPM handle");
            }
        }

        *handles = remaining;

        first_err.map_or(Ok(()), Err)
    }

    pub(super) fn close_handles(&mut self, handles: &mut Vec<ObjectHandle>) -> Result<()> {
        let mut first_err = None;
        let mut remaining = Vec::new();

        while let Some(mut handle) = handles.pop() {
            if let Err(e) = self.close_handle(&mut handle) {
                first_err.get_or_insert(e);
                remaining.push(handle);

                debug!("failed to close ESAPI handle");
            }
        }

        *handles = remaining;

        first_err.map_or(Ok(()), Err)
    }

    pub(super) fn close_handle(&mut self, handle: &mut ObjectHandle) -> Result<()> {
        if let Err(e) = self.ctx.tr_close(handle) {
            debug!("failed to close ESAPI handle");
            return Err(Error::from_tss_err(e));
        } 

        Ok(())
    }

    fn flush_context(&mut self, flush_handle: impl Into<ObjectHandle>) -> Result<()> {
        self.ctx.flush_context(flush_handle.into()).map_err(Error::from_tss_err)
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
