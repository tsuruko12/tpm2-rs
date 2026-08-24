use tracing::debug;

use super::super::{TpmRc, types::{TpmiDhContext, TpmiShAuthSession}};
use super::{Command, CommandResources, Context, SessionSlots, response::ensure_no_response_body};
use crate::{
    Error, Result,
    types::{
        Authorization, LoadedObjectHandle,
        tpm::{TpmCc, TpmaSession, TpmiDhObject, TpmiDhPersistent, TpmiRhProvision, TpmHandle},
    },
};

const RESPONSE_HANDLE_COUNT: usize = 0;

impl Context {
    pub(super) fn evict_control(
        &mut self,
        resources: &mut CommandResources,
        obj_handle: TpmiDhObject,
        persistent_handle: &mut TpmiDhPersistent,
        owner_authorization: &Authorization,
        session_salt_handle: Option<TpmiDhObject>,
        search_end: Option<TpmiDhPersistent>,
    ) -> Result<()> {
        let command_code = TpmCc::EVICT_CONTROL;
        let owner_handle = TpmiRhProvision::OWNER;

        let mut command_params = persistent_handle.value().to_be_bytes();

        let result = (|| {
            let authorization_area = self.prepare_sessions(
                resources,
                TpmaSession::empty(),
                Some(owner_authorization),
                session_salt_handle,
            )?;

            let mut command = Command::new(command_code)
                .with_handles([
                    TpmHandle::from(owner_handle),
                    TpmHandle::from(obj_handle),
                ])
                .with_authorization_area(authorization_area)
                .with_parameters(&mut command_params);

            loop {
                match self.submit(&mut command, RESPONSE_HANDLE_COUNT, resources) {
                    Ok(response_body) => {
                        break ensure_no_response_body(&response_body);
                    }
                    Err(err) => {
                        let handle_value = persistent_handle.value();

                        if err.tpm_rc() == Some(TpmRc::NV_DEFINED) {
                            if let Some(end) = search_end {
                                let next_handle = handle_value + 1;
                                if next_handle > end.value() {
                                    return Err(Error::PersistentHandleInUse(handle_value));
                                }
                                *persistent_handle = TpmiDhPersistent::try_from(next_handle)?;

                                command
                                    .parameters_mut()
                                    .copy_from_slice(&next_handle.to_be_bytes());

                                continue;
                            }
                            return Err(Error::PersistentHandleInUse(handle_value));
                        }
                        return Err(err);
                    }
                }
            }
        })();

        self.cleanup_on_error(result, resources)
    }

    fn flush_sessions(&mut self, sessions: &mut SessionSlots) -> Result<()> {
        let mut first_err = None;

        for session in sessions {
            let Some(handle) = *session else {
                continue;
            };

            if handle != TpmiShAuthSession::RS_PW {
                if let Err(e) = self.flush_context(handle.into()) {
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
            LoadedObjectHandle::Persistent(_) => Ok(()),
            LoadedObjectHandle::Transient(handle) => self.flush_handle(&mut handle.into()),
        }
    }

    pub(super) fn flush_handle(&mut self, handle: &mut TpmiDhObject) -> Result<()> {
        if *handle == TpmiDhObject::RH_NULL {
            return Ok(());
        }

        let context_handle = TpmiDhContext::try_from(*handle)?;

        self.flush_context(context_handle)
            .inspect_err(|_| debug!("failed to flush TPM handle"))?;

        *handle = TpmiDhObject::RH_NULL;

        Ok(())
    }

    fn flush_handles(&mut self, handles: &mut Vec<TpmiDhObject>) -> Result<()> {
        let mut first_err = None;

        for handle in handles.iter_mut() {
            if let Err(e) = self.flush_handle(handle) {
                first_err.get_or_insert(e);
            }
        }

        first_err.map_or(Ok(()), Err)
    }

    fn flush_context(&mut self, flush_handle: TpmiDhContext) -> Result<()> {
        let mut command =
            Command::new(TpmCc::FLUSH_CONTEXT).with_handles([flush_handle]);

        self.submit(
            &mut command,
            RESPONSE_HANDLE_COUNT,
            &mut CommandResources::default(),
        )
        .and_then(|response_body| ensure_no_response_body(&response_body))
    }
}

impl CommandResources {
    pub(super) fn release_handle(
        &mut self,
        ctx: &mut Context,
        target: LoadedObjectHandle,
    ) -> Result<()> {
        match target {
            LoadedObjectHandle::Persistent(_) => Ok(()),
            LoadedObjectHandle::Transient(handle) => self.flush_handle(ctx, handle),
        }
    }

    pub(super) fn flush_handle(&mut self, ctx: &mut Context, target: TpmiDhObject) -> Result<()> {
        let Some(handle) = self
            .transient_handles
            .iter_mut()
            .find(|handle| **handle == target)
        else {
            return Ok(());
        };

        ctx.flush_handle(handle)
    }

    pub(super) fn flush_sessions(&mut self, ctx: &mut Context) -> Result<()> {
        let result = ctx.flush_sessions(&mut self.session_handles);

        for (handle, state) in self
            .session_handles
            .iter()
            .zip(self.session_states.iter_mut())
        {
            if handle.is_none() {
                *state = None;
            }
        }

        result
    }

    pub(super) fn flush_all_handles(&mut self, ctx: &mut Context) -> Result<()> {
        ctx.flush_handles(&mut self.transient_handles)
    }

    pub(super) fn release(&mut self, ctx: &mut Context) -> Result<()> {
        self.flush_all_handles(ctx)?;
        self.flush_sessions(ctx)
    }

    pub(super) fn cleanup(&mut self, ctx: &mut Context) {
        let _ = self.flush_all_handles(ctx);
        let _ = self.flush_sessions(ctx);
    }
}
