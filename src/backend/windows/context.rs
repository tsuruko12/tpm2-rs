mod capability;
mod handle;
mod key;
mod provision;
mod random;
mod session;
mod tbs;

use std::{ffi::c_void, ptr};

use tracing::debug;

use super::types::TpmiShAuthSession;

type SessionSlots = [Option<TpmiShAuthSession>; 3];
type ContextHandle = *mut c_void;

#[derive(Debug)]
pub(crate) struct Context {
    handle: ContextHandle,
    sessions: SessionSlots,
}

impl Drop for Context {
    fn drop(&mut self) {
        if let Err(e) = self.flush_sessions() {
            debug!(err = ?e, "failed to flush TPM sessions");
        }

        if let Err(e) = self.close() {
            debug!(err = ?e, "failed to close TBS context handle");
        }

        self.handle = ptr::null_mut();
    }
}
