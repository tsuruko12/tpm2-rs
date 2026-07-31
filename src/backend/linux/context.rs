mod capability;
mod handle;
mod key;
mod provision;
mod random;
mod session;
mod tcti;

use tracing::debug;
use tss_esapi::{
    Context as EsapiContext, interface_types::session_handles::AuthSession, structures::Auth,
};

use crate::{Error, Result};

#[derive(Debug)]
pub(crate) struct Context {
    ctx: EsapiContext,
    sessions: [Option<AuthSession>; 3],
}

impl Drop for Context {
    fn drop(&mut self) {
        if let Err(e) = self.flush_sessions() {
            debug!(err = ?e, "failed to flush TPM sessions");
        }
    }
}

fn auth_from_bytes(bytes: &[u8]) -> Result<Auth> {
    bytes
        .try_into()
        .map_err(|_| Error::invalid_state("auth value exceeds the nameAlg digest size"))
}
