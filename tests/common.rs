use std::sync::Once;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use tpm_tool::Context;

static INIT: Once = Once::new();

#[cfg(target_os = "linux")]
pub(crate) fn connect_tpm() -> Context {
    init_tracing();
    Context::connect_from_env().expect("failed to connect to swtpm")
}

#[cfg(target_os = "windows")]
pub(crate) fn connect_tpm() -> Context {
    init_tracing();
    Context::connect().expect("failed to connect to the TPM")
}

fn init_tracing() {
    INIT.call_once(|| {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .init();
    });
}
