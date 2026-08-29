use std::sync::{Mutex, MutexGuard, Once};

use tpm_tool::Context;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

static INIT: Once = Once::new();
static TPM_TEST_LOCK: Mutex<()> = Mutex::new(());

pub(crate) struct TestContext {
    _guard: MutexGuard<'static, ()>,
    pub(crate) ctx: Context,
}

#[cfg(target_os = "linux")]
pub(crate) fn connect_tpm() -> TestContext {
    init_tracing();

    let guard = TPM_TEST_LOCK
        .lock()
        .expect("TPM test lock is poisoned");

    let ctx = Context::connect_from_env()
        .expect("failed to connect to swtpm");

    TestContext {
        _guard: guard,
        ctx,
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn connect_tpm() -> Context {
    init_tracing();

    let guard = TPM_TEST_LOCK
        .lock()
        .expect("TPM test lock is poisoned");

    let ctx = Context::connect().expect("failed to connect to the TPM");

    TestContext {
        _guard: guard,
        ctx,
    }
}

fn init_tracing() {
    INIT.call_once(|| {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .init();
    });
}
