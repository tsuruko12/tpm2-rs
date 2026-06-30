mod log;

use log::init_tracing;
use tpm_tool::Context;

#[cfg(target_os = "linux")]
fn connect() -> Context {
    init_tracing();
    Context::connect_from_env().expect("failed to connect to swtpm")
}

#[cfg(target_os = "windows")]
fn connect() -> Context {
    init_tracing();
    Context::connect().expect("failed to connect to the TPM")
}

#[test]
fn get_random_returns_empty_for_zero_length() {
    let mut context = connect();

    let random = context
        .get_random(0)
        .expect("failed to request zero random bytes");

    assert!(random.is_empty());
}

#[test]
fn get_random_returns_requested_length() {
    let mut context = connect();

    for requested in [1, 16, 32, 64] {
        let random = context
            .get_random(requested)
            .expect("failed to get random bytes from the TPM");

        assert_eq!(random.len(), requested);
    }
}
