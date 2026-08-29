mod common;

use std::sync::Mutex;

use common::connect_tpm;
use tpm_tool::{Error, policy::{PcrSlot, Policy, PolicyBranch}, public::KeyTemplate};

static TPM_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn creates_temporary_keys() {
    let _guard = TPM_TEST_LOCK.lock().expect("TPM test lock is poisoned");
    let mut ctx = connect_tpm();

    ctx.create_key(KeyTemplate::rsa_sign(), None, None, None, None)
        .expect("failed to create a temporary RSA key");

    ctx.create_key(KeyTemplate::aes_gcm_128(), None, None, None, None)
        .expect("failed to create a temporary symmetric key");
}

#[test]
fn creates_named_keys() {
    let _guard = TPM_TEST_LOCK.lock().expect("TPM test lock is poisoned");
    let mut ctx = connect_tpm();
    let name = "srk";

    let _ = ctx
        .create_key(
            KeyTemplate::storage_root_key(),
            Some("srk"),
            None,
            None,
            None,
        )
        .expect("failed to create a named key");

    let duplicate = ctx.create_key(
        KeyTemplate::storage_root_key(),
        Some(&name),
        None,
        None,
        None,
    );
    assert!(matches!(duplicate, Err(Error::KeyAlreadyExists(_))));
}

#[test]
fn creates_key_with_authorization() {
    let _guard = TPM_TEST_LOCK.lock().expect("TPM test lock is poisoned");
    let mut ctx = connect_tpm();

    let policy_pcr = Policy::pcr(&[PcrSlot::Slot7, PcrSlot::Slot0]).expect("invalid PCR slots");
    let policy = Policy::or(vec![
        PolicyBranch::new("auth", Policy::auth_value()),
        PolicyBranch::new("pcr", policy_pcr),
    ]);

    ctx.create_key(
        KeyTemplate::rsa_sign(),
        Some("rsa-sign"),
        Some(b"AuthValue"),
        Some(policy),
        None,
    )
    .expect("failed to create a named key");
}

#[test]
fn rejects_persisting_temporary_key() {
    let _guard = TPM_TEST_LOCK.lock().expect("TPM test lock is poisoned");
    let mut ctx = connect_tpm();

    let key = ctx
        .create_key(KeyTemplate::rsa_sign(), None, None, None, None)
        .expect("failed to create a temporary RSA key");

    assert!(matches!(
        ctx.persist(&key, None),
        Err(Error::InvalidKey { .. })
    ));
}

#[test]
fn persists_stored_key() {
    let _guard = TPM_TEST_LOCK.lock().expect("TPM test lock is poisoned");
    let mut ctx = connect_tpm();
    let key_name = format!("persistent-rsa-sign-{}", std::process::id());

    let key = ctx
        .create_key(
            KeyTemplate::rsa_sign(),
            Some(&key_name),
            None,
            None,
            None,
        )
        .expect("failed to create a stored RSA key");

    ctx.persist(&key, None)
        .expect("failed to persist the RSA key");

    assert!(matches!(
        ctx.persist(&key, None),
        Err(Error::InvalidKey { .. })
    ));
}
