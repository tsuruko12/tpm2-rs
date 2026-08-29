mod common;

use common::connect_tpm;
use tpm_tool::{Error, policy::{PcrSlot, Policy, PolicyBranch}, public::KeyTemplate};

#[test]
fn creates_temporary_keys() {
    let mut test = connect_tpm();

    test.ctx.create_key(KeyTemplate::rsa_sign(), None, None, None, None)
        .expect("failed to create a temporary RSA key");

    test.ctx.create_key(KeyTemplate::aes_gcm_128(), None, None, None, None)
        .expect("failed to create a temporary symmetric key");
}

#[test]
fn creates_named_keys() {
    let mut test = connect_tpm();
    let name = "srk";

    let _ = test.ctx
        .create_key(
            KeyTemplate::storage_root_key(),
            Some("srk"),
            None,
            None,
            None,
        )
        .expect("failed to create a named key");

    let duplicate = test.ctx.create_key(
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
    let mut test = connect_tpm();

    let policy_pcr = Policy::pcr(&[PcrSlot::Slot7, PcrSlot::Slot0]).expect("invalid PCR slots");
    let policy = Policy::or(vec![
        PolicyBranch::new("auth", Policy::auth_value()),
        PolicyBranch::new("pcr", policy_pcr),
    ]);

    test.ctx.create_key(
        KeyTemplate::rsa_sign(),
        Some("rsa-sign"),
        Some(b"AuthValue"),
        Some(policy),
        None,
    )
    .expect("failed to create a named key");
}

fn persists_stored_key_at_specified_handle() {
    let mut test = connect_tpm();

    let key = test.ctx.open("rsa-sign").expect("failed to open key");
    test.ctx.set_policy_branch(&key, "pcr");

    test.ctx.persist(&key, Some(0x8100_8100))
        .expect("failed to persist a stored key");
}
