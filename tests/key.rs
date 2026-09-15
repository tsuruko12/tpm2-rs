mod common;

use common::connect_tpm;
use tpm2_rs::{Error, Key, Result, policy::{PcrSlot, Policy, PolicyBranch}, public::KeyTemplate};

use crate::common::TestContext;

#[test]
fn creates_temporary_keys() {
    let mut test = connect_tpm();

    test.ctx.create_key(KeyTemplate::rsa_sign(), None, None, None, None)
        .expect("failed to create a temporary RSA key");

    test.ctx.create_key(KeyTemplate::aes_gcm_128(), None, None, None, None)
        .expect("failed to create a temporary symmetric key");
}

#[test] 
fn creates_and_persists_keys() {
    let mut test = connect_tpm();

    let (key1, key2) = create_named_keys(&mut test).expect("failed to create named keys");

    let key3 = create_key_with_authorization(&mut test)
        .expect("failed to create a key with authorization");
    test.ctx.set_auth_value(&key3, b"AuthValue");
    test.ctx.set_policy_branch(&key3, "auth");

    let created_keys = [&key1, &key2, &key3];
    let persistent_handles = [0x8100_8500, 0x8100_8501, 0x8100_8502];
    for (key, handle) in created_keys.iter().zip(persistent_handles) {
        persist_stored_key(&mut test, key, handle);
    }

    delete_stored_keys(&mut test, key1.name().unwrap());
    delete_stored_keys(&mut test, key3.name().unwrap());

    for key in created_keys {
        assert!(matches!(
            test.ctx.open_key(key.name().unwrap()),
            Err(Error::KeyNotFound)
        ));        
    }
}

fn create_named_keys(test: &mut TestContext) -> Result<(Key, Key)> {
    let name = "srk";

    let srk = test.ctx
        .create_key(
            KeyTemplate::storage_root_key(),
            Some("srk"),
            None,
            None,
            None,
        )?;

    let duplicate = test.ctx.create_key(
        KeyTemplate::storage_root_key(),
        Some(&name),
        None,
        None,
        None,
    );
    assert!(matches!(duplicate, Err(Error::KeyAlreadyExists(_))));

    let ecc_sign_key = test.ctx
        .create_key(
            KeyTemplate::ecc_sign(),
            Some("ecc-sign"),
            None,
            None,
            Some(&srk),
        )?;

    Ok((srk, ecc_sign_key))
}

fn create_key_with_authorization(test: &mut TestContext) -> Result<Key> {
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
}

fn persist_stored_key(test: &mut TestContext, key: &Key, persistent_handle: u32) {
    test
        .ctx
        .persist(&key, Some(persistent_handle))
        .expect("failed to persist a stored key")
}

fn delete_stored_keys(test: &mut TestContext, key_name: &str) {
    test.ctx.delete_key(key_name).expect("failed to persist a stored key: {key_name}");
}