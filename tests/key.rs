mod common;

use common::connect_tpm;
use std::assert_matches;
use tpm2_rs::{
    Error, Key, Result,
    policy::{PcrSlot, Policy, PolicyBranch, PolicyCommand},
    public::KeyTemplate,
};

use crate::common::TestContext;

mod create {
    use rand::RngCore;

    use super::*;

    #[test]
    fn creates_key_with_auth_exceeding_sha256_digest_size() {
        let mut test = connect_tpm();

        let mut auth = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut auth);

        let _ = create_temporary_key_with_authorization(
            &mut test,
            KeyTemplate::ecc_sign(),
            Some(&auth),
            None,
        );
    }

    #[test]
    fn rejects_duplicate_key_name() {
        let mut test = connect_tpm();
        let key_name = "rsa-decrypt";

        let _ = create_key_with_no_authorization(
            &mut test,
            KeyTemplate::rsa_decrypt(),
            Some(key_name),
            None,
        );

        assert_matches!(
            test.ctx
                .create_key(KeyTemplate::rsa_decrypt(), Some(key_name), None, None, None),
            Err(Error::KeyAlreadyExists(_)),
        );

        delete_stored_keys(&mut test, key_name);
    }

    #[test]
    fn rejects_parent_key() {
        let mut test = connect_tpm();

        let storage_key =
            create_key_with_no_authorization(&mut test, KeyTemplate::aes_gcm_128(), None, None);

        assert_matches!(
            test.ctx.create_key(
                KeyTemplate::aes_gcm_128(),
                None,
                None,
                None,
                Some(&storage_key),
            ),
            Err(Error::InvalidParameter(_)),
        );

        assert_matches!(
            test.ctx.create_key(
                KeyTemplate::storage_root(),
                None,
                None,
                None,
                Some(&storage_key),
            ),
            Err(Error::InvalidParameter(_)),
        );
    }
}

mod persist {
    use super::*;

    #[test]
    fn persists_named_keys() {
        let mut test = connect_tpm();

        let key1 = create_key_with_no_authorization(
            &mut test,
            KeyTemplate::storage_root(),
            Some("srk"),
            None,
        );
        let key2 = create_key_with_no_authorization(
            &mut test,
            KeyTemplate::rsa_sign(),
            Some("rsa-sign"),
            Some(&key1),
        );

        persist_stored_key(&mut test, &key1, 0x8100_8500);
        persist_stored_key(&mut test, &key2, 0x8100_8501);

        delete_stored_keys(&mut test, key1.name().unwrap());

        for key in [&key1, &key2] {
            assert_matches!(
                test.ctx.open_key(key.name().unwrap()),
                Err(Error::KeyNotFound),
            );
        }
    }

    #[test]
    fn rejects_persisting_at_used_handle() {
        let mut test = connect_tpm();
        let persistent_handle = 0x8100_8500;

        let key1 = create_key_with_no_authorization(
            &mut test,
            KeyTemplate::rsa_decrypt(),
            Some("rsa-decrypt"),
            None,
        );
        let key2 = create_key_with_no_authorization(
            &mut test,
            KeyTemplate::ecc_sign(),
            Some("ecc-sign"),
            None,
        );

        persist_stored_key(&mut test, &key1, persistent_handle);

        assert_matches!(
            test.ctx.persist_key(&key2, Some(persistent_handle)),
            Err(Error::PersistentHandleInUse(_)),
        );

        delete_stored_keys(&mut test, "rsa-decrypt");
        delete_stored_keys(&mut test, "ecc-sign");
    }

    #[test]
    fn rejects_persisting_sym_key_and_unstored_key() {
        let mut test = connect_tpm();
        let persistent_handle = 0x8100_8500;

        let rsa_key =
            create_key_with_no_authorization(&mut test, KeyTemplate::rsa_decrypt(), None, None);
        assert_matches!(
            test.ctx.persist_key(&rsa_key, Some(persistent_handle)),
            Err(Error::InvalidKey { .. }),
        );

        let sym_key = create_key_with_no_authorization(
            &mut test,
            KeyTemplate::aes_gcm_128(),
            Some("aes-gcm-128"),
            None,
        );
        assert_matches!(
            test.ctx.persist_key(&sym_key, Some(persistent_handle)),
            Err(Error::InvalidKey { .. }),
        );

        delete_stored_keys(&mut test, "aes-gcm-128");
    }
}

mod sign {
    use der::Decode;
    use rand::RngCore;

    use super::*;
    use tpm2_rs::{
        algorithm::HashAlgorithm,
        public::{RsaKeyBits, RsaTemplate},
        signature::Signature,
    };

    #[test]
    fn signs_with_restricted_key() {
        let mut test = connect_tpm();

        let mut data = [0u8; 1025];
        rand::thread_rng().fill_bytes(&mut data);

        let key = create_key_with_no_authorization(
            &mut test,
            KeyTemplate::attestation_sign(),
            None,
            None,
        );

        if cfg!(target_os = "windows") {
            let signature = test.ctx.sign(&key, &data, None).expect("failed to sign");
            match signature {
                Signature::Ecdsa(ecdsa_sig) => {
                    assert_eq!(ecdsa_sig.hash_alg(), HashAlgorithm::Sha256);
                    Decode::from_der(ecdsa_sig.value()).expect("failed to decode")
                }
                _ => panic!("unexpected signature type"),
            }
        } else if cfg!(target_os = "linux") {
            assert_matches!(
                test.ctx.sign(&key, &data, None),
                Err(Error::InvalidParameter(_)),
            );
        }
    }

    #[test]
    fn signs_with_rsa_key() {
        let mut test = connect_tpm();

        let data = b"test message for RSA signature";
        let key = create_key_with_no_authorization(&mut test, KeyTemplate::rsa_sign(), None, None);

        let signature = test.ctx.sign(&key, data, None).expect("failed to sign");
        match signature {
            Signature::RsaPss(rsa_sig) => {
                assert_eq!(rsa_sig.hash_alg(), HashAlgorithm::Sha256);
            }
            _ => panic!("unexpected signature type"),
        }
    }

    #[test]
    fn rejects_invalid_key() {
        let mut test = connect_tpm();

        let data = b"test message for ECDSA signature";
        let key =
            create_key_with_no_authorization(&mut test, KeyTemplate::aes_gcm_128(), None, None);

        assert_matches!(
            test.ctx.sign(&key, data, None),
            Err(Error::InvalidKey { .. }),
        );
    }

    #[test]
    fn requires_option_scheme() {
        let mut test = connect_tpm();

        let rsa_template = RsaTemplate::sign_decrypt(RsaKeyBits::Bits2048);
        let data = b"test message";

        let key =
            create_key_with_no_authorization(&mut test, KeyTemplate::rsa(rsa_template), None, None);

        assert_matches!(
            test.ctx.sign(&key, data, None),
            Err(Error::InvalidParameter(_)),
        );
    }
}

#[test]
fn raises_error_with_unselected_policy_branch() {
    let mut test = connect_tpm();

    let policy_pcr = PolicyBranch::new(
        "pcr",
        Policy::pcr(&[PcrSlot::Slot7]).expect("failed to build PCR policy"),
    );
    let policy_command = PolicyBranch::new("command", Policy::Command(PolicyCommand::Create));

    let srk = create_temporary_key_with_authorization(
        &mut test,
        KeyTemplate::storage_root(),
        None,
        Some(Policy::Or(vec![policy_pcr, policy_command])),
    )
    .expect("failed to create temporary key");

    assert_matches!(
        test.ctx
            .create_key(KeyTemplate::ecc_sign(), None, None, None, Some(&srk),),
        Err(Error::InvalidPolicy(_)),
    );
}

fn create_key_with_no_authorization(
    test: &mut TestContext,
    template: KeyTemplate,
    key_name: Option<&str>,
    parent: Option<&Key>,
) -> Key {
    test.ctx
        .create_key(template, key_name, None, None, parent)
        .expect("failed to create key")
}

fn create_temporary_key_with_authorization(
    test: &mut TestContext,
    template: KeyTemplate,
    auth: Option<&[u8]>,
    policy: Option<Policy>,
) -> Result<Key> {
    test.ctx.create_key(template, None, auth, policy, None)
}

fn persist_stored_key(test: &mut TestContext, key: &Key, persistent_handle: u32) {
    test.ctx
        .persist_key(&key, Some(persistent_handle))
        .expect("failed to persist stored key")
}

fn delete_stored_keys(test: &mut TestContext, key_name: &str) {
    test.ctx
        .delete_key(key_name)
        .expect("failed to persist stored key: {key_name}");
}
