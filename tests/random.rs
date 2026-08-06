mod common;

use common::connect_tpm;

#[test]
fn get_random_returns_empty_for_zero_length() {
    let mut ctx = connect_tpm();

    let random = ctx
        .get_random(0)
        .expect("failed to request zero random bytes");

    assert!(random.is_empty());
}

#[test]
fn get_random_returns_requested_length() {
    let mut ctx = connect_tpm();

    for requested in [1, 16, 32, 64] {
        let random = ctx
            .get_random(requested)
            .expect("failed to get random bytes from the TPM");

        assert_eq!(random.len(), requested);
    }
}
