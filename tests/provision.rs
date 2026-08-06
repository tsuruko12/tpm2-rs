mod common;

use common::connect_tpm;

#[test]
fn provision() {
    let mut ctx = connect_tpm();
    ctx.provision().expect("failed to provision");
}