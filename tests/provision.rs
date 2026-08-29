mod common;

use common::connect_tpm;

#[test]
#[ignore]
fn provision() {
    let mut test = connect_tpm();
    test.ctx.provision().expect("failed to provision");
}