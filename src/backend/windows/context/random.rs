use crate::{error::Result, types::TpmCc};

use super::Context;
use super::super::{codec::read_tpm2b_exact, commands::Command};

impl Context {
    pub(crate) fn get_random(&mut self, num_bytes: u16) -> Result<Vec<u8>> {
        let request_param = num_bytes.to_be_bytes();
        let command = Command::new(TpmCc::GET_RANDOM)
            .with_parameters(&request_param);

        let response_body = self.submit(command)?;
        
        read_tpm2b_exact(&response_body)
    }
}
