use crate::error::Result;

use super::{Command, CommandHeader, Context, TPM_CC_GET_RANDOM, require_len, unmarshal_tpm2b};

const REQUEST_PARAM_SIZE: usize = 2;
const RESPONSE_MIN_SIZE: usize = 2;

impl Context {
    pub(crate) fn get_random_once(&mut self, num_bytes: u16) -> Result<Vec<u8>> {
        let header = CommandHeader::no_sessions(REQUEST_PARAM_SIZE, TPM_CC_GET_RANDOM);
        let command = Command::new(header, num_bytes.to_be_bytes());

        let request_params = self.submit(command)?;
        require_len(&request_params, RESPONSE_MIN_SIZE)?;

        unmarshal_tpm2b(&request_params)
    }
}
