use crate::{commands::{Command, CommandHeader, TPM_CC_GET_RANDOM}, error::Result};

use super::Context;

const BYTES_REQUESTED_SIZE: usize = 2;

impl Context {
    pub(crate) fn get_random_once(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        let header = CommandHeader::no_sessions(BYTES_REQUESTED_SIZE, TPM_CC_GET_RANDOM);
        
        let num_bytes = u16::try_from(num_bytes).unwrap(); // gurantered u16
        let command = Command::new(header, num_bytes.to_be_bytes());

        self.submit(command)
    }
}