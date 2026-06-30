use crate::error::Result;

use super::{Command, Context, CommandHeader, Digest, TPM_CC_GET_RANDOM};

const BYTES_REQUESTED_SIZE: usize = 2;

impl Context {
    pub(crate) fn get_random_once(&mut self, num_bytes: u16) -> Result<Digest> {
        let header = CommandHeader::no_sessions(BYTES_REQUESTED_SIZE, TPM_CC_GET_RANDOM);
        let command = Command::new(header, num_bytes.to_be_bytes());

        let params = self.submit(command)?;

        Digest::new(&params)
    }
}
