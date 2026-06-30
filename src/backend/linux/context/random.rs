use tss_esapi::structures::Digest;

use crate::error::{Error, Result};

use super::Context;

impl Context {
    pub(crate) fn get_random_once(&mut self, num_bytes: u16) -> Result<Digest> {
        self
            .ctx
            .get_random(num_bytes as usize)
            .map_err(Error::from_tss_err)
    }
}