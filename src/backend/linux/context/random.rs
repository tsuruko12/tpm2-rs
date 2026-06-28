use crate::error::{Error, Result};

use super::Context;

impl Context {
    pub(crate) fn get_random_once(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        self
            .ctx
            .get_random(num_bytes)
            .map(|digest| digest.value().to_vec())
            .map_err(Error::from_tss_err)
    }
}