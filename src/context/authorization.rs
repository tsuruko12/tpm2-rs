use crate::types::{Key, tpm::Tpm2bAuth};

use super::Context;

impl Context {
    /// Set an authorization value for the specified key.
    /// 
    /// If the value is already set, it is replaced.
    pub fn set_auth_value(&mut self, key: &Key, auth_value: &[u8]) {
        self.cache.set_key_auth(
            key.id().clone(), 
            Tpm2bAuth::normalize_sha256(auth_value),
        );
    }

    /// Set a PolicyOR branch label for the specified key.
    /// 
    /// This method may be called multiple times to select branches for multiple PolicyORs.
    pub fn set_policy_branch(&mut self, key: &Key, branch_label: &str) {
        self
            .cache
            .set_key_policy_branche(key.id().clone(), branch_label);
    }
}
