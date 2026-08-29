use crate::{types::Authorization, Result};

use super::Context;

impl Context {
    /// Provisions the key store and the internal TPM keys it requires.
    ///
    /// Fails if the store has already been initialized.
    pub fn provision(&mut self) -> Result<()> {
        self.store.ensure_uninitialized()?;

        let owner_authorization = Authorization::default();
        let key_meta = self.backend.create_internal_keys(&owner_authorization)?;

        self.store.init(&key_meta).inspect_err(|_| {
            self.backend
                .evict_persistent_handles(&owner_authorization, &key_meta, None)
        })
    }
}
