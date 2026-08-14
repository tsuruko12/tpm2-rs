use std::collections::HashMap;

use crate::{
    hierarchy::Hierarchy, policy::PolicyData, types::{KeyData, KeyId, Tpm2bAuth}
};

// TODO: consider pub(super)

#[derive(Default)]
pub(crate) struct Cache {
    temporary_keys: HashMap<String, TemporaryKey>,
    auths: HashMap<AuthorizationTarget, Tpm2bAuth>,
    selected_policy_branches: HashMap<AuthorizationTarget, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum AuthorizationTarget {
    Key(KeyId),
    Hierarchy(Hierarchy),
}

impl Cache {
    pub(crate) fn contains_temporary_key(&self, id: &str) -> bool {
        self.temporary_keys.contains_key(id)
    }

    pub(crate) fn add_temporary_key(&mut self, id: String, key: TemporaryKey) {
        self.temporary_keys.insert(id, key);
    }

    pub(crate) fn temporary_key(&self, id: &str) -> Option<&TemporaryKey> {
        self.temporary_keys.get(id)
    }

    pub(crate) fn has_auth(&self, target: &AuthorizationTarget) -> bool {
        self.auths.contains_key(target)
    }

    pub(crate) fn set_auth(&mut self, target: AuthorizationTarget, auth: Tpm2bAuth) {
        self.auths.insert(target, auth);
    }

    pub(crate) fn auth(&self, target: &AuthorizationTarget) -> Tpm2bAuth {
        self.auths
            .get(target)
            .map(Tpm2bAuth::clone)
            .unwrap_or_default()
    }

    pub(crate) fn set_selected_policy_branch(
        &mut self,
        target: AuthorizationTarget,
        index: usize,
    ) {
        self.selected_policy_branches.insert(target, index);
    }

    pub(crate) fn get_selected_policy_branch(
        &self,
        target: &AuthorizationTarget,
    ) -> Option<usize> {
        self.selected_policy_branches.get(target).copied()
    }
}

pub(crate) struct TemporaryKey {
    pub(crate) data: KeyData,
    pub(crate) policy: Option<PolicyData>,
    pub(crate) parent: Option<KeyId>,
}