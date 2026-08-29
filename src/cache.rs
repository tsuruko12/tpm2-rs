use std::collections::{HashMap, HashSet};

use crate::{
    hierarchy::Hierarchy, policy::PolicyData, types::{KeyData, KeyId, tpm::Tpm2bAuth}
};

// TODO: consider pub(super)

#[derive(Default)]
pub(crate) struct Cache {
    temporary_keys: HashMap<String, TemporaryKey>,
    auths: HashMap<AuthorizationTarget, Tpm2bAuth>,
    selected_policy_branches: HashMap<AuthorizationTarget, HashSet<String>>,
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

    pub(crate) fn set_key_auth(&mut self, target: KeyId, auth: Tpm2bAuth) {
        self.auths.insert(AuthorizationTarget::Key(target), auth);
    }

    pub(crate) fn set_hierarchy_auth(&mut self, target: Hierarchy, auth: Tpm2bAuth) {
        self.auths.insert(AuthorizationTarget::Hierarchy(target), auth);
    }

    pub(crate) fn auth(&self, target: &AuthorizationTarget) -> Tpm2bAuth {
        self.auths
            .get(target)
            .map(Tpm2bAuth::clone)
            .unwrap_or_default()
    }

    pub(crate) fn set_key_policy_branche(
        &mut self,
        target: KeyId,
        label: &str,
    ) {
        self
            .selected_policy_branches
            .entry(AuthorizationTarget::Key(target))
            .or_default()
            .insert(label.to_string());
    }

    pub(crate) fn set_hierarchy_policy_branche(
        &mut self,
        target: Hierarchy,
        label: &str,
    ) {
        self
            .selected_policy_branches
            .entry(AuthorizationTarget::Hierarchy(target))
            .or_default()
            .insert(label.to_string());
    }

    pub(crate) fn key_policy_branches(
        &self,
        target: KeyId,
    ) -> Option<&HashSet<String>> {
        self
            .selected_policy_branches
            .get(&AuthorizationTarget::Key(target))
    }

    pub(crate) fn hierarchy_policy_branches(
        &self,
        target: Hierarchy,
    ) -> Option<&HashSet<String>> {
        self
            .selected_policy_branches
            .get(&AuthorizationTarget::Hierarchy(target))
    }
}

pub(crate) struct TemporaryKey {
    pub(crate) data: KeyData,
    pub(crate) policy: Option<PolicyData>,
    pub(crate) parent: Option<KeyId>,
}
