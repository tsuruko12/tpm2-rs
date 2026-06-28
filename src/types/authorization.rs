use std::collections::{HashMap, hash_map::Entry};

use zeroize::Zeroizing;

use crate::{
    data::generate_id,
    error::Result,
    types::{Hierarchy, policy::Policy},
};

#[derive(Default)]
struct KeyAuthorization {
    parent_auth: Option<Zeroizing<Vec<u8>>>,
    selected_policy_branch: Option<usize>,
}

pub(crate) struct AuthorizationCache {
    key_authorizations: HashMap<String, KeyAuthorization>,
    hierarchy_policy_branches: HashMap<Hierarchy, Option<usize>>,
}

impl Default for AuthorizationCache {
    fn default() -> Self {
        let hierarchy_policy_branches = [
            (Hierarchy::Storage, None),
            (Hierarchy::Platform, None),
            (Hierarchy::Endorsement, None),
        ]
        .into_iter()
        .collect();

        Self {
            key_authorizations: Default::default(),
            hierarchy_policy_branches,
        }
    }
}

impl AuthorizationCache {
    pub(crate) fn register(&mut self) -> Result<String> {
        loop {
            let id = generate_id()?;

            match self.key_authorizations.entry(id.clone()) {
                Entry::Occupied(_) => continue,
                Entry::Vacant(entry) => {
                    entry.insert(KeyAuthorization::default());
                    return Ok(id);
                }
            }
        }
    }

    pub(crate) fn unregister(&mut self, id: &str) {
        self.key_authorizations.remove(id);
    }

    pub(crate) fn set_parent_auth(&mut self, id: &str, auth: impl Into<Zeroizing<Vec<u8>>>) {
        self.key_authorizations
            .entry(id.to_string())
            .or_default()
            .parent_auth = Some(auth.into());
    }

    pub(crate) fn set_policy_branch(&mut self, id: &str, index: usize) {
        self.key_authorizations
            .entry(id.to_string())
            .or_default()
            .selected_policy_branch = Some(index);
    }

    pub(crate) fn get_policy_branch(&self, id: &str) -> Option<usize> {
        self.key_authorizations
            .get(id)
            .and_then(|entry| entry.selected_policy_branch)
    }

    pub(crate) fn set_hierarchy_policy_branch(&mut self, hierarchy: Hierarchy, index: usize) {
        *self
            .hierarchy_policy_branches
            .get_mut(&hierarchy)
            .expect("hierarchy authorization should be registered") = Some(index);
    }

    pub(crate) fn get_hierarchy_policy_branch(&self, hierarchy: Hierarchy) -> Option<usize> {
        self.hierarchy_policy_branches
            .get(&hierarchy)
            .copied()
            .flatten()
    }

    pub(crate) fn has_parent_auth(&self, id: &str) -> bool {
        self.key_authorizations
            .get(id)
            .is_some_and(|entry| entry.parent_auth.is_some())
    }
}

#[derive(Default)]
pub(crate) struct Authorization {
    auth: Option<Zeroizing<Vec<u8>>>,
    policy: Option<Policy>,
}

impl Authorization {
    pub(crate) fn new(auth: Option<&[u8]>, policy: Option<Policy>) -> Self {
        let auth = auth.map(|v| Zeroizing::new(v.to_vec()));
        Self { auth, policy }
    }

    pub(crate) fn auth_bytes(&self) -> Option<&[u8]> {
        self.auth.as_ref().map(|v| v.as_slice())
    }

    pub(crate) fn policy(&self) -> Option<&Policy> {
        self.policy.as_ref()
    }

    pub(crate) fn set_auth(&mut self, auth: impl Into<Zeroizing<Vec<u8>>>) {
        self.auth = Some(auth.into());
    }
}

