use std::collections::HashMap;

use crate::{
    hierarchy::Hierarchy, 
    policy::PolicyData, 
    types::Tpm2bAuth,
};

pub(crate) struct AuthorizationCache {
    key_authorizations: HashMap<String, KeyAuthorization>,
    hierarchy_authorizations: HashMap<Hierarchy, HierarchyAuthorization>,
}

#[derive(Default)]
struct KeyAuthorization {
    parent_auth: Tpm2bAuth,
}

#[derive(Default)]
struct HierarchyAuthorization {
    auth: Tpm2bAuth,
    policy_branch: Option<usize>,  
}

impl Default for AuthorizationCache {
    fn default() -> Self {
        let hierarchy_authorizations = [
            Hierarchy::Storage,
            Hierarchy::Platform,
            Hierarchy::Endorsement,
        ]
        .into_iter()
        .map(|hierarchy| (hierarchy, HierarchyAuthorization::default()))
        .collect();

        Self {
            key_authorizations: HashMap::new(),
            hierarchy_authorizations,
        }
    }
}

impl AuthorizationCache {
    pub(crate) fn has_parent_auth(&self, parent_name: &str) -> bool {
        self.key_authorizations.contains_key(parent_name)
    }
    
    pub(crate) fn set_parent_auth(&mut self, parent_name: &str, auth: Tpm2bAuth) {
        self.key_authorizations
            .entry(parent_name.to_string())
            .or_default()
            .parent_auth = auth;
    }

    pub(crate) fn get_parent_auth(&self, parent_name: &str) -> Option<&Tpm2bAuth> {
        self
            .key_authorizations
            .get(parent_name)
            .map(|authorization| &authorization.parent_auth)
    }

    pub(crate) fn set_hierarchy_policy_branch(&mut self, hierarchy: Hierarchy, index: usize) {
        self
            .hierarchy_authorizations
            .get_mut(&hierarchy)
            .expect("hierarchy authorization should be registered")
            .policy_branch = Some(index);
    }

    pub(crate) fn get_owner_auth(&self) -> &Tpm2bAuth {
        self.get_hierarchy_auth(Hierarchy::Storage)
    }

    pub(crate) fn get_hierarchy_auth(&self, hierarchy: Hierarchy) -> &Tpm2bAuth {
        &self
            .hierarchy_authorizations
            .get(&hierarchy)
            .expect("hierarchy authorization should be registered")
            .auth
    }

    pub(crate) fn get_hierarchy_policy_branch(&self, hierarchy: Hierarchy) -> Option<usize> {
        self.hierarchy_authorizations
            .get(&hierarchy)
            .and_then(|authorization| authorization.policy_branch)
    }
}

#[derive(Debug, Default)]
pub(crate) struct Authorization {
    auth: Tpm2bAuth,
    policy: Option<PolicyData>,
}

impl Authorization {
    pub(crate) fn new(auth: Tpm2bAuth, policy: Option<PolicyData>) -> Self {
        Self { auth, policy }
    }

    pub(crate) fn auth(&self) -> &Tpm2bAuth {
        &self.auth
    }

    pub(crate) fn policy(&self) -> Option<&PolicyData> {
        self.policy.as_ref()
    }

    pub(crate) fn set_auth(&mut self, auth: impl Into<Tpm2bAuth>) {
        self.auth = auth.into();
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self {
            auth: self.auth.duplicate(),
            policy: self.policy.clone(),
        }
    }

    pub(crate) fn as_parts(&self) -> (&Tpm2bAuth, Option<&PolicyData>) {
        (&self.auth, self.policy())
    }
}
