use crate::{policy::PolicyData, types::Tpm2bAuth};

#[derive(Default)]
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

    pub(crate) fn as_parts(&self) -> (&Tpm2bAuth, Option<&PolicyData>) {
        (&self.auth, self.policy())
    }
}
