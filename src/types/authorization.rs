use crate::{policy::PolicyData, types::tpm::Tpm2bAuth};

#[derive(Default)]
pub(crate) struct Authorization {
    pub(crate) auth: Tpm2bAuth,
    pub(crate) policy: Option<PolicyData>,
}