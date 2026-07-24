use crate::types::{TpmCc, TpmHandle, Tpm2bAuth};

use super::TpmiStCommandTag;
use super::super::types::{TpmaSession, TpmiShAuthSession, Tpm2bNonce};

pub(crate) struct Command<'a> {
    header: CommandHeader,
    handles: Vec<TpmHandle>,
    authorizations: &'a [&'a TpmsAuthCommand],
    parameters: &'a [u8], // marshaled parameters
}

impl<'a> Command<'a> {
    pub(crate) fn new(command_code: TpmCc) -> Self {
        Self {
            header: CommandHeader::no_sessions(command_code),
            handles: Vec::new(),
            authorizations: &[],
            parameters: &[],
        }
    }

    pub(crate) fn with_handles(mut self, handles: impl Into<Vec<TpmHandle>>) -> Self {
        self.handles = handles.into();
        self
    }

    pub(crate) fn with_authorizations(
        mut self,
        authorizations: &'a [&'a TpmsAuthCommand],
    ) -> Self {
        if !authorizations.is_empty() {
            self.authorizations = authorizations;
            self.header.use_sessions();
        }

        self
    }

    pub(crate) fn with_parameters(mut self, parameters: &'a [u8]) -> Self {
        self.parameters = parameters;
        self
    }

    pub(crate) fn header(&self) -> CommandHeader {
        self.header
    }

    pub(crate) fn handles(&self) -> &[TpmHandle] {
        &self.handles
    }

    pub(crate) fn authorizations(&self) -> &'a [&'a TpmsAuthCommand] {
        self.authorizations
    }

    pub(crate) fn parameters(&self) -> &[u8] {
        &self.parameters
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CommandHeader {
    tag: TpmiStCommandTag,
    command_code: TpmCc,
}

impl CommandHeader {
    fn no_sessions(command_code: TpmCc) -> Self {
        Self {
            tag: TpmiStCommandTag::NO_SESSIONS,
            command_code,
        }
    }

    fn use_sessions(&mut self) {
        self.tag = TpmiStCommandTag::SESSIONS;
    }

    pub(crate) fn tag(&self) -> TpmiStCommandTag {
        self.tag
    }

    pub(crate) fn command_code(&self) -> TpmCc {
        self.command_code
    }
}

pub(crate) struct TpmsAuthCommand {
    session_handle: TpmiShAuthSession,
    nonce: Tpm2bNonce,
    session_attributes: TpmaSession,
    hmac: Tpm2bAuth,
}

impl TpmsAuthCommand {
    pub(crate) fn new(
        session_handle: TpmiShAuthSession,
        nonce: Tpm2bNonce,
        session_attributes: TpmaSession,
        hmac: Tpm2bAuth,
    ) -> Self {
        Self {
            session_handle,
            nonce,
            session_attributes,
            hmac,
        }
    }

    pub(crate) fn password() -> Self {
        Self {
            session_handle: TpmiShAuthSession::RS_PW,
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::empty(),
            hmac: Tpm2bAuth::default(),
        }
    }

    pub(crate) fn set_hmac(&mut self, hmac: Tpm2bAuth) {
        self.hmac = hmac;
    }

    pub(crate) fn session_handle(&self) -> TpmiShAuthSession {
        self.session_handle
    }

    pub(crate) fn nonce(&self) -> &Tpm2bNonce {
        &self.nonce
    }

    pub(crate) fn session_attributes(&self) -> TpmaSession {
        self.session_attributes
    }

    pub(crate) fn as_parts(&self) -> (TpmiShAuthSession, &Tpm2bNonce, TpmaSession, &Tpm2bAuth) {
        (
            self.session_handle,
            &self.nonce,
            self.session_attributes,
            &self.hmac,
        )
    }
}
