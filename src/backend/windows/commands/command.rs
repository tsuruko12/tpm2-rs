use crate::types::tpm::{Tpm2bAuth, TpmCc, TpmHandle, TpmaSession};

use super::super::types::{Tpm2bNonce, TpmiShAuthSession};
use super::TpmiStCommandTag;

pub(in crate::backend::windows) struct Command<'p> {
    header: CommandHeader,
    handles: Vec<TpmHandle>,
    authorization_area: Vec<TpmsAuthCommand>,
    parameters: &'p mut [u8], // marshaled parameters
}

impl<'p> Command<'p> {
    pub(in crate::backend::windows) fn new(command_code: TpmCc) -> Self {
        Self {
            header: CommandHeader::no_sessions(command_code),
            handles: Vec::new(),
            authorization_area: Vec::new(),
            parameters: &mut [],
        }
    }

    pub(in crate::backend::windows) fn with_handles<T, I>(mut self, handles: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<TpmHandle>,
    {
        self.handles = handles.into_iter().map(Into::into).collect();
        self
    }

    pub(in crate::backend::windows) fn with_authorization_area(mut self, authorization_area: Vec<TpmsAuthCommand>) -> Self {
        if !authorization_area.is_empty() {
            self.authorization_area = authorization_area;
            self.header.use_sessions();
        }

        self
    }

    pub(in crate::backend::windows) fn with_parameters(mut self, parameters: &'p mut [u8]) -> Self {
        self.parameters = parameters;
        self
    }

    pub(in crate::backend::windows) fn header(&self) -> CommandHeader {
        self.header
    }

    pub(in crate::backend::windows) fn handles(&self) -> &[TpmHandle] {
        &self.handles
    }

    pub(in crate::backend::windows) fn authorization_area(&self) -> &[TpmsAuthCommand] {
        &self.authorization_area
    }

    pub(in crate::backend::windows) fn authorization_area_mut(&mut self) -> &mut [TpmsAuthCommand] {
        &mut self.authorization_area
    }

    pub(in crate::backend::windows) fn parameters(&self) -> &[u8] {
        &self.parameters
    }

    pub(in crate::backend::windows) fn parameters_mut(&mut self) -> &mut [u8] {
        self.parameters
    }
}

#[derive(Debug, Clone, Copy)]
pub(in crate::backend::windows) struct CommandHeader {
    tag: TpmiStCommandTag,
    command_code: TpmCc,
}

impl CommandHeader {
    pub(in crate::backend::windows) const SIZE: usize = 10;

    fn no_sessions(command_code: TpmCc) -> Self {
        Self {
            tag: TpmiStCommandTag::NO_SESSIONS,
            command_code,
        }
    }

    fn use_sessions(&mut self) {
        self.tag = TpmiStCommandTag::SESSIONS;
    }

    pub(in crate::backend::windows) fn tag(&self) -> TpmiStCommandTag {
        self.tag
    }

    pub(in crate::backend::windows) fn command_code(&self) -> TpmCc {
        self.command_code
    }
}

pub(in crate::backend::windows) struct TpmsAuthCommand {
    session_handle: TpmiShAuthSession,
    nonce: Tpm2bNonce,
    session_attributes: TpmaSession,
    hmac: Tpm2bAuth,
}

impl TpmsAuthCommand {
    pub(in crate::backend::windows) fn new(
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

    pub(in crate::backend::windows) fn password(session_attributes: TpmaSession) -> Self {
        Self {
            session_handle: TpmiShAuthSession::RS_PW,
            nonce: Tpm2bNonce::default(),
            session_attributes,
            hmac: Tpm2bAuth::default(),
        }
    }

    pub(in crate::backend::windows) fn set_hmac(&mut self, hmac: Tpm2bAuth) {
        self.hmac = hmac;
    }

    pub(in crate::backend::windows) fn session_handle(&self) -> TpmiShAuthSession {
        self.session_handle
    }

    pub(in crate::backend::windows) fn nonce(&self) -> &Tpm2bNonce {
        &self.nonce
    }

    pub(in crate::backend::windows) fn session_attributes(&self) -> TpmaSession {
        self.session_attributes
    }

    pub(in crate::backend::windows) fn hmac(&self) -> &Tpm2bAuth {
        &self.hmac
    }
}
