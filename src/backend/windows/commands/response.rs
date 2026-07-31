use super::super::{
    codec::{TpmUnmarshal, read_vec},
    types::{Tpm2bNonce, TpmRc, TpmaSession},
};
use super::TpmiStCommandTag;
use crate::{
    Error, Result,
    types::{Tpm2bAuth, TpmHandle},
};

pub(crate) struct Response {
    header: ResponseHeader,
    body: ResponseBody,
}

impl Response {
    pub(crate) fn new(header: ResponseHeader, body: ResponseBody) -> Self {
        Self { header, body }
    }

    pub(crate) fn header(&self) -> ResponseHeader {
        self.header
    }

    pub(crate) fn into_body(self) -> ResponseBody {
        self.body
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ResponseHeader {
    tag: TpmiStCommandTag,
    response_size: u32,
    response_code: TpmRc,
}

impl ResponseHeader {
    pub(crate) fn new(tag: TpmiStCommandTag, response_size: u32, response_code: TpmRc) -> Self {
        Self {
            tag,
            response_size,
            response_code,
        }
    }

    pub(crate) fn tag(&self) -> TpmiStCommandTag {
        self.tag
    }

    pub(crate) fn response_size(&self) -> u32 {
        self.response_size
    }

    pub(crate) fn response_code(&self) -> TpmRc {
        self.response_code
    }
}

// auth_area is present only for session responses
pub(crate) struct ResponseBody {
    handles: Vec<TpmHandle>,
    params: Vec<u8>,
    auth_area: Option<TpmsAuthResponse>,
}

impl ResponseBody {
    fn parse(input: &mut &[u8], response_handle_count: usize, uses_sessions: bool) -> Result<Self> {
        let mut handles = Vec::with_capacity(response_handle_count);

        for _ in 0..response_handle_count {
            handles.push(TpmHandle::unmarshal(input)?);
        }

        let (params, auth_area) = if uses_sessions {
            let param_size =
                usize::try_from(u32::unmarshal(input)?).map_err(|_| Error::InvalidData)?;
            let params = read_vec(input, param_size)?;

            let auth_area = if input.is_empty() {
                None
            } else {
                Some(TpmsAuthResponse::unmarshal(input)?)
            };

            (params, auth_area)
        } else {
            let params_len = input.len();
            let params = read_vec(input, params_len)?;

            (params, None)
        };

        Ok(Self {
            handles,
            params,
            auth_area,
        })
    }

    pub(crate) fn handles(&self) -> &[TpmHandle] {
        &self.handles
    }

    pub(crate) fn params(&self) -> &[u8] {
        &self.params
    }

    pub(crate) fn auth_area(&self) -> Option<&TpmsAuthResponse> {
        self.auth_area.as_ref()
    }
}

pub(crate) struct TpmsAuthResponse {
    nonce: Tpm2bNonce,
    session_attributes: TpmaSession,
    hmac: Tpm2bAuth,
}

impl TpmsAuthResponse {
    pub(crate) fn new(nonce: Tpm2bNonce, session_attributes: TpmaSession, hmac: Tpm2bAuth) -> Self {
        Self {
            nonce,
            session_attributes,
            hmac,
        }
    }

    pub(crate) fn into_nonce(self) -> Tpm2bNonce {
        self.nonce
    }

    pub(crate) fn nonce(&self) -> &Tpm2bNonce {
        &self.nonce
    }

    pub(crate) fn as_parts(&self) -> (&Tpm2bNonce, TpmaSession, &Tpm2bAuth) {
        (&self.nonce, self.session_attributes, &self.hmac)
    }
}
