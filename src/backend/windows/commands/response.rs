use tracing::debug;

use super::super::{
    TpmRc,
    types::Tpm2bNonce,
};
use super::TpmiStCommandTag;
use crate::{
    Error, Result,
    types::tpm::{Tpm2bAuth, TpmHandle, TpmUnmarshal, TpmaSession, read_vec},
};

pub(in crate::backend::windows) struct Response {
    pub(in crate::backend::windows) header: ResponseHeader,
    pub(in crate::backend::windows) body: ResponseBody,
    pub(in crate::backend::windows) authorization_area: Vec<TpmsAuthResponse>,
}

impl Response {
    pub(in crate::backend::windows) fn parse(input: &mut &[u8], response_handle_count: usize) -> Result<Self> {
        let response_size = input.len();
        let header = ResponseHeader::unmarshal(input)?;
        if header.response_size as usize != response_size {
            debug!(
                declared_size = header.response_size,
                response_size,
                "response size mismatch"
            );
            return Err(Error::InvalidData);
        }

        if header.response_code != TpmRc::SUCCESS {
            return Err(Error::from_rc(header.response_code));
        }

        let mut handles = Vec::with_capacity(response_handle_count);
        for _ in 0..response_handle_count {
            handles.push(TpmHandle::unmarshal(input)?);
        }

        let (authorization_area, body) = if header.tag == TpmiStCommandTag::SESSIONS {
            let param_size =
                usize::try_from(u32::unmarshal(input)?).map_err(|_| Error::InvalidData)?;
            let parameters = read_vec(input, param_size)?;

            let mut authorization_area = Vec::new();
            while !input.is_empty() {
                authorization_area.push(TpmsAuthResponse::unmarshal(input)?);
            }

            (authorization_area, ResponseBody { handles, parameters })
        } else {
            let params_len = input.len();
            let parameters = read_vec(input, params_len)?;

            (Vec::new(), ResponseBody { handles, parameters })
        };

        Ok(Self { header, authorization_area, body })
    }
}

#[derive(Debug, Clone, Copy)]
pub(in crate::backend::windows) struct ResponseHeader {
    pub(in crate::backend::windows) tag: TpmiStCommandTag,
    pub(in crate::backend::windows) response_size: u32,
    pub(in crate::backend::windows) response_code: TpmRc,
}

pub(in crate::backend::windows) struct ResponseBody {
    pub(in crate::backend::windows) handles: Vec<TpmHandle>,
    pub(in crate::backend::windows) parameters: Vec<u8>,
}

pub(in crate::backend::windows) struct TpmsAuthResponse {
    pub(in crate::backend::windows) nonce: Tpm2bNonce,
    pub(in crate::backend::windows) session_attributes: TpmaSession,
    pub(in crate::backend::windows) hmac: Tpm2bAuth,
}
