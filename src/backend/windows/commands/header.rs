use crate::error::{Error, Result};

use super::{TpmCc, TpmRc, TpmSt, TpmiStCommandTag, Uint32, TPM_RC_SUCCESS};

const TPM_HEADER_SIZE: usize = 10;
const TPM_ST_NO_SESSIONS: TpmiStCommandTag = 0x8001;
const TPM_ST_SESSIONS: TpmiStCommandTag = 0x8002;
// big-endian

#[derive(Debug)]
pub(crate) struct CommandHeader {
    tag: TpmiStCommandTag,
    command_size: Uint32,
    command_code: TpmCc,
}

impl CommandHeader {
    pub(crate) fn no_sessions(body_len: usize, command_code: u32) -> Self {
        Self {
            tag: TPM_ST_NO_SESSIONS,
            command_size: (TPM_HEADER_SIZE + body_len) as u32,
            command_code,
        }
    }

    pub(crate) fn with_sessions(body_len: usize, command_code: u32) -> Self {
        Self {
            tag: TPM_ST_SESSIONS,
            command_size: (TPM_HEADER_SIZE + body_len) as u32,
            command_code,
        }
    } 

    pub(crate) fn marshal(&self) -> Vec<u8> {
        let mut encoded = Vec::new();

        encoded.extend_from_slice(&self.tag.to_be_bytes());
        encoded.extend_from_slice(&self.command_size.to_be_bytes());
        encoded.extend_from_slice(&self.command_code.to_be_bytes());

        encoded
    }
}

// エラー時はresponse headerのみ
// エラー時はresponse codeは上位20bitは0、下位12bitがエラーコード
// 成功時は可変の戻り値含む

pub(crate) struct Response<'a> {
    tag: TpmSt,
    response_size: Uint32,
    response_code: TpmRc,
    parameters: &'a [u8],
}

impl<'a>  Response<'a> {
    pub(crate) fn unmarshal(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > TPM_HEADER_SIZE {
            return Err(Error::Internal("TPM response header must be 10 bytes"));
        }

        let tag = TpmiStCommandTag::from_be_bytes(bytes[0..2].try_into().unwrap());
        let response_size = Uint32::from_be_bytes(bytes[2..6].try_into().unwrap());
        let response_code = TpmRc::from_be_bytes(bytes[6..TPM_HEADER_SIZE].try_into().unwrap());

        let parameters = if bytes.len() == TPM_HEADER_SIZE {
            &[]
        } else {
            &bytes[TPM_HEADER_SIZE..]
        };

        Ok(Self {
            tag,
            response_size,
            response_code,
            parameters,
        })
    }

    pub(crate) fn ensure_response_code(&self) -> Result<()> {
        if self.response_code == TPM_RC_SUCCESS {
            Ok(())
        } else {
            Err(Error::from_rc(self.response_code))
        }
    }

    pub(crate) fn parameters(&self) -> &'a [u8] {
        self.parameters
    }
}
