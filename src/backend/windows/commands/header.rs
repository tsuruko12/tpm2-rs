use crate::types::{TpmCc, TpmRc, TpmiStCommandTag, Uint32};

const TPM_ST_NO_SESSIONS: TpmiStCommandTag = 0x8001;
const TPM_ST_SESSIONS: TpmiStCommandTag = 0x8002;
const TPM_HEADER_SIZE: usize = 10;

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

// エラー時はresponse sizeは10バイト、上位20bitは0で12bitがエラーコード
// 成功時は１０バイト以上返る

pub(crate) struct ResponseHeader {
    tag: TpmiStCommandTag,
    response_size: Uint32,
    response_code: TpmRc,
}
