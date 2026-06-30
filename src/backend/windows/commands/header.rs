use super::{
    TpmCc, TpmiStCommandTag, Uint32, TPM_ST_NO_SESSIONS,
    TPM_ST_SESSIONS,
};

pub(crate) const TPM_HEADER_SIZE: usize = 10;

// big-endian

#[derive(Debug)]
pub(crate) struct CommandHeader {
    tag: TpmiStCommandTag,
    command_size: Uint32,
    command_code: TpmCc,
}

impl CommandHeader {
    pub(crate) fn no_sessions(body_len: usize, command_code: TpmCc) -> Self {
        Self {
            tag: TPM_ST_NO_SESSIONS,
            command_size: (TPM_HEADER_SIZE + body_len) as u32,
            command_code,
        }
    }

    pub(crate) fn with_sessions(body_len: usize, command_code: TpmCc) -> Self {
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

    pub(super) fn command_size(&self) -> Uint32 {
        self.command_size
    }
}

// エラー時はresponse headerのみ
// エラー時はresponse codeは上位20bitは0、下位12bitがエラーコード
// 成功時は可変の戻り値含む
