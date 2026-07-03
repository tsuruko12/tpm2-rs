use super::TpmCc;

pub(crate) const TPM_HEADER_SIZE: usize = 10;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TpmiStCommandTag {
    NoSessions = 0x8001,
    Sessions = 0x8002,
}

impl TpmiStCommandTag {
    pub(crate) fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommandHeader {
    tag: TpmiStCommandTag,
    command_size: u32,
    command_code: TpmCc,
}

impl CommandHeader {
    pub(crate) fn no_sessions(body_len: usize, command_code: TpmCc) -> Self {
        Self {
            tag: TpmiStCommandTag::NoSessions,
            command_size: (TPM_HEADER_SIZE + body_len) as u32,
            command_code,
        }
    }

    pub(crate) fn with_sessions(body_len: usize, command_code: TpmCc) -> Self {
        Self {
            tag: TpmiStCommandTag::Sessions,
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

    pub(super) fn command_size(&self) -> u32 {
        self.command_size
    }
}

// エラー時はresponse headerのみ
// エラー時はresponse codeは上位20bitは0、下位12bitがエラーコード
// 成功時は可変の戻り値含む
