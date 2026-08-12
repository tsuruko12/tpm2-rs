mod parse;
mod wire;

pub(super) use self::parse::{
    CreatePrimaryResponse, CreateResponse, GetCapabilityResponse, GetRandomResponse, LoadResponse, PcrReadResponse,
    ReadPublicResponse, StartAuthSessionResponse, parse_response_params_and_authorizations,
};
pub(super) use crate::types::{
    TpmMarshal, TpmUnmarshal, marshal_tpm2b, read_tpm2b, read_u16, read_u32, read_vec,
};
pub(super) use self::wire::{read_tpm2b_exact, tpm2b_payload_mut};

use self::wire::{ensure_consumed, read_u8};
