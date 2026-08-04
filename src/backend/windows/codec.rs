mod parse;
mod wire;

pub(super) use self::parse::{
    CreatePrimaryResponse, CreateResponse, GetCapabilityResponse, GetRandomResponse, LoadResponse, PcrReadResponse,
    ReadPublicResponse, StartAuthSessionResponse, parse_response_params_and_authorizations,
};
pub(super) use self::wire::{
    TpmMarshal, TpmUnmarshal, marshal_tpm2b, read_tpm2b_exact, read_vec, tpm2b_payload_mut,
};

use self::wire::{ensure_consumed, read_tpm2b, read_u8, read_u32};
