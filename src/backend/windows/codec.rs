mod parse;
mod wire;

pub(super) use self::parse::{
    CreateResponse, CreatePrimaryResponse, GetCapabilityResponse, LoadResponse, PcrReadResponse, 
    ReadPublicResponse, StartAuthSessionResponse, parse_response_params_and_authorizations
};
pub(super) use self::wire::{
    read_vec, marshal_tpm2b, read_tpm2b_exact, tpm2b_payload_mut, 
    TpmMarshal, TpmUnmarshal
};

use self::wire::{ensure_consumed, read_tpm2b, read_u8, read_u32};
