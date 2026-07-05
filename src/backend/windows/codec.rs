mod macros;
mod wire;

pub(super) use macros::marshal_be;
pub(super) use wire::{
    require_len, unmarshal_algs, unmarshal_cc, unmarshal_cca, unmarshal_ecc_curves,
    unmarshal_handles, unmarshal_pcr_properties, unmarshal_pcrs, unmarshal_tpm_properties,
    unmarshal_tpm2b,
};

use super::types::{
    TpmAlgId, TpmCc, TpmEccCurve, TpmHandle, TpmaAlgorithm, TpmaCc, TpmlAlgProperty, TpmlCc,
    TpmlCca, TpmlEccCurve, TpmlHandle, TpmlPcrSelection, TpmlTaggedPcrProperty,
    TpmlTaggedTpmProperty, TpmsAlgProperty, TpmsPcrSelection, TpmsTaggedPcrSelect,
    TpmsTaggedProperty,
};
