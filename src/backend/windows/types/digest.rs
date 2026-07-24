use crate::{macros::tpm_list_type, types::Tpm2bDigest};

tpm_list_type!(TpmlDigest(Tpm2bDigest););
