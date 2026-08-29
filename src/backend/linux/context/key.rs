mod create;
mod crypto;
mod load;
mod read_public;

use sha2::{Digest, Sha256};
use tss_esapi::{structures::Public, traits::Marshall};

use crate::{Error, Result, types::tpm::{Tpm2bName, TpmiAlgHash}};
use super::{Context, CommandResources};

fn compute_obj_name(public: &Public) -> Result<Tpm2bName> {
    let public_area_bytes = public
        .marshall()
        .map_err(|e| Error::invalid_state(format!("failed to marshal tss-esapi public: {e:?}")))?;
    let digest = Sha256::digest(&public_area_bytes);

    let mut name = Vec::with_capacity(size_of::<TpmiAlgHash>() + digest.len());
    let nam_alg = TpmiAlgHash::from(public.name_hashing_algorithm());
    name.extend_from_slice(&nam_alg.value().to_be_bytes());
    name.extend_from_slice(&digest);

    name.try_into()
}