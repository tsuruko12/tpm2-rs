mod create;
mod crypto;
mod load;
mod read_public;

use sha2::{Digest, Sha256};

use super::{Command, CommandResources, Context};
use crate::{
    Result,
    types::tpm::{Tpm2bName, TpmMarshal, TpmiAlgHash, TpmtPublic},
};

fn compute_obj_name(public_area: &TpmtPublic) -> Result<Tpm2bName> {
    let mut public_area_bytes = Vec::new();
    public_area.marshal(&mut public_area_bytes)?;

    let digest = Sha256::digest(&public_area_bytes);

    let mut name = Vec::with_capacity(size_of::<TpmiAlgHash>() + digest.len());
    name.extend_from_slice(&public_area.name_alg().value().to_be_bytes());
    name.extend_from_slice(&digest);

    name.try_into()
}
