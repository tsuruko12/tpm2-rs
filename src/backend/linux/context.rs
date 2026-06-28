mod random;
mod tcti;

use tss_esapi::Context as EsapiContext;

use crate::{data::MetadataStore, types::AuthorizationCache};

pub struct Context {
    ctx: EsapiContext,
    store: MetadataStore,
    authorization_cache: AuthorizationCache,
}