mod capability;
mod random;
mod tcti;

use tss_esapi::Context as EsapiContext;

pub struct Context {
    ctx: EsapiContext,
}
