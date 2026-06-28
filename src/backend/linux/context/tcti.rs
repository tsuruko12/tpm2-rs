use std::str::FromStr;

use tss_esapi::{Context as EsapiContext, TctiNameConf, tcti_ldr::DeviceConfig};

use super::Context;
use crate::{
    data::MetadataStore,
    error::{Error, Result},
    types::AuthorizationCache,
};

impl Context {
    fn from_context(ctx: EsapiContext) -> Result<Self> {
        Ok(Self {
            ctx,
            store: MetadataStore::new()?,
            authorization_cache: AuthorizationCache::default(),
        })
    }

    pub(crate) fn create_context() -> Result<Self> {
        let tcti = TctiNameConf::Device(DeviceConfig::from_str("/dev/tpmrm0").unwrap());
        let ctx = EsapiContext::new(tcti)
            .or_else(|_| {
                EsapiContext::new(TctiNameConf::Device(
                    DeviceConfig::from_str("/dev/tpm0").unwrap(),
                ))
            })
            .map_err(Error::connect)?;

        Self::from_context(ctx)
    }

    pub(crate) fn create_context_from_tcti_env() -> Result<Self> {
        let tcti = TctiNameConf::from_environment_variable().map_err(Error::connect)?;
        let ctx = EsapiContext::new(tcti).map_err(Error::connect)?;

        Self::from_context(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::Context;

    #[test]
    #[ignore = "requires access to a local TPM device"]
    fn connect_to_tpm() {
        Context::create_context().expect("failed to connect to TPM");
    }

    #[test]
    #[ignore = "requires TPM2TOOLS_TCTI or TCTI environment configuration"]
    fn connect_to_tpm_from_env() {
        Context::create_context_from_tcti_env().expect("failed to connect to TPM from environment");
    }
}