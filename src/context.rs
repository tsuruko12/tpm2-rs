use crate::{backend::BackendContext, error::{Error, Result}};

pub struct Context {
    inner: BackendContext,
}

impl Context {
    pub fn connect() -> Result<Self> {
        Ok(Self { 
            inner: BackendContext::create_context()? 
        })
    }

    #[cfg(target_os = "linux")]
    pub fn connect_from_env() -> Result<Self> {
        Ok(Self {
            inner: BackendContext::create_context_from_tcti_env()?,
        })
    }

    fn get_random(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(num_bytes);
        
        while buf.len() < num_bytes {
            let remaining = num_bytes - buf.len();
            let chunk = self.get_random_once(remaining)?;

            if chunk.is_empty() {
                return Err(Error::failure("TPM returned no random bytes"));
            }

            buf.extend_from_slice(&chunk);
        }

        buf.truncate(num_bytes);

        Ok(buf)
    }
}

pub(crate) fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
}