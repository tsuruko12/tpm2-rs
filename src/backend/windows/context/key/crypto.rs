use super::{Command, CommandResources, Context};
use super::super::RsaEncryptResponse;
use crate::backend::windows::types::TpmtRsaDecrypt;
use crate::{
    Result,
    backend::windows::types::Tpm2bData,
    types::{
        Authorization, LoadedObjectHandle,
        tpm::{Tpm2bPublicKeyRsa, TpmCc, TpmMarshal, TpmaSession, TpmiDhObject},
    },
};

const RSA_ENCRYPT_RESPONSE_HANDLE_COUNT: usize = 0;

impl Context {
    pub(super) fn wrap_key(
        &mut self,
        rsa_handle: LoadedObjectHandle,
        rsa_authorization: &Authorization,
        message: Tpm2bPublicKeyRsa,
        session_salt_handle: TpmiDhObject,
    ) -> Result<Tpm2bPublicKeyRsa> {
        let in_scheme = TpmtRsaDecrypt::oaep();
        let label = Tpm2bData::default();

        let mut command_params = Vec::new();
        message.marshal(&mut command_params)?;
        in_scheme.marshal(&mut command_params)?;
        label.marshal(&mut command_params)?;

        let mut resources = CommandResources::default();

        let result = (|| {
            let authorization_area = self.prepare_sessions(
                &mut resources,
                TpmaSession::decrypt(),
                Some(rsa_authorization),
                Some(session_salt_handle),
            )?;
            let mut command = Command::new(TpmCc::RSA_ENCRYPT)
                .with_handles([rsa_handle.inner()])
                .with_authorization_area(authorization_area)
                .with_parameters(&mut command_params);

            let response_body = self.submit(
                &mut command,
                RSA_ENCRYPT_RESPONSE_HANDLE_COUNT,
                &mut resources,
            )?;

            RsaEncryptResponse::try_from(response_body).map(|response| response.out_data)
        })();

        self.cleanup_on_err(result, &mut resources)
    }
}
