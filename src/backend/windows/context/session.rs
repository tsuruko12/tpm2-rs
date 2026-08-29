mod crypto;
mod policy;

use rsa::{BigUint, RsaPublicKey};
use zeroize::Zeroizing;

use super::super::{
    types::{TpmiShAuthSession, TpmiShHmac, Tpm2bNonce, TpmSe, Tpm2bEncryptedSecret},
};
use super::{
    Command, CommandResources, Context, SessionState, StartAuthSessionResponse, TpmsAuthCommand,
};
use crate::{
    Error, Result, 
    types::{
        Authorization, PolicyAuthKind, PolicyData,
        tpm::{
            Tpm2bAuth, TpmCc, TpmHandle, TpmaSession, TpmiAlgHash, TpmMarshal, TpmiDhObject,
            TpmtSymDefObject
        },
    },
};

use self::crypto::{derive_session_key, generate_caller_nonce, generate_encrypted_salt};

const RESPONSE_HANDLE_COUNT: usize = 1;
const DEFAULT_EXPONENT: u32 = 65_537;

#[derive(Debug, Clone)]
struct SaltKey {
    handle: TpmiDhObject,
    public_key: RsaPublicKey,
}

// policy + no-attrs -> policy authorization
// policy + attrs -> policy authorization + extra HMAC session for attrs
// no-policy + attrs -> HMAC authorization
// no-policy + auth + no-attrs -> HMAC authorization
// no-policy + no-auth + no-attrs -> password authorization
impl Context {
    pub(super) fn prepare_sessions(
        &mut self,
        resources: &mut CommandResources,
        hmac_session_attrs: TpmaSession,
        authorization: Option<&Authorization>,
        tpm_key: Option<TpmiDhObject>,
    ) -> Result<Vec<TpmsAuthCommand>> {
        // tpm_key is only None before the handle is created
        let salt_key = match tpm_key {
            Some(handle) => Some(SaltKey {
                handle,
                public_key: self.build_rsa_public_key(handle)?,
            }),
            None => None,
        };

        let Some(authorization) = authorization else {
            return Ok(vec![self.prepare_hmac_session(
                resources, 
                hmac_session_attrs, 
                salt_key.as_ref(),
                None,
            )?]);
        };

        let mut auth_commands = Vec::with_capacity(2);

        if let Some(policy) = &authorization.policy {
            let required_auth = policy.auth_kind()?
                .map(|kind| (kind, &authorization.auth));

            auth_commands.push(self.prepare_policy_session(
                resources,
                hmac_session_attrs,
                policy,
                salt_key.as_ref(),
                required_auth,
            )?);

            if !hmac_session_attrs.is_empty() {
                auth_commands.push(self.prepare_hmac_session(
                    resources,
                    hmac_session_attrs,
                    salt_key.as_ref(),
                    None,
                )?);
            }
        } else if (hmac_session_attrs.is_empty()
            || hmac_session_attrs == TpmaSession::CONTINUE_SESSION)
            && authorization.auth.is_empty()
        {
            auth_commands.push(TpmsAuthCommand::password());
        } else {
            auth_commands.push(self.prepare_hmac_session(
                resources,
                hmac_session_attrs,
                salt_key.as_ref(),
                Some(&authorization.auth),
            )?);
        }

        Ok(auth_commands)
    }

    fn build_rsa_public_key(&mut self, salt_key: TpmiDhObject) -> Result<RsaPublicKey> {
        let public_unique = self.read_rsa_public_unique(salt_key)?;

        RsaPublicKey::new(
            BigUint::from_bytes_be(public_unique.as_bytes()),
            BigUint::from(DEFAULT_EXPONENT),
        )
        .map_err(|e| Error::invalid_state(
            format!("failed to construct RSA public key: {e:?}")
        ))
    }

    fn prepare_policy_session(
        &mut self,
        resources: &mut CommandResources,
        hmac_session_attrs: TpmaSession,
        policy: &PolicyData,
        salt_key: Option<&SaltKey>,
        required_auth: Option<(PolicyAuthKind, &Tpm2bAuth)>,
    ) -> Result<TpmsAuthCommand> {
        let session_type = TpmSe::Policy;
        let session_attrs = policy_session_attrs_from_hmac(hmac_session_attrs);
        let nonce_caller = generate_caller_nonce()?;

        let auth_command = match required_auth {
            Some((auth_kind, auth)) => {
                let uses_hmac = matches!(auth_kind, PolicyAuthKind::AuthValue);
                let (response, mut session_value) = match salt_key {
                    Some(salt_key) => {
                        self.start_salted_session(resources, salt_key, &nonce_caller, session_type)?
                    }
                    None => self.start_unsalted_session(resources, &nonce_caller, session_type)?,
                };

                let hmac = match auth_kind {
                    PolicyAuthKind::AuthValue => {
                        session_value.extend_from_slice(auth.as_bytes());
                        Tpm2bAuth::default()
                    }
                    PolicyAuthKind::Password => auth.clone(),
                };

                resources.add_session_state(SessionState {
                    session_value,
                    nonce_tpm: response.nonce_tpm,
                    uses_hmac,
                })?;

                TpmsAuthCommand::new(response.session_handle, nonce_caller, session_attrs, hmac)
            }
            None => {
                let (response, _) = self.start_unsalted_session(
                    resources, 
                    &nonce_caller, 
                    session_type
                )?;
                resources.add_session_state(SessionState {
                    session_value: Vec::new().into(),
                    nonce_tpm: response.nonce_tpm,
                    uses_hmac: false,
                })?;

                TpmsAuthCommand::new(
                    response.session_handle,
                    Tpm2bNonce::default(),
                    session_attrs,
                    Tpm2bAuth::default(),
                )
            }
        };

        self.apply_policy(
            auth_command
                .session_handle()
                .try_into()
                .expect("expected policy session handle"),
            policy,
        )?;

        Ok(auth_command)
    }

    fn prepare_hmac_session(
        &mut self,
        resources: &mut CommandResources,
        session_attrs: TpmaSession,
        salt_key: Option<&SaltKey>,
        auth: Option<&Tpm2bAuth>,
    ) -> Result<TpmsAuthCommand> {
        let session_type = TpmSe::Hmac;
        let nonce_caller = generate_caller_nonce()?;

        let (response, mut session_value) = match salt_key {
            Some(salt_key) => {
                self.start_salted_session(resources, salt_key, &nonce_caller, session_type)?
            }
            None => self.start_unsalted_session(resources, &nonce_caller, session_type)?,
        };

        if let Some(auth) = auth {
            session_value.extend_from_slice(auth.as_bytes());
        }

        resources.add_session_state(SessionState {
            session_value,
            nonce_tpm: response.nonce_tpm,
            uses_hmac: true,
        })?;

        Ok(TpmsAuthCommand::new(
            response.session_handle,
            nonce_caller,
            session_attrs,
            Tpm2bAuth::default(),
        ))
    }

    fn start_unsalted_session(
        &mut self,
        resources: &mut CommandResources,
        nonce_caller: &Tpm2bNonce,
        session_type: TpmSe,
    ) -> Result<(StartAuthSessionResponse, Zeroizing<Vec<u8>>)> {
        let response =
            self.start_auth_session(
                resources, 
                nonce_caller, 
                &Tpm2bEncryptedSecret::default(), 
                session_type, 
                None,
            )?;

        Ok((response, Vec::new().into()))
    }

    fn start_salted_session(
        &mut self,
        resources: &mut CommandResources,
        salt_key: &SaltKey,
        nonce_caller: &Tpm2bNonce,
        session_type: TpmSe,
    ) -> Result<(StartAuthSessionResponse, Zeroizing<Vec<u8>>)> {
        let (encrypted_salt, salt) = generate_encrypted_salt(&salt_key.public_key)?;

        let response = self.start_auth_session(
            resources,
            nonce_caller,
            &encrypted_salt,
            session_type,
            Some(salt_key.handle.into()),
        )?;

        let session_key = derive_session_key(
            salt.as_ref(),
            response.nonce_tpm.as_bytes(),
            nonce_caller.as_bytes(),
        )?;

        Ok((response, session_key))
    }

    fn start_auth_session(
        &mut self,
        resources: &mut CommandResources,
        nonce_caller: &Tpm2bNonce,
        encrypted_salt: &Tpm2bEncryptedSecret,
        session_type: TpmSe,
        tpm_key: Option<TpmHandle>,
    ) -> Result<StartAuthSessionResponse> {
        let tpm_key = tpm_key.unwrap_or(TpmHandle::RH_NULL);
        let symmetric = TpmtSymDefObject::aes_128_cfb();
        let auth_hash = TpmiAlgHash::SHA256;

        let mut command_params = Vec::new();
        nonce_caller.marshal(&mut command_params)?;
        encrypted_salt.marshal(&mut command_params)?;
        session_type.marshal(&mut command_params)?;
        symmetric.marshal(&mut command_params)?;
        auth_hash.marshal(&mut command_params)?;

        let mut command = Command::new(TpmCc::START_AUTH_SESSION)
            .with_handles([tpm_key, TpmHandle::RH_NULL])
            .with_parameters(&mut command_params);

        let response_body = self.submit(&mut command, RESPONSE_HANDLE_COUNT, resources)?;
        let response = StartAuthSessionResponse::try_from(response_body)?;
        resources.add_session_handle(response.session_handle)?;

        Ok(response)
    }
}

fn policy_session_attrs_from_hmac(hmac_session_attrs: TpmaSession) -> TpmaSession {
    if hmac_session_attrs.contains(TpmaSession::CONTINUE_SESSION) {
        TpmaSession::continue_session()
    } else {
        TpmaSession::empty()
    }
}

pub(super) fn prepare_reused_sessions(
    resources: &CommandResources,
    auth_commands: &[TpmsAuthCommand], 
    hmac_session_attrs: TpmaSession,
) -> Result<Vec<TpmsAuthCommand>> {
    let mut new_auth_commands = Vec::with_capacity(2);

    for auth_command in auth_commands {
        if auth_command.session_handle() == TpmiShAuthSession::RS_PW {
            new_auth_commands.push(TpmsAuthCommand::password());
            continue;
        }

        let session_attrs = if TpmiShHmac::try_from(auth_command.session_handle()).is_ok() {
            hmac_session_attrs
        } else {
            policy_session_attrs_from_hmac(hmac_session_attrs)
        };

        let session_state = resources.get_session_state(auth_command.session_handle())?;
        let (nonce, hmac) = if session_state.uses_hmac {
            (generate_caller_nonce()?, Tpm2bAuth::default())
        } else {
            (auth_command.nonce().clone(), auth_command.hmac().clone())
        };
        
        new_auth_commands.push(TpmsAuthCommand::new(
            auth_command.session_handle(), 
            nonce, 
            session_attrs, 
            hmac,
        ));
    }

    Ok(new_auth_commands)
}
