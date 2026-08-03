mod crypto;
mod policy;

use rsa::{BigUint, RsaPublicKey};
use zeroize::Zeroizing;

use super::super::{
    codec::{StartAuthSessionResponse, TpmMarshal, marshal_tpm2b},
    commands::{Command, TpmsAuthCommand, TpmsAuthResponse},
    types::{Tpm2bNonce, TpmSe, TpmaSession, TpmiShAuthSession, TpmiShHmac},
};
use super::Context;
use crate::{
    Error, Result,
    types::{
        Authorization, PolicyAuthKind, PolicyData, Tpm2bAuth, TpmCc, TpmHandle, TpmiAlgHash,
        TpmiDhObject, TpmtSymDefObject,
    },
};

pub(super) use self::crypto::{decrypt_response_parameter, encrypt_command_parameter};
use self::crypto::{
    derive_session_key, generate_caller_nonce, generate_encrypted_salt, verify_response_hmac
};
use super::super::{codec, commands, types};

const AUTH_HASH: TpmiAlgHash = TpmiAlgHash::SHA256;
const DEFAULT_EXPONENT: u32 = 65_537;

pub(super) enum PreparedSession {
    Password {
        auth_command: TpmsAuthCommand,
    },
    Hmac {
        auth_command: TpmsAuthCommand,
        session_value: Zeroizing<Vec<u8>>,
        nonce_tpm: Tpm2bNonce,
    },
    Policy {
        auth_command: TpmsAuthCommand,
        session_value: Zeroizing<Vec<u8>>,
        nonce_tpm: Tpm2bNonce,
        requires_hmac: bool,
    },
}

pub(super) enum ResponseAuthContext<'a> {
    None,
    Hmac(ResponseHmacContext<'a>),
}

impl ResponseAuthContext<'_> {
    pub(super) fn requires_hmac(&self) -> bool {
        matches!(self, Self::Hmac(_))
    }

    pub(super) fn verify_hmac(
        &self,
        command_code: TpmCc,
        parameters: &[u8],
        auth_response: &TpmsAuthResponse,
    ) -> Result<()> {
        match self {
            Self::None => Ok(()),
            Self::Hmac(context) => verify_response_hmac(
                context.session_value,
                command_code,
                parameters,
                context.nonce_caller.as_bytes(),
                auth_response,
            ),
        }
    }
}

pub(super) struct HmacSessionState {
    session_handle: TpmiShAuthSession,
    session_value: Zeroizing<Vec<u8>>,
    nonce_tpm: Tpm2bNonce,
}

impl HmacSessionState {
    pub(super) fn from_response(
        idx: usize,
        sessions: Vec<PreparedSession>,
        auth_responses: Vec<TpmsAuthResponse>,
    ) -> Result<Self> {
        let session = sessions
            .into_iter()
            .nth(idx)
            .ok_or_else(|| Error::invalid_state("HMAC prepared session was not found"))?;

        let auth_response = auth_responses
            .into_iter()
            .nth(idx)
            .ok_or_else(|| Error::invalid_state("HMAC authorization response was not found"))?;

        let PreparedSession::Hmac {
            auth_command,
            session_value,
            ..
        } = session
        else {
            return Err(Error::invalid_state(
                "prepared session at HMAC session index was not HMAC",
            ));
        };

        Ok(Self {
            session_handle: auth_command.session_handle(),
            session_value,
            nonce_tpm: auth_response.into_nonce(),
        })
    }
}

impl PreparedSession {
    fn auth_command(&self) -> &TpmsAuthCommand {
        match self {
            Self::Password { auth_command }
            | Self::Hmac { auth_command, .. }
            | Self::Policy { auth_command, .. } => auth_command,
        }
    }

    fn response_auth_context(&self) -> ResponseAuthContext<'_> {
        match self {
            Self::Password { .. }
            | Self::Policy {
                requires_hmac: false,
                ..
            } => ResponseAuthContext::None,
            Self::Hmac {
                auth_command,
                session_value,
                ..
            }
            | Self::Policy {
                auth_command,
                session_value,
                requires_hmac: true,
                ..
            } => ResponseAuthContext::Hmac(ResponseHmacContext {
                session_value,
                nonce_caller: auth_command.nonce(),
                command_attrs: auth_command.session_attributes(),
            }),
        }
    }

    fn update_hmac(&mut self, cp_hash_data: &CpHashData<'_>) -> Result<()> {
        match self {
            Self::Hmac {
                auth_command,
                session_value,
                nonce_tpm,
            }
            | Self::Policy {
                auth_command,
                session_value,
                nonce_tpm,
                requires_hmac: true,
            } => {
                let hmac = crypto::compute_hmac(
                    session_value,
                    cp_hash_data,
                    auth_command.nonce().as_bytes(),
                    nonce_tpm.as_bytes(),
                    auth_command.session_attributes(),
                )?;
                auth_command.set_hmac(hmac);

                Ok(())
            }
            Self::Password { .. }
            | Self::Policy {
                requires_hmac: false,
                ..
            } => Ok(()),
        }
    }
}

pub(super) fn authorization_commands(
    sessions: &[PreparedSession],
) -> Vec<&TpmsAuthCommand> {
    sessions.iter().map(PreparedSession::auth_command).collect()
}

pub(super) fn response_auth_contexts(
    sessions: &[PreparedSession],
) -> Vec<ResponseAuthContext<'_>> {
    sessions
        .iter()
        .map(PreparedSession::response_auth_context)
        .collect()
}

pub(super) fn update_command_hmacs(
    sessions: &mut [PreparedSession],
    cp_hash_data: &CpHashData<'_>,
) -> Result<()> {
    for session in sessions {
        session.update_hmac(cp_hash_data)?;
    }

    Ok(())
}

pub(super) struct ResponseHmacContext<'a> {
    pub(super) session_value: &'a [u8],
    pub(super) nonce_caller: &'a Tpm2bNonce,
    pub(super) command_attrs: TpmaSession,
}

pub(super) struct CpHashData<'a> {
    pub(super) command_code: TpmCc,
    pub(super) handle_names: &'a [&'a [u8]],
    pub(super) parameters: &'a [u8],
}

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
        authorization: &Authorization, 
        session_attrs: TpmaSession,
        tpm_key: Option<TpmiDhObject>,
        hmac_session_state: Option<HmacSessionState>,
    ) -> Result<Vec<PreparedSession>> {
        let mut sessions = Vec::with_capacity(2);

        let result = (|| {
            // tpm_key is only None before the handle is created
            let salt_key = match tpm_key {
                Some(handle) => Some(SaltKey {
                    handle,
                    public_key: self.build_rsa_public_key(handle)?,
                }),
                None => None,
            };
            let (auth, policy) = authorization.as_parts();

            if let Some(policy) = policy {
                let required_auth = policy.auth_kind()?.map(|kind| (kind, auth));

                sessions.push(self.prepare_policy_session(
                    policy,
                    salt_key.as_ref(),
                    required_auth,
                )?);

                if !session_attrs.is_empty() {
                    sessions.push(self.prepare_hmac_session(
                        session_attrs,
                        salt_key.as_ref(),
                        None,
                        hmac_session_state,
                    )?);
                }

                return Ok(sessions);
            }

            if (session_attrs.is_empty()
                || session_attrs == TpmaSession::CONTINUE_SESSION)
                && auth.is_empty()
                && hmac_session_state.is_none()
            {
                sessions.push(PreparedSession::Password {
                    auth_command: TpmsAuthCommand::password(),
                });
            } else {
                sessions.push(self.prepare_hmac_session(
                    session_attrs,
                    salt_key.as_ref(),
                    Some(auth),
                    hmac_session_state,
                )?);
            }

            Ok(sessions)
        })();

        if result.is_err() {
            let _ = self.flush_sessions();
        }

        result
    }

    fn build_rsa_public_key(&mut self, salt_key: TpmiDhObject) -> Result<RsaPublicKey> {
        let public_unique = self.read_rsa_public_unique(salt_key)?;

        RsaPublicKey::new(
            BigUint::from_bytes_be(&public_unique),
            BigUint::from(DEFAULT_EXPONENT),
        )
        .map_err(|e| Error::invalid_state(format!("failed to construct RSA public key: {e:?}")))
    }

    fn prepare_policy_session(
        &mut self,
        policy: &PolicyData,
        salt_key: Option<&SaltKey>,
        required_auth: Option<(PolicyAuthKind, &[u8])>,
    ) -> Result<PreparedSession> {
        self.ensure_session_slot_available()?;

        let session_type = TpmSe::Policy;
        let session_attrs = TpmaSession::empty();
        let nonce_caller = generate_caller_nonce()?;

        let (auth_command, nonce_tpm, session_value, requires_hmac) = match required_auth {
            Some((auth_kind, auth)) => {
                let (response, mut session_value) = match salt_key {
                    Some(salt_key) => self.start_salted_session(salt_key, &nonce_caller, session_type)?,
                    None => self.start_unsalted_session(&nonce_caller, session_type)?, 
                };

                let (hmac, requires_hmac) = match auth_kind {
                    PolicyAuthKind::AuthValue => {
                        session_value.extend_from_slice(auth);
                        (Tpm2bAuth::default(), true)
                    },
                    PolicyAuthKind::Password => (Tpm2bAuth::from(auth), false),
                };

                (
                    TpmsAuthCommand::new(response.session_handle, nonce_caller, session_attrs, hmac),
                    response.nonce,
                    session_value,
                    requires_hmac,
                )
            },
            None => {
                let (response, _) = self.start_unsalted_session(&nonce_caller, session_type)?;

                (
                    TpmsAuthCommand::new(
                        response.session_handle,
                        Tpm2bNonce::default(),
                        session_attrs,
                        Tpm2bAuth::default(),
                    ),
                    response.nonce,
                    Zeroizing::new(Vec::new()),
                    false,
                )
            },
        };

        self.apply_policy(auth_command.session_handle().try_into()?, policy)?;

        Ok(PreparedSession::Policy {
            auth_command,
            session_value,
            nonce_tpm,
            requires_hmac,
        })
    }

    fn prepare_hmac_session(
        &mut self,
        attrs: TpmaSession,
        salt_key: Option<&SaltKey>,
        auth: Option<&[u8]>,
        hmac_session_state: Option<HmacSessionState>,
    ) -> Result<PreparedSession> {
        self.ensure_session_slot_available()?;

        let session_type = TpmSe::Hmac;
        let nonce_caller = generate_caller_nonce()?;

        let (session_handle, session_value, nonce_tpm) = match hmac_session_state {
            Some(state) => (state.session_handle, state.session_value, state.nonce_tpm),
            None => {
                let (response, mut session_value) = match salt_key {
                    Some(salt_key) => self.start_salted_session(salt_key, &nonce_caller, session_type)?,
                    None => self.start_unsalted_session(&nonce_caller, session_type)?, 
                };

                if let Some(auth) = auth {
                    session_value.extend_from_slice(auth);
                }

                (response.session_handle, session_value, response.nonce)
            }
        };

        let auth_command = TpmsAuthCommand::new(
            session_handle, 
            nonce_caller, 
            attrs, 
            Tpm2bAuth::default(),
        );

        Ok(PreparedSession::Hmac {
            auth_command,
            session_value,
            nonce_tpm,
        })
    }

    fn start_unsalted_session(
        &mut self, 
        nonce_caller: &Tpm2bNonce, 
        session_type: TpmSe,
    ) -> Result<(StartAuthSessionResponse, Zeroizing<Vec<u8>>)> {
        let response = self.start_auth_session(
            nonce_caller.as_bytes(),
            &[],
            session_type,
            None,
        )?;

        Ok((response, Vec::new().into()))
    }

    fn start_salted_session(
        &mut self,
        salt_key: &SaltKey,
        nonce_caller: &Tpm2bNonce,
        session_type: TpmSe,
    ) -> Result<(StartAuthSessionResponse, Zeroizing<Vec<u8>>)> {
        let (encrypted_salt, salt) = generate_encrypted_salt(&salt_key.public_key)?;

        let response = self.start_auth_session(
            nonce_caller.as_bytes(),
            &encrypted_salt,
            session_type,
            Some(salt_key.handle),
        )?;
        let session_key = derive_session_key(
            salt.as_ref(), 
            response.nonce.as_bytes(), 
            nonce_caller.as_bytes(),
        )?;

        Ok((response, session_key))
    }

    fn start_auth_session(
        &mut self,
        nonce_caller: &[u8],
        encrypted_salt: &[u8],
        session_type: TpmSe,
        salt_key: Option<TpmiDhObject>,
    ) -> Result<StartAuthSessionResponse> {
        let command_handles = match salt_key {
            Some(handle) => vec![handle.into(), TpmHandle::RH_NULL],
            None => vec![TpmHandle::RH_NULL, TpmHandle::RH_NULL],
        };

        let mut request_params = Vec::new();

        marshal_tpm2b(&mut request_params, nonce_caller)?;
        marshal_tpm2b(&mut request_params, encrypted_salt)?;
        request_params.push(session_type as u8);
        TpmtSymDefObject::aes_128_cfb().marshal(&mut request_params)?;
        AUTH_HASH.raw().marshal(&mut request_params)?;

        let command = Command::new(TpmCc::START_AUTH_SESSION)
            .with_handles(command_handles)
            .with_parameters(&request_params);

        let response_body = self.submit(command)?;
        let response = StartAuthSessionResponse::parse(&response_body)?;

        self.register_session(response.session_handle);

        Ok(response)
    }

    fn ensure_session_slot_available(&self) -> Result<()> {
        if self.sessions.iter().any(Option::is_none) {
            Ok(())
        } else {
            Err(Error::invalid_state("no available session slot"))
        }
    }

    fn register_session(&mut self, session: TpmiShAuthSession) {
        let slot = self
            .sessions
            .iter_mut()
            .find(|slot| slot.is_none())
            .expect("session slot must be available");

        *slot = Some(session);
    }
}

pub(super) fn find_hmac_session(sessions: &[PreparedSession]) -> Option<usize> {
    for (idx, session) in sessions.iter().enumerate() {
        let handle = session.auth_command().session_handle();

        if (TpmiShHmac::FIRST..=TpmiShHmac::LAST).contains(&handle.raw()) {
            return Some(idx);
        }
    }

    None
}
