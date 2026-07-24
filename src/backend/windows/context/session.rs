mod crypto;
mod policy;

use rsa::{BigUint, RsaPublicKey};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    types::{
        Authorization, PolicyAuthKind, PolicyData, TpmCc, TpmHandle, TpmiAlgHash, TpmiDhObject,
        TpmtSymDefObject, Tpm2bAuth
    },
};
use super::super::{
    codec::{StartAuthSessionResponse, TpmMarshal, marshal_tpm2b},
    commands::{Command, TpmsAuthCommand, TpmsAuthResponse},
    types::{Tpm2bNonce, TpmSe, TpmaSession, TpmiShAuthSession, TpmiShHmac},
};
use super::Context;

pub(super) use self::crypto::{decrypt_response_parameter, encrypt_command_parameter, verify_response_hmac};
use self::crypto::{derive_session_key, generate_caller_nonce, generate_encrypted_salt};
use super::super::{codec, commands, types};

const AUTH_HASH: TpmiAlgHash = TpmiAlgHash::SHA256;
const BUF_LEN: usize = 32;
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
        } = session else {
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

pub(super) fn split_prepared_sessions<'a>(
    sessions: &'a [PreparedSession],
) -> (Vec<&'a TpmsAuthCommand>, Vec<ResponseAuthContext<'a>>) {
    let auth_commands = sessions.iter().map(PreparedSession::auth_command).collect();
    let auth_contexts = sessions
        .iter()
        .map(PreparedSession::response_auth_context)
        .collect();

    (auth_commands, auth_contexts)
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
struct SessionSaltKey {
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
        session_salt_key_handle: Option<TpmiDhObject>,
        hmac_session_state: Option<HmacSessionState>,
    ) -> Result<Vec<PreparedSession>> {
        // session_salt_key_handle is only None before the handle is created
        let session_salt_key_handle = if let Some(handle) = session_salt_key_handle {
            handle
        } else {
            return Ok(
                vec![PreparedSession::Password { auth_command: TpmsAuthCommand::password() }]
            );
        };

        let session_salt_key = SessionSaltKey {
            handle: session_salt_key_handle,
            public_key: self.build_rsa_public_key(session_salt_key_handle)?,
        };
        let (auth, policy) = authorization.as_parts();

        let mut sessions = Vec::new();

        if let Some(policy) = policy {
            let required_auth = policy.auth_kind()?.map(|kind| (kind, auth));

            sessions.push(self.prepare_policy_session(policy, &session_salt_key, required_auth)?);

            if !session_attrs.is_empty() {
                sessions.push(self.prepare_hmac_session(
                    session_attrs,
                    &session_salt_key,
                    None,
                    hmac_session_state,
                )?);
            }

            return Ok(sessions);
        }

        if (session_attrs.is_empty() || session_attrs == TpmaSession::CONTINUE_SESSION) 
            && auth.is_empty() 
            && hmac_session_state.is_none()
        {
            sessions.push(PreparedSession::Password { auth_command: TpmsAuthCommand::password() });
        } else {
            sessions.push(self.prepare_hmac_session(
                session_attrs,
                &session_salt_key,
                Some(auth),
                hmac_session_state,
            )?);
        }

        Ok(sessions)
    }

    fn build_rsa_public_key(&mut self, session_salt_key: TpmiDhObject) -> Result<RsaPublicKey> {
        let public_unique = self.read_rsa_public_unique(session_salt_key)?;

        RsaPublicKey::new(
            BigUint::from_bytes_be(&public_unique),
            BigUint::from(DEFAULT_EXPONENT),
        )
        .map_err(|e| Error::invalid_state(format!("failed to construct RSA public key: {e:?}")))
    }

    fn prepare_policy_session(
        &mut self,
        policy: &PolicyData,
        session_salt_key: &SessionSaltKey,
        require_auth: Option<(PolicyAuthKind, &[u8])>,
    ) -> Result<PreparedSession> {
        let session_attrs = TpmaSession::empty();
        let nonce_caller = generate_caller_nonce()?;

        let (auth_command, nonce_tpm, session_value, requires_hmac) = if let Some(require_auth) =
            require_auth
        {
            let (auth_kind, auth) = require_auth;
            let (encrypted_salt, salt) = generate_encrypted_salt(&session_salt_key.public_key)?;

            let response = self.start_auth_session(
                nonce_caller.as_bytes(),
                &encrypted_salt,
                TpmSe::Policy,
                Some(session_salt_key.handle),
            )?;

            let mut session_value = derive_session_key(
                salt.as_ref(),
                response.nonce.as_bytes(),
                nonce_caller.as_bytes(),
            )?;

            let (hmac, requires_hmac) = match auth_kind {
                PolicyAuthKind::AuthValue => {
                    session_value.extend_from_slice(auth);

                    (Tpm2bAuth::default(), true)
                }
                PolicyAuthKind::Password => (Tpm2bAuth::from(auth), false),
            };

            (
                TpmsAuthCommand::new(response.session_handle, nonce_caller, session_attrs, hmac),
                response.nonce,
                session_value,
                requires_hmac,
            )
        } else {
            let response =
                self.start_auth_session(nonce_caller.as_bytes(), &[], TpmSe::Policy, None)?;

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
        session_salt_key: &SessionSaltKey,
        auth: Option<&[u8]>,
        hmac_session_state: Option<HmacSessionState>,
    ) -> Result<PreparedSession> {
        let nonce_caller = generate_caller_nonce()?;

        let (session_handle, session_value, nonce_tpm) = if let Some(state) = hmac_session_state {
            (state.session_handle, state.session_value, state.nonce_tpm)
        } else {
            let (encrypted_salt, salt) = generate_encrypted_salt(&session_salt_key.public_key)?;

            let (session_handle, nonce_tpm) = self
                .start_auth_session(
                    nonce_caller.as_bytes(),
                    &encrypted_salt,
                    TpmSe::Hmac,
                    Some(session_salt_key.handle),
                )
                .map(|response| (response.session_handle, response.nonce))?;

            let mut session_value =
                derive_session_key(salt.as_ref(), nonce_tpm.as_bytes(), nonce_caller.as_bytes())?;

            if let Some(auth) = auth {
                session_value.extend_from_slice(auth);
            }

            (session_handle, session_value, nonce_tpm)
        };

        let auth_command =
            TpmsAuthCommand::new(session_handle, nonce_caller, attrs, Tpm2bAuth::default());

        Ok(PreparedSession::Hmac {
            auth_command,
            session_value,
            nonce_tpm,
        })
    }

    fn start_auth_session(
        &mut self,
        nonce_caller: &[u8],
        encrypted_salt: &[u8],
        session_type: TpmSe,
        session_salt_key: Option<TpmiDhObject>,
    ) -> Result<StartAuthSessionResponse> {
        let command_handles = if let Some(handle) = session_salt_key {
            vec![handle.into(), TpmHandle::RH_NULL]
        } else {
            vec![TpmHandle::RH_NULL, TpmHandle::RH_NULL]
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
        self.register_session(response.session_handle)?;

        Ok(response)
    }

    fn register_session(&mut self, session: TpmiShAuthSession) -> Result<()> {
        let slot = self
            .sessions
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| Error::invalid_state("no available session slot"))?;

        *slot = Some(session);

        Ok(())
    }
}

pub(super) fn find_hmac_session(
    sessions: &[PreparedSession],
) -> Option<usize> {
    for (idx, session) in sessions.iter().enumerate() {
        let handle = session.auth_command().session_handle();

        if (TpmiShHmac::FIRST..=TpmiShHmac::LAST).contains(&handle.raw()) {
            return Some(idx);
        }
    }

    None
}
