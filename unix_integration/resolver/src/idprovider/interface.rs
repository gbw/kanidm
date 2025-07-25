use async_trait::async_trait;
use kanidm_hsm_crypto::provider::BoxedDynTpm;
use kanidm_unix_common::unix_proto::{
    DeviceAuthorizationResponse, PamAuthRequest, PamAuthResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::time::SystemTime;
use tokio::sync::broadcast;
use uuid::Uuid;

pub type XKeyId = String;

pub use kanidm_hsm_crypto as tpm;

/// Errors that the IdProvider may return. These drive the resolver state machine
/// and should be carefully selected to match your expected errors.
#[derive(Debug)]
pub enum IdpError {
    /// An error occurred in the underlying communication to the Idp. A timeout or
    /// or other communication issue exists. The resolver will take this provider
    /// offline.
    Transport,
    /// The provider is online but the provider module is not current authorised with
    /// the idp. After returning this error the operation will be retried after a
    /// successful authentication.
    ProviderUnauthorised,
    /// The provider made an invalid or illogical request to the idp, and a result
    /// is not able to be provided to the resolver.
    BadRequest,
    /// The idp has indicated that the requested resource does not exist and should
    /// be considered deleted, removed, or not present.
    NotFound,
    /// The idp was unable to perform an operation on the underlying hsm keystorage
    KeyStore,
    /// The idp failed to interact with the configured TPM
    Tpm,
}

pub enum UserTokenState {
    /// Indicate to the resolver that the cached UserToken should be used, if present.
    UseCached,
    /// The requested entity is not found, or has been removed.
    NotFound,

    /// Update the cache state with the data found in this UserToken.
    Update(UserToken),
}

pub enum GroupTokenState {
    /// Indicate to the resolver that the cached GroupToken should be used, if present.
    UseCached,
    /// The requested entity is not found, or has been removed.
    NotFound,

    /// Update the cache state with the data found in this GroupToken.
    Update(GroupToken),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Id {
    Name(String),
    Gid(u32),
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq, Hash)]
pub enum ProviderOrigin {
    // To allow transition, we have an ignored type that effectively
    // causes these items to be nixed.
    #[default]
    Ignore,
    /// Provided by local files, commonly /etc/passwd, /etc/group and /etc/shadow
    System,
    Kanidm,
}

impl fmt::Display for ProviderOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProviderOrigin::Ignore => {
                write!(f, "Ignored")
            }
            ProviderOrigin::System => {
                write!(f, "System")
            }
            ProviderOrigin::Kanidm => {
                write!(f, "Kanidm")
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupToken {
    #[serde(default)]
    pub provider: ProviderOrigin,
    pub name: String,
    pub spn: String,
    pub uuid: Uuid,
    pub gidnumber: u32,

    #[serde(flatten)]
    pub extra_keys: BTreeMap<XKeyId, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserToken {
    #[serde(default)]
    pub provider: ProviderOrigin,

    pub name: String,
    pub spn: String,
    pub uuid: Uuid,
    pub gidnumber: u32,
    pub displayname: String,
    pub shell: Option<String>,
    pub groups: Vec<GroupToken>,

    // Could there be a better type here?
    pub sshkeys: Vec<String>,
    // Defaults to false.
    pub valid: bool,

    // These are opaque extra keys that the provider can interpret for internal
    // functions.
    #[serde(flatten)]
    pub extra_keys: BTreeMap<XKeyId, Value>,
}

#[derive(Debug)]
pub enum AuthCredHandler {
    Password,
    DeviceAuthorizationGrant,
    /// Additional data required by the provider to complete the
    /// authentication, but not required by PAM
    ///
    /// Sadly due to how this is passed around we can't make this a
    /// generic associated type, else it would have to leak up to the
    /// daemon.
    ///
    /// ⚠️  TODO: Optimally this should actually be a tokio oneshot receiver
    /// with the decision from a task that is spawned.
    MFA {
        data: Vec<String>,
    },
    SetupPin,
    Pin,
}

pub enum AuthRequest {
    Password,
    DeviceAuthorizationGrant {
        data: DeviceAuthorizationResponse,
    },
    MFACode {
        msg: String,
    },
    MFAPoll {
        /// Message to display to the user.
        msg: String,
        /// Interval in seconds between poll attempts.
        polling_interval: u32,
    },
    MFAPollWait,
    SetupPin {
        /// Message to display to the user.
        msg: String,
    },
    Pin,
}

#[allow(clippy::from_over_into)]
impl Into<PamAuthResponse> for AuthRequest {
    fn into(self) -> PamAuthResponse {
        match self {
            AuthRequest::Password => PamAuthResponse::Password,
            AuthRequest::DeviceAuthorizationGrant { data } => {
                PamAuthResponse::DeviceAuthorizationGrant { data }
            }
            AuthRequest::MFACode { msg } => PamAuthResponse::MFACode { msg },
            AuthRequest::MFAPoll {
                msg,
                polling_interval,
            } => PamAuthResponse::MFAPoll {
                msg,
                polling_interval,
            },
            AuthRequest::MFAPollWait => PamAuthResponse::MFAPollWait,
            AuthRequest::SetupPin { msg } => PamAuthResponse::SetupPin { msg },
            AuthRequest::Pin => PamAuthResponse::Pin,
        }
    }
}

pub enum AuthResult {
    Success,
    SuccessUpdate { new_token: UserToken },
    Denied,
    Next(AuthRequest),
}

#[async_trait]
#[allow(clippy::too_many_arguments)]
pub trait IdProvider {
    /// Retrieve this providers origin
    fn origin(&self) -> ProviderOrigin;

    /// Attempt to go online *immediately*
    async fn attempt_online(&self, _tpm: &mut BoxedDynTpm, _now: SystemTime) -> bool;

    /// Mark that this provider should attempt to go online next time it
    /// receives a request
    async fn mark_next_check(&self, _now: SystemTime);

    /// Force this provider offline immediately.
    async fn mark_offline(&self);

    /// Determine if this provider has a configured extension of a local system group
    /// with remote members.
    fn has_map_group(&self, local: &str) -> Option<&Id>;

    // This is similar to a "domain join" process. What do we actually need to pass here
    // for this to work for kanidm or himmelblau? Should we make it take a generic?
    /*
    async fn configure_machine_identity(
        &self,
        _keystore: &mut KeyStoreTxn,
        _tpm: &mut BoxedDynTpm,
        _machine_key: &tpm::MachineKey,
    ) -> Result<(), IdpError> {
        Ok(())
    }
    */

    async fn unix_user_get(
        &self,
        _id: &Id,
        _token: Option<&UserToken>,
        _tpm: &mut BoxedDynTpm,
        _now: SystemTime,
    ) -> Result<UserTokenState, IdpError>;

    async fn unix_user_online_auth_init(
        &self,
        _account_id: &str,
        _token: &UserToken,
        _tpm: &mut BoxedDynTpm,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError>;

    async fn unix_user_online_auth_step(
        &self,
        _account_id: &str,
        _current_token: Option<&UserToken>,
        _cred_handler: &mut AuthCredHandler,
        _pam_next_req: PamAuthRequest,
        _tpm: &mut BoxedDynTpm,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<AuthResult, IdpError>;

    async fn unix_unknown_user_online_auth_init(
        &self,
        _account_id: &str,
        _tpm: &mut BoxedDynTpm,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<Option<(AuthRequest, AuthCredHandler)>, IdpError>;

    async fn unix_user_offline_auth_init(
        &self,
        _token: &UserToken,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError>;

    // I thought about this part of the interface a lot. we could have the
    // provider actually need to check the password or credentials, but then
    // we need to rework the tpm/crypto engine to be an argument to pass here
    // as well the cached credentials.
    //
    // As well, since this is "offline auth" the provider isn't really "doing"
    // anything special here - when you say you want offline password auth, the
    // resolver can just do it for you for all the possible implementations.
    // This is similar for offline ctap2 as well, or even offline totp.
    //
    // I think in the future we could reconsider this and let the provider be
    // involved if there is some "custom logic" or similar that is needed but
    // for now I think making it generic is a good first step and we can change
    // it later.
    //
    // EDIT 04042024: When we're performing an offline PIN auth, the PIN can
    // unlock the associated TPM key. While we can't perform a full request
    // for an auth token, we can verify that the PIN successfully unlocks the
    // TPM key.
    async fn unix_user_offline_auth_step(
        &self,
        _current_token: Option<&UserToken>,
        _session_token: &UserToken,
        _cred_handler: &mut AuthCredHandler,
        _pam_next_req: PamAuthRequest,
        _tpm: &mut BoxedDynTpm,
    ) -> Result<AuthResult, IdpError>;

    async fn unix_user_authorise(&self, _token: &UserToken) -> Result<Option<bool>, IdpError>;

    async fn unix_group_get(
        &self,
        id: &Id,
        _tpm: &mut BoxedDynTpm,
        _now: SystemTime,
    ) -> Result<GroupTokenState, IdpError>;
}
