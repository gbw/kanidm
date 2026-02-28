use serde::{Deserialize, Serialize};

#[derive(PartialEq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProfileMenuItems {
    UserProfile,
    Credentials,
    EnrolDevice,
    UnixPassword,
    Radius,
}

// pub(crate) enum UiMessage {
//     UnlockEdit,
// }
//
// impl std::fmt::Display for UiMessage {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         match self {
//             UiMessage::UnlockEdit => write!(f, "Unlock Edit 🔒"),
//         }
//     }
// }

pub(crate) enum Urls {
    Apps,
    CredReset,
    EnrolDevice,
    Profile,
    UpdateCredentials,
    Oauth2Resume,
    #[cfg(feature = "dev-oauth2-device-flow")]
    Oauth2DeviceResume,
    #[cfg(feature = "dev-oauth2-device-flow")]
    Oauth2Device,
    Login,
    Ui,
    WellKnownChangePassword,
    Radius,
    Admin,
}

impl AsRef<str> for Urls {
    fn as_ref(&self) -> &str {
        match self {
            Self::Apps => "/ui/apps",
            Self::CredReset => "/ui/reset",
            Self::EnrolDevice => "/ui/enrol",
            Self::Profile => "/ui/profile",
            Self::UpdateCredentials => "/ui/update_credentials",
            Self::Oauth2Resume => "/ui/oauth2/resume",
            #[cfg(feature = "dev-oauth2-device-flow")]
            Self::Oauth2DeviceResume => "/ui/oauth2/device/resume",
            #[cfg(feature = "dev-oauth2-device-flow")]
            Self::Oauth2Device => "/ui/oauth2/device",
            Self::Login => "/ui/login",
            Self::Ui => "/ui",
            Self::WellKnownChangePassword => "/.well-known/change-password",
            Self::Radius => "/ui/radius",
            Self::Admin => "/ui/admin/persons",
        }
    }
}

impl std::fmt::Display for Urls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl Urls {
    /// Returns the route path without the `/ui` prefix.
    /// This is useful when defining routes in a router that is already mounted at `/ui`.
    #[cfg(feature = "dev-oauth2-device-flow")]
    pub(crate) const fn as_route(&self) -> &'static str {
        match self {
            Self::Oauth2Device => "/oauth2/device",
            Self::Oauth2DeviceResume => "/oauth2/device/resume",
            // These should not be used with as_route, but we need to handle all variants
            Self::Apps => "/apps",
            Self::CredReset => "/reset",
            Self::EnrolDevice => "/enrol",
            Self::Profile => "/profile",
            Self::UpdateCredentials => "/update_credentials",
            Self::Oauth2Resume => "/oauth2/resume",
            Self::Login => "/login",
            Self::Ui => "",
            Self::WellKnownChangePassword => "/.well-known/change-password",
            Self::Radius => "/radius",
            Self::Admin => "/admin/persons",
        }
    }
}
