/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;

/// This represents the authenticator's response to a client’s request
/// for the creation of a new public key credential. It contains
/// information about the new credential that can be used to identify
/// it for later use, and metadata that can be used by the WebAuthn
/// Relying Party to assess the characteristics of the credential during
/// registration.
///
/// <https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse>
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAttestationResponse {
    /// Base64url of [crate::fido2::models::CollectedClientData] in JSON form.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Base64<UrlSafe>,
    /// Values obtained from `AuthenticatorAttestationResponse.getTransports()`.
    /// Webauthn spec recommends RP to store it and user them along with
    /// `allowCredentials` while authentication ceremony.
    pub get_transports: Option<Vec<AuthenticatorTransport>>,
    /// Base64url of [crate::fido2::models::AttestationObject].
    ///
    /// See in order:
    /// <https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-attestationobject>
    /// <https://www.w3.org/TR/webauthn-2/#sctn-attestation>
    /// <https://www.w3.org/TR/webauthn-2/#sctn-defined-attestation-formats>
    ///
    /// Currently, only U2F is supported, others will be rejected.
    pub attestation_object: Base64<UrlSafe>
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct ConfirmEmailRequest {
    pub confirm_token: String
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct ConfirmEmailResponse {
    pub user_email: String
}

/// This contains the request for adding a FIDO device
/// to user's data.
/// Initially, `POST /sys/v1/session/config_2fa/new_challenge` needs
/// to be called with protocol set to `fido2` and using that data,
/// `navigator.credentials.create()` is called in the frontend.
/// The data returned by `create` is sent in this request. The data
/// sent back here creates a new FIDO2 device for the user after
/// the payload is verified as per the rules stated in webauthn doc.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FidoAddDeviceRequest {
    /// A user friendly name for the device.
    pub name: String,
    /// Result of calling `navigator.credentials.create()` with the
    /// data obtained from `new_challenge` API.
    pub attestation_result: PublicKeyCredential<AuthenticatorAttestationResponse>
}

/// Initiate password reset sequence.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ForgotPasswordRequest {
    pub user_email: String
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GetUserPermissionsParams {
    /// If `true`, implied permissions are added in the output. For example, if
    /// permission A implies permission B, and the user has permission A, the
    /// output will include both A and B if this is set to `true`. If this is
    /// set to `false`, B will only be returned if it was assigned to the user
    /// directly.
    pub with_implied: Option<bool>
}

impl UrlEncode for GetUserPermissionsParams {
    fn url_encode(&self, m: &mut HashMap<String, String>) {
        if let Some(ref v) = self.with_implied {
            m.insert("with_implied".to_string(), v.to_string());
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetUserPermissionsResponse {
    /// User's permissions in the account.
    pub account: AccountPermissions,
    /// User's permissions in all groups. Note that this will only be returned
    /// if the user has one or more all-groups roles.
    #[serde(default)]
    pub all_groups: Option<GroupPermissions>,
    /// User's permissions in groups.
    pub groups: HashMap<Uuid,GroupPermissions>
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ListUsersParams {
    pub group_id: Option<Uuid>,
    pub acct_id: Option<Uuid>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    #[serde(flatten)]
    pub sort: UserSort
}

impl UrlEncode for ListUsersParams {
    fn url_encode(&self, m: &mut HashMap<String, String>) {
        if let Some(ref v) = self.group_id {
            m.insert("group_id".to_string(), v.to_string());
        }
        if let Some(ref v) = self.acct_id {
            m.insert("acct_id".to_string(), v.to_string());
        }
        if let Some(ref v) = self.limit {
            m.insert("limit".to_string(), v.to_string());
        }
        if let Some(ref v) = self.offset {
            m.insert("offset".to_string(), v.to_string());
        }
        self.sort.url_encode(m);
    }
}

/// Request to delete a FIDO device.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct MfaDelDeviceRequest {
    /// Name of the FIDO device to delete.
    pub name: String
}

/// A FIDO device that may be used for second factor authentication.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct MfaDevice {
    /// Name given to the FIDO device.
    pub name: String
}

/// Request to rename a FIDO device.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct MfaRenameDeviceRequest {
    /// Old name of FIDO device.
    pub old_name: String,
    /// New name of FIDO device.
    pub new_name: String
}

/// Request to change user's password.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PasswordChangeRequest {
    pub current_password: String,
    pub new_password: String
}

/// Request to perform a password reset.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PasswordResetRequest {
    pub reset_token: String,
    pub new_password: String
}

/// Accept/reject invitations to join account.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessInviteRequest {
    /// Optional list of account IDs to accept.
    #[serde(default)]
    pub accepts: Option<HashSet<Uuid>>,
    /// Optional list of account IDs to reject.
    #[serde(default)]
    pub rejects: Option<HashSet<Uuid>>
}

/// U2F recovery codes.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct RecoveryCodes {
    pub recovery_codes: Vec<String>
}

/// Request to signup a new user.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignupRequest {
    pub user_email: String,
    pub user_password: String,
    #[serde(default)]
    pub recaptcha_response: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>
}

/// Description of a U2F device to add for two factor authentication.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct U2fAddDeviceRequest {
    pub name: String,
    pub registration_data: Blob,
    pub client_data: Blob,
    pub version: String
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct User {
    pub account_role: UserAccountFlags,
    #[serde(default)]
    pub created_at: Option<Time>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// Explicit group assignments.
    /// 
    /// This is similar to `groups` field except that it does not include groups due to
    /// all-groups roles. Use this field to find out which group assignments can be
    /// changed using `mod_groups` and `del_groups` fields in user update API.
    pub explicit_groups: HashMap<Uuid,UserGroupRole>,
    #[serde(default)]
    pub first_name: Option<String>,
    pub groups: HashMap<Uuid,UserGroupRole>,
    #[serde(default)]
    pub has_account: Option<bool>,
    #[serde(default)]
    pub has_password: Option<bool>,
    #[serde(default)]
    pub last_logged_in_at: Option<Time>,
    #[serde(default)]
    pub last_name: Option<String>,
    /// Mfa devices registered with the user
    pub mfa_devices: Vec<MfaDevice>,
    #[serde(default)]
    pub new_email: Option<String>,
    #[serde(default)]
    pub self_provisioned: Option<bool>,
    pub u2f_devices: Vec<MfaDevice>,
    #[serde(default)]
    pub user_email: Option<String>,
    pub user_id: Uuid
}

#[derive(Default, Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct UserRequest {
    #[serde(default)]
    pub account_role: Option<UserAccountFlags>,
    #[serde(default)]
    pub add_groups: Option<HashMap<Uuid,UserGroupRole>>,
    /// FIDO devices to add. Only one device can be added at present.
    #[serde(default)]
    pub add_mfa_devices: Option<Vec<FidoAddDeviceRequest>>,
    #[serde(default)]
    pub add_u2f_devices: Option<Vec<U2fAddDeviceRequest>>,
    #[serde(default)]
    pub del_groups: Option<HashMap<Uuid,UserGroupRole>>,
    /// Mfa devices to delete
    #[serde(default)]
    pub del_mfa_devices: Option<Vec<MfaDelDeviceRequest>>,
    #[serde(default)]
    pub del_u2f_devices: Option<Vec<MfaDelDeviceRequest>>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub mod_groups: Option<HashMap<Uuid,UserGroupRole>>,
    /// Mfa devices to rename
    #[serde(default)]
    pub rename_mfa_devices: Option<Vec<MfaRenameDeviceRequest>>,
    #[serde(default)]
    pub rename_u2f_devices: Option<Vec<MfaRenameDeviceRequest>>,
    #[serde(default)]
    pub user_email: Option<String>,
    #[serde(default)]
    pub user_password: Option<String>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum UserSort {
    ByUserId {
        order: Order,
        start: Option<Uuid>
    }
}

impl UrlEncode for UserSort {
    fn url_encode(&self, m: &mut HashMap<String, String>) {
        match *self {
            UserSort::ByUserId{ ref order, ref start } => {
                m.insert("sort".to_string(), format!("user_id:{}", order));
                if let Some(v) = start {
                    m.insert("start".to_string(), v.to_string());
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValidateTokenRequest {
    pub reset_token: String
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValidateTokenResponse {
    pub user_email: String
}

pub struct OperationChangePassword;
#[allow(unused)]
impl Operation for OperationChangePassword {
    type PathParams = ();
    type QueryParams = ();
    type Body = PasswordChangeRequest;
    type Output = ();

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/change_password")
    }
}

impl SdkmsClient {
    pub async fn change_password(&self, req: &PasswordChangeRequest) -> Result<()> {
        self.execute::<OperationChangePassword>(req, (), None).await
    }
}

pub struct OperationConfirmEmail;
#[allow(unused)]
impl Operation for OperationConfirmEmail {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ConfirmEmailRequest;
    type Output = ConfirmEmailResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/{id}/confirm_email", id = p.0)
    }
}

impl SdkmsClient {
    pub async fn confirm_email(&self, id: &Uuid, req: &ConfirmEmailRequest) -> Result<ConfirmEmailResponse> {
        self.execute::<OperationConfirmEmail>(req, (id,), None).await
    }
}

pub struct OperationDeleteStale;
#[allow(unused)]
impl Operation for OperationDeleteStale {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = ();

    fn method() -> Method {
        Method::DELETE
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/{id}", id = p.0)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn delete_stale(&self, id: &Uuid) -> Result<()> {
        self.execute::<OperationDeleteStale>(&(), (id,), None).await
    }
}

pub struct OperationDeleteUser;
#[allow(unused)]
impl Operation for OperationDeleteUser {
    type PathParams = ();
    type QueryParams = ();
    type Body = ();
    type Output = ();

    fn method() -> Method {
        Method::DELETE
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users")
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn delete_user(&self) -> Result<()> {
        self.execute::<OperationDeleteUser>(&(), (), None).await
    }
}

pub struct OperationDeleteUserAccount;
#[allow(unused)]
impl Operation for OperationDeleteUserAccount {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = ();

    fn method() -> Method {
        Method::DELETE
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/{id}/accounts", id = p.0)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn delete_user_account(&self, id: &Uuid) -> Result<()> {
        self.execute::<OperationDeleteUserAccount>(&(), (id,), None).await
    }
}

pub struct OperationForgotPassword;
#[allow(unused)]
impl Operation for OperationForgotPassword {
    type PathParams = ();
    type QueryParams = ();
    type Body = ForgotPasswordRequest;
    type Output = ();

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/forgot_password")
    }
}

impl SdkmsClient {
    pub async fn forgot_password(&self, req: &ForgotPasswordRequest) -> Result<()> {
        self.execute::<OperationForgotPassword>(req, (), None).await
    }
}

pub struct OperationGenerateRecoveryCodes;
#[allow(unused)]
impl Operation for OperationGenerateRecoveryCodes {
    type PathParams = ();
    type QueryParams = ();
    type Body = ();
    type Output = RecoveryCodes;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/generate_recovery_codes")
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn generate_recovery_codes(&self) -> Result<RecoveryCodes> {
        self.execute::<OperationGenerateRecoveryCodes>(&(), (), None).await
    }
}

pub struct OperationGetUser;
#[allow(unused)]
impl Operation for OperationGetUser {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = User;

    fn method() -> Method {
        Method::GET
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/{id}", id = p.0)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn get_user(&self, id: &Uuid) -> Result<User> {
        self.execute::<OperationGetUser>(&(), (id,), None).await
    }
}

pub struct OperationGetUserAccounts;
#[allow(unused)]
impl Operation for OperationGetUserAccounts {
    type PathParams = ();
    type QueryParams = ();
    type Body = ();
    type Output = HashMap<Uuid,UserAccountFlags>;

    fn method() -> Method {
        Method::GET
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/accounts")
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn get_user_accounts(&self) -> Result<HashMap<Uuid,UserAccountFlags>> {
        self.execute::<OperationGetUserAccounts>(&(), (), None).await
    }
}

pub struct OperationGetUserPermissions;
#[allow(unused)]
impl Operation for OperationGetUserPermissions {
    type PathParams = ();
    type QueryParams = GetUserPermissionsParams;
    type Body = ();
    type Output = GetUserPermissionsResponse;

    fn method() -> Method {
        Method::GET
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/permissions?{q}", q = q.encode())
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn get_user_permissions(&self, query_params: Option<&GetUserPermissionsParams>) -> Result<GetUserPermissionsResponse> {
        self.execute::<OperationGetUserPermissions>(&(), (), query_params).await
    }
}

pub struct OperationInviteUser;
#[allow(unused)]
impl Operation for OperationInviteUser {
    type PathParams = ();
    type QueryParams = ();
    type Body = UserRequest;
    type Output = User;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/invite")
    }
}

impl SdkmsClient {
    pub async fn invite_user(&self, req: &UserRequest) -> Result<User> {
        self.execute::<OperationInviteUser>(req, (), None).await
    }
}

pub struct OperationListUsers;
#[allow(unused)]
impl Operation for OperationListUsers {
    type PathParams = ();
    type QueryParams = ListUsersParams;
    type Body = ();
    type Output = Vec<User>;

    fn method() -> Method {
        Method::GET
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users?{q}", q = q.encode())
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn list_users(&self, query_params: Option<&ListUsersParams>) -> Result<Vec<User>> {
        self.execute::<OperationListUsers>(&(), (), query_params).await
    }
}

pub struct OperationProcessInvite;
#[allow(unused)]
impl Operation for OperationProcessInvite {
    type PathParams = ();
    type QueryParams = ();
    type Body = ProcessInviteRequest;
    type Output = ();

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/process_invite")
    }
}

impl SdkmsClient {
    pub async fn process_invite(&self, req: &ProcessInviteRequest) -> Result<()> {
        self.execute::<OperationProcessInvite>(req, (), None).await
    }
}

pub struct OperationResendConfirmEmail;
#[allow(unused)]
impl Operation for OperationResendConfirmEmail {
    type PathParams = ();
    type QueryParams = ();
    type Body = ();
    type Output = ();

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/resend_confirm_email")
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn resend_confirm_email(&self) -> Result<()> {
        self.execute::<OperationResendConfirmEmail>(&(), (), None).await
    }
}

pub struct OperationResendInvite;
#[allow(unused)]
impl Operation for OperationResendInvite {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = ();

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/{id}/resend_invite", id = p.0)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn resend_invite(&self, id: &Uuid) -> Result<()> {
        self.execute::<OperationResendInvite>(&(), (id,), None).await
    }
}

pub struct OperationResetPassword;
#[allow(unused)]
impl Operation for OperationResetPassword {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = PasswordResetRequest;
    type Output = ();

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/{id}/reset_password", id = p.0)
    }
}

impl SdkmsClient {
    pub async fn reset_password(&self, id: &Uuid, req: &PasswordResetRequest) -> Result<()> {
        self.execute::<OperationResetPassword>(req, (id,), None).await
    }
}

pub struct OperationSignupUser;
#[allow(unused)]
impl Operation for OperationSignupUser {
    type PathParams = ();
    type QueryParams = ();
    type Body = SignupRequest;
    type Output = User;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users")
    }
}

impl SdkmsClient {
    pub async fn signup_user(&self, req: &SignupRequest) -> Result<User> {
        self.execute::<OperationSignupUser>(req, (), None).await
    }
}

pub struct OperationUpdateUser;
#[allow(unused)]
impl Operation for OperationUpdateUser {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = UserRequest;
    type Output = User;

    fn method() -> Method {
        Method::PATCH
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/{id}", id = p.0)
    }
}

impl SdkmsClient {
    pub async fn update_user(&self, id: &Uuid, req: &UserRequest) -> Result<User> {
        self.execute::<OperationUpdateUser>(req, (id,), None).await
    }
}

pub struct OperationValidateToken;
#[allow(unused)]
impl Operation for OperationValidateToken {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ValidateTokenRequest;
    type Output = ValidateTokenResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/users/{id}/validate_token", id = p.0)
    }
}

impl SdkmsClient {
    pub async fn validate_token(&self, id: &Uuid, req: &ValidateTokenRequest) -> Result<ValidateTokenResponse> {
        self.execute::<OperationValidateToken>(req, (id,), None).await
    }
}

