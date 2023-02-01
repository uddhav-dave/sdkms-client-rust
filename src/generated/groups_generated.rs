/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;

#[derive(PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Clone)]
pub enum AwskmsRegion {
    #[serde(rename = "us-east-1")]
    UsEast1,
    #[serde(rename = "us-east-2")]
    UsEast2,
    #[serde(rename = "us-west-1")]
    UsWest1,
    #[serde(rename = "us-west-2")]
    UsWest2,
    #[serde(rename = "af-south-1")]
    AfSouth1,
    #[serde(rename = "ap-east-1")]
    ApEast1,
    #[serde(rename = "ap-southeast-3")]
    ApSoutheast3,
    #[serde(rename = "ap-south-1")]
    ApSouth1,
    #[serde(rename = "ap-northeast-3")]
    ApNortheast3,
    #[serde(rename = "ap-northeast-2")]
    ApNortheast2,
    #[serde(rename = "ap-southeast-1")]
    ApSoutheast1,
    #[serde(rename = "ap-southeast-2")]
    ApSoutheast2,
    #[serde(rename = "ap-northeast-1")]
    ApNortheast1,
    #[serde(rename = "ca-central-1")]
    CaCentral1,
    #[serde(rename = "eu-central-1")]
    EuCentral1,
    #[serde(rename = "eu-west-1")]
    EuWest1,
    #[serde(rename = "eu-west-2")]
    EuWest2,
    #[serde(rename = "eu-south-1")]
    EuSouth1,
    #[serde(rename = "eu-west-3")]
    EuWest3,
    #[serde(rename = "eu-north-1")]
    EuNorth1,
    #[serde(rename = "me-south-1")]
    MeSouth1,
    #[serde(rename = "sa-east-1")]
    SaEast1,
    #[serde(rename = "us-gov-east-1")]
    UsGovEast1,
    #[serde(rename = "us-gov-west-1")]
    UsGovWest1
}

#[derive(PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum AwskmsService {
    Kms,
    KmsFips
}

#[derive(Debug, Eq, PartialEq, Copy, Hash, Serialize, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum AzureKeyVaultType {
    Standard,
    Premium,
    Managed
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct CheckHmgRequest {
    /// The ID of the hmg configuration in the group.
    pub id: Option<Uuid>,
    pub config: Option<HmgConfig>
}

#[derive(PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Clone)]
pub struct GcpKeyRingConfig {
    pub service_account_email: String,
    pub project_id: String,
    pub location: String,
    pub key_ring: Option<String>,
    pub private_key: Option<Blob>
}

/// Information about a group's recent scans.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct GetAllHmgScansResponse {
    /// List of all tracked scans, from newest to oldest.
    pub items: Vec<Scan>
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GetGroupsParams {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(flatten)]
    pub sort_by: Option<GroupSort>,
    #[serde(default)]
    pub filter: Option<String>
}

impl UrlEncode for GetGroupsParams {
    fn url_encode(&self, m: &mut HashMap<String, String>) {
        if let Some(ref v) = self.limit {
            m.insert("limit".to_string(), v.to_string());
        }
        self.sort_by.url_encode(m);
        if let Some(ref v) = self.filter {
            m.insert("filter".to_string(), v.to_string());
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Group {
    pub acct_id: Uuid,
    #[serde(default)]
    pub approval_policy: Option<GroupApprovalPolicy>,
    /// Settings for automatic key scanning. For now, this is only available for DSM-backed groups.
    #[serde(default)]
    pub auto_scan: Option<HmgAutoScan>,
    pub client_configurations: ClientConfigurations,
    pub created_at: Time,
    pub creator: Principal,
    #[serde(default)]
    pub cryptographic_policy: Option<CryptographicPolicy>,
    #[serde(default)]
    pub custodian_policy: Option<QuorumPolicy>,
    #[serde(default)]
    pub custom_metadata: Option<HashMap<String,String>>,
    #[serde(default)]
    pub description: Option<String>,
    pub group_id: Uuid,
    #[serde(default)]
    pub hmg: Option<HashMap<Uuid,HmgConfig>>,
    #[serde(default)]
    pub hmg_redundancy: Option<HmgRedundancyScheme>,
    #[serde(default)]
    pub hmg_segregation: Option<bool>,
    #[serde(default)]
    pub hmg_sync: Option<bool>,
    #[serde(default)]
    pub key_history_policy: Option<KeyHistoryPolicy>,
    #[serde(default)]
    pub key_metadata_policy: Option<KeyMetadataPolicy>,
    pub name: String,
    /// Name of an AES key from another group. The key will be used to encrypt the key material of all keys in this group
    #[serde(default)]
    pub wrapping_key_name: Option<WrappingKeyName>
}

/// Group approval policy.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct GroupApprovalPolicy {
    #[serde(flatten)]
    pub policy: QuorumPolicy,
    /// Deprecated, left this for backward compatibility.
    /// When this is true, manage operations on security objects require approval.
    #[serde(default)]
    pub protect_manage_operations: Option<bool>,
    /// Use QuorumGroupPermissions to represent operations that require approval.
    pub protect_permissions: Option<QuorumGroupPermissions>,
    /// When this is true, cryptographic operations on security objects require approval.
    pub protect_crypto_operations: Option<bool>
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct GroupRequest {
    #[serde(default)]
    pub add_hmg: Option<Vec<HmgConfig>>,
    #[serde(default)]
    pub approval_policy: Option<GroupApprovalPolicy>,
    /// Settings for automatic key scanning. For now, this is only available for DSM-backed groups.
    #[serde(default)]
    pub auto_scan: Option<Removable<HmgAutoScan>>,
    #[serde(default)]
    pub client_configurations: Option<ClientConfigurationsRequest>,
    #[serde(default)]
    pub cryptographic_policy: Option<Removable<CryptographicPolicy>>,
    #[serde(default)]
    pub custodian_policy: Option<QuorumPolicy>,
    #[serde(default)]
    pub custom_metadata: Option<HashMap<String,String>>,
    #[serde(default)]
    pub del_hmg: Option<HashSet<Uuid>>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub hmg_redundancy: Option<HmgRedundancyScheme>,
    #[serde(default)]
    pub hmg_segregation: Option<bool>,
    #[serde(default)]
    pub hmg_sync: Option<bool>,
    #[serde(default)]
    pub key_history_policy: Option<Removable<KeyHistoryPolicy>>,
    #[serde(default)]
    pub key_metadata_policy: Option<Removable<KeyMetadataPolicy>>,
    #[serde(default)]
    pub mod_hmg: Option<HashMap<Uuid,HmgConfig>>,
    #[serde(default)]
    pub name: Option<String>,
    /// Name of an AES key from another group. The key will be used to encrypt the key material of all keys in this group
    #[serde(default)]
    pub wrapping_key_name: Option<WrappingKeyName>
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub enum GroupSort {
    ByGroupId {
        order: Order,
        start: Option<Uuid>
    }
}

impl UrlEncode for GroupSort {
    fn url_encode(&self, m: &mut HashMap<String, String>) {
        match *self {
            GroupSort::ByGroupId{ ref order, ref start } => {
                m.insert("sort".to_string(), format!("group_id:{}", order));
                if let Some(v) = start {
                    m.insert("start".to_string(), v.to_string());
                }
            }
        }
    }
}

/// Settings for automatic scanning in externally-backed groups. Today, this is only
/// applicable for DSM-backed groups.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct HmgAutoScan {
    /// The number of hours between successive automatic scans. Must be greater than 0.
    pub scan_interval_hours: u8
}

#[derive(PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "kind")]
pub enum HmgConfig {
    Ncipher {
        url: String,
        tls: TlsConfig,
        slot: usize,
        #[serde(default)]
        pin: Option<String>,
        #[serde(default)]
        hsm_order: Option<i32>
    },
    Safenet {
        url: String,
        tls: TlsConfig,
        slot: usize,
        #[serde(default)]
        pin: Option<String>,
        #[serde(default)]
        hsm_order: Option<i32>
    },
    AwsCloudHsm {
        url: String,
        tls: TlsConfig,
        slot: usize,
        #[serde(default)]
        pin: Option<String>,
        #[serde(default)]
        hsm_order: Option<i32>
    },
    AwsKms {
        url: String,
        tls: TlsConfig,
        #[serde(default)]
        access_key: Option<String>,
        #[serde(default)]
        secret_key: Option<String>,
        #[serde(default)]
        region: Option<AwskmsRegion>,
        #[serde(default)]
        service: Option<AwskmsService>
    },
    Fortanix {
        url: String,
        tls: TlsConfig,
        #[serde(default)]
        pin: Option<String>
    },
    FortanixFipsCluster {
        url: String,
        tls: TlsConfig,
        #[serde(default)]
        pin: Option<String>,
        #[serde(default)]
        credentials: Option<Vec<String>>
    },
    AzureKeyVault {
        url: String,
        tls: TlsConfig,
        #[serde(default)]
        secret_key: Option<String>,
        tenant_id: Uuid,
        client_id: Uuid,
        subscription_id: Uuid,
        #[serde(default)]
        key_vault_type: Option<AzureKeyVaultType>
    },
    GcpKeyRing (
        GcpKeyRingConfig
    )
}

#[derive(Eq, Debug, PartialEq, Hash, Copy, Serialize, Deserialize, Clone)]
pub enum HmgRedundancyScheme {
    PriorityFailover
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyVault {
    pub id: String,
    pub name: String,
    pub vault_type: AzureKeyVaultType,
    pub location: String,
    #[serde(default)]
    pub tags: Option<HashMap<String,String>>,
    #[serde(default)]
    pub retention: Option<u32>,
    pub uri: String
}

/// Subset of GroupPermissions to represent GroupPermissions flags in use
pub use self::quorum_group_permissions::QuorumGroupPermissions;
pub mod quorum_group_permissions {
    bitflags_set!{
        pub struct QuorumGroupPermissions: u64 {
            const GET_SOBJECTS = 0x0000000000000001;
            const ROTATE_SOBJECTS = 0x0000000000000002;
            const REVOKE_SOBJECTS = 0x0000000000000004;
            const REVERT_SOBJECTS = 0x0000000000000008;
            const DELETE_KEY_MATERIAL = 0x0000000000000010;
            const DELETE_SOBJECTS = 0x0000000000000020;
            const DESTROY_SOBJECTS = 0x0000000000000040;
            const MOVE_SOBJECTS = 0x0000000000000080;
            const CREATE_SOBJECTS = 0x0000000000000100;
            const UPDATE_SOBJECTS_PROFILE = 0x0000000000000200;
            const UPDATE_SOBJECTS_ENABLED_STATE = 0x0000000000000400;
            const UPDATE_SOBJECT_POLICIES = 0x0000000000000800;
            const ACTIVATE_SOBJECTS = 0x0000000000001000;
            const UPDATE_KEY_OPS = 0x0000000000002000;
        }
    }
}

/// An object for representing a scan of objects from a source HSM,
/// DSM cluster, or cloud KMS.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct Scan {
    /// The ID of the scan.
    pub scan_id: Uuid,
    /// Whether the scan is async or not.
    pub is_async: bool,
    /// The time the scan began.
    pub started_at: Time,
    /// The time the scan finished.
    #[serde(default)]
    pub finished_at: Option<Time>,
    /// The "return status" of the scan.
    #[serde(default)]
    pub scan_result: Option<ScanResult>,
    /// Any warnings thrown during the scan.
    #[serde(default)]
    pub warnings: Option<Vec<ScanWarning>>
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct ScanHmgRequest {

}

/// The result of a scan.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(tag = "$type", rename = "snake_case")]
pub enum ScanResult {
    /// Indicates that a scan completed successfully.
    Success,
    /// Indicates that a scan has failed. The most recent error is included
    /// (taken from the last retry).
    Failed {
        message: String
    }
}

/// A warning "thrown" by a scan.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct ScanWarning {
    /// The ID of the source key for which the warning applies to.
    #[serde(default)]
    pub source_key_id: Option<Uuid>,
    /// The ID of the virtual key for which the warning applies to.
    #[serde(default)]
    pub virtual_key_id: Option<Uuid>,
    /// The warning message associated with the warning.
    pub message: String
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum WrappingKeyName {
    Null,
    Value (
        String
    )
}

pub struct OperationAsyncScanHmg;
#[allow(unused)]
impl Operation for OperationAsyncScanHmg {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = Scan;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/{id}/hmg/scans", id = p.0)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn async_scan_hmg(&self, id: &Uuid) -> Result<Scan> {
        self.execute::<OperationAsyncScanHmg>(&(), (id,), None).await
    }
}

pub struct OperationCheckHmg;
#[allow(unused)]
impl Operation for OperationCheckHmg {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = CheckHmgRequest;
    type Output = ();

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/{id}/hmg/check", id = p.0)
    }
}

impl SdkmsClient {
    pub async fn check_hmg(&self, id: &Uuid, req: &CheckHmgRequest) -> Result<()> {
        self.execute::<OperationCheckHmg>(req, (id,), None).await
    }
}

pub struct OperationCheckHmgConfig;
#[allow(unused)]
impl Operation for OperationCheckHmgConfig {
    type PathParams = ();
    type QueryParams = ();
    type Body = HmgConfig;
    type Output = ();

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/hmg/check")
    }
}

impl SdkmsClient {
    pub async fn check_hmg_config(&self, req: &HmgConfig) -> Result<()> {
        self.execute::<OperationCheckHmgConfig>(req, (), None).await
    }
}

pub struct OperationCreateGroup;
#[allow(unused)]
impl Operation for OperationCreateGroup {
    type PathParams = ();
    type QueryParams = ();
    type Body = GroupRequest;
    type Output = Group;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups")
    }
}

impl SdkmsClient {
    pub async fn create_group(&self, req: &GroupRequest) -> Result<Group> {
        self.execute::<OperationCreateGroup>(req, (), None).await
    }
    pub async fn request_approval_to_create_group(
        &self, req: &GroupRequest,
        description: Option<String>) -> Result<PendingApproval<OperationCreateGroup>> {
        self.request_approval::<OperationCreateGroup>(req, (), None, description).await
    }
}

pub struct OperationDeleteGroup;
#[allow(unused)]
impl Operation for OperationDeleteGroup {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = ();

    fn method() -> Method {
        Method::DELETE
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/{id}", id = p.0)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn delete_group(&self, id: &Uuid) -> Result<()> {
        self.execute::<OperationDeleteGroup>(&(), (id,), None).await
    }
}

pub struct OperationGetAllHmgScans;
#[allow(unused)]
impl Operation for OperationGetAllHmgScans {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = GetAllHmgScansResponse;

    fn method() -> Method {
        Method::GET
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/{id}/hmg/scans", id = p.0)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn get_all_hmg_scans(&self, id: &Uuid) -> Result<GetAllHmgScansResponse> {
        self.execute::<OperationGetAllHmgScans>(&(), (id,), None).await
    }
}

pub struct OperationGetGcpKeyRings;
#[allow(unused)]
impl Operation for OperationGetGcpKeyRings {
    type PathParams = ();
    type QueryParams = ();
    type Body = GcpKeyRingConfig;
    type Output = Vec<String>;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/hmg/gcp_key_rings")
    }
}

impl SdkmsClient {
    pub async fn get_gcp_key_rings(&self, req: &GcpKeyRingConfig) -> Result<Vec<String>> {
        self.execute::<OperationGetGcpKeyRings>(req, (), None).await
    }
}

pub struct OperationGetGroup;
#[allow(unused)]
impl Operation for OperationGetGroup {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = Group;

    fn method() -> Method {
        Method::GET
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/{id}", id = p.0)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn get_group(&self, id: &Uuid) -> Result<Group> {
        self.execute::<OperationGetGroup>(&(), (id,), None).await
    }
}

pub struct OperationGetScan;
#[allow(unused)]
impl Operation for OperationGetScan {
    type PathParams = (Uuid, Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = Scan;

    fn method() -> Method {
        Method::GET
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/{id}/hmg/scans/{scan_id}", id = p.0, scan_id = p.1)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn get_scan(&self, id: &Uuid, scan_id: &Uuid) -> Result<Scan> {
        self.execute::<OperationGetScan>(&(), (id, scan_id,), None).await
    }
}

pub struct OperationGetVaults;
#[allow(unused)]
impl Operation for OperationGetVaults {
    type PathParams = ();
    type QueryParams = ();
    type Body = HmgConfig;
    type Output = Vec<KeyVault>;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/hmg/azure_vaults")
    }
}

impl SdkmsClient {
    pub async fn get_vaults(&self, req: &HmgConfig) -> Result<Vec<KeyVault>> {
        self.execute::<OperationGetVaults>(req, (), None).await
    }
}

pub struct OperationListGroups;
#[allow(unused)]
impl Operation for OperationListGroups {
    type PathParams = ();
    type QueryParams = GetGroupsParams;
    type Body = ();
    type Output = Vec<Group>;

    fn method() -> Method {
        Method::GET
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups?{q}", q = q.encode())
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn list_groups(&self, query_params: Option<&GetGroupsParams>) -> Result<Vec<Group>> {
        self.execute::<OperationListGroups>(&(), (), query_params).await
    }
}

pub struct OperationScanHmg;
#[allow(unused)]
impl Operation for OperationScanHmg {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ScanHmgRequest;
    type Output = Vec<Sobject>;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/{id}/hmg/scan", id = p.0)
    }
}

impl SdkmsClient {
    pub async fn scan_hmg(&self, id: &Uuid, req: &ScanHmgRequest) -> Result<Vec<Sobject>> {
        self.execute::<OperationScanHmg>(req, (id,), None).await
    }
}

pub struct OperationUpdateGroup;
#[allow(unused)]
impl Operation for OperationUpdateGroup {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = GroupRequest;
    type Output = Group;

    fn method() -> Method {
        Method::PATCH
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/{id}", id = p.0)
    }
}

impl SdkmsClient {
    pub async fn update_group(&self, id: &Uuid, req: &GroupRequest) -> Result<Group> {
        self.execute::<OperationUpdateGroup>(req, (id,), None).await
    }
    pub async fn request_approval_to_update_group(
        &self, id: &Uuid, req: &GroupRequest,
        description: Option<String>) -> Result<PendingApproval<OperationUpdateGroup>> {
        self.request_approval::<OperationUpdateGroup>(req, (id,), None, description).await
    }
}

