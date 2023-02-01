/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;

#[derive(Ord, PartialOrd, Debug, Eq, PartialEq, Hash, Copy, Serialize, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum ActionType {
    Administrative,
    Auth,
    CryptoOperation,
    RunPlugin,
    Custom,
    Other
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EsAuditLog {
    pub action_type: ActionType,
    pub actor_type: String,
    pub message: String,
    pub severity: SeverityLevel,
    pub time: AuditLogTime,
    pub acct_id: Uuid,
    pub actor_id: Uuid,
    pub group_ids: Vec<Uuid>,
    pub object_id: Uuid,
    pub client_ip: Option<IpAddr>,
    pub response_time: Option<Duration>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EsAuditLogOuter {
    pub _id: String,
    pub _source: EsAuditLog
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EsAuditQueryResponse {
    pub hits: Vec<EsAuditLogOuter>
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct LogsParams {
    /// The input `size` value can't be greater than 1000. If a higher
    /// value is specifed, only 1000 results are returned.
    pub size: Option<u32>,
    pub from: Option<u32>,
    pub range_from: Option<u64>,
    pub range_to: Option<u64>,
    pub action_type: Option<Vec<ActionType>>,
    pub actor_type: Option<Vec<String>>,
    pub actor_id: Option<Uuid>,
    pub object_id: Option<Uuid>,
    pub previous_id: Option<Uuid>,
    pub severity: Option<Vec<SeverityLevel>>
}

impl UrlEncode for LogsParams {
    fn url_encode(&self, m: &mut HashMap<String, String>) {
        if let Some(ref v) = self.size {
            m.insert("size".to_string(), v.to_string());
        }
        if let Some(ref v) = self.from {
            m.insert("from".to_string(), v.to_string());
        }
        if let Some(ref v) = self.range_from {
            m.insert("range_from".to_string(), v.to_string());
        }
        if let Some(ref v) = self.range_to {
            m.insert("range_to".to_string(), v.to_string());
        }
        if let Some(ref comma_seperated_type) = self.action_type {
            comma_seperated_type.url_encode(m);
        }
        if let Some(ref comma_seperated_type) = self.actor_type {
            comma_seperated_type.url_encode(m);
        }
        if let Some(ref v) = self.actor_id {
            m.insert("actor_id".to_string(), v.to_string());
        }
        if let Some(ref v) = self.object_id {
            m.insert("object_id".to_string(), v.to_string());
        }
        if let Some(ref v) = self.previous_id {
            m.insert("previous_id".to_string(), v.to_string());
        }
        if let Some(ref comma_seperated_type) = self.severity {
            comma_seperated_type.url_encode(m);
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Serialize, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum SeverityLevel {
    Info,
    Warning,
    Error,
    Critical
}

pub struct OperationGetAllLogs;
#[allow(unused)]
impl Operation for OperationGetAllLogs {
    type PathParams = ();
    type QueryParams = LogsParams;
    type Body = ();
    type Output = EsAuditQueryResponse;

    fn method() -> Method {
        Method::GET
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/logs?{q}", q = q.encode())
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn get_all_logs(&self, query_params: Option<&LogsParams>) -> Result<EsAuditQueryResponse> {
        self.execute::<OperationGetAllLogs>(&(), (), query_params).await
    }
}

