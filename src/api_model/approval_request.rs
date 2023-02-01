use super::*;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ApprovableResult {
    pub status: u16,
    pub body: serde_json::Value,
}

impl ApprovableResult {
    pub fn is_ok(&self) -> bool {
        200 <= self.status && self.status < 300
    }
}
