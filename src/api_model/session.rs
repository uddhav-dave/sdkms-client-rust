use super::*;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthResponse {
    pub token_type: String,
    pub expires_in: u32,
    pub access_token: String,
    pub entity_id: Uuid,
    pub challenge: Option<MfaChallengeResponse>,
}