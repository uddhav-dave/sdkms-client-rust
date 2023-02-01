use super::*;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BatchEncryptRequestItem {
    pub kid: Uuid,
    pub request: EncryptRequest,
}

pub type BatchEncryptRequest = Vec<BatchEncryptRequestItem>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BatchDecryptRequestItem {
    pub kid: Uuid,
    pub request: DecryptRequest,
}

pub type BatchDecryptRequest = Vec<BatchDecryptRequestItem>;

pub type BatchSignRequest = Vec<SignRequest>;

pub type BatchVerifyRequest = Vec<VerifyRequest>;

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum BatchResponseItem<T> {
    Success { status: u16, body: T },
    Error { status: u16, error: String },
}

impl<T> BatchResponseItem<T> {
    pub fn status(&self) -> u16 {
        match *self {
            BatchResponseItem::Success { status, .. } | BatchResponseItem::Error { status, .. } => {
                status
            }
        }
    }
}

pub type BatchResponse<T> = Vec<BatchResponseItem<T>>;