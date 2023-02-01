use super::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Locked(String),
    #[error("{0}")]
    NotFound(String),
    #[error("unexpected status code: {0}")]
    StatusCode(String),
    #[error("{0}")]
    EncoderError( #[from] serde_json::error::Error),
    #[error("{0}")]
    IoError( #[from] io::Error),
    #[error("{0}")]
    NetworkError( #[from] simple_hyper_client::Error),
    #[cfg(feature = "native-tls")]
    #[error("{0}")]
    TlsError( #[from] native_tls::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    pub fn from_status(status: StatusCode, msg: String) -> Self {
        match status {
            StatusCode::UNAUTHORIZED => Error::Unauthorized(msg),
            StatusCode::FORBIDDEN => Error::Forbidden(msg),
            StatusCode::BAD_REQUEST => Error::BadRequest(msg),
            StatusCode::CONFLICT => Error::Conflict(msg),
            StatusCode::LOCKED => Error::Locked(msg),
            StatusCode::NOT_FOUND => Error::NotFound(msg),
            _ => Error::StatusCode(format!("{}\n{}", status.to_string(), msg)),
        }
    }
}
