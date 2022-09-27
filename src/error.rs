use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("JWT is expected to be in the format HEADER.PAYLOAD.SIGNATURE")]
    InvalidTokenFormat,
    #[error("failed to decode JWT part from Base-64: {0}")]
    PartDecodeFailed(#[from] base64::DecodeError),
    #[error("failed to parse part as JSON: {0}")]
    JsonParseFailed(#[from] serde_json::Error),
}
