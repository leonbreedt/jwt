use ansi_term::Color;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("JWT is expected to be in the format HEADER.PAYLOAD.SIGNATURE")]
    InvalidTokenFormat,
    #[error("failed to decode JWT part from Base-64: {0}")]
    PartDecodeFailed(#[from] base64::DecodeError),
    #[error("failed to parse part as JSON: {0}")]
    JsonParseFailed(#[from] serde_json::Error),
    #[error("failed to verify JWT signature: {0}")]
    SignatureVerificationError(openssl::error::ErrorStack),
    #[error("expected public key to be either PEM or DER encoded RSA public key")]
    SignaturePublicKeyFormatError,
    #[error("no keys in JWKS public key set")]
    SignaturePublicKeyEmptyJwks,
    #[error("OpenSSL operation failed: {0}")]
    GenericOpenSSLError(#[from] openssl::error::ErrorStack),
}

pub fn display_message_and_exit(message: &str) {
    eprintln!("{}: {}", Color::Red.paint("error"), message);
    std::process::exit(1);
}
