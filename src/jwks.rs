use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::JwtError;

#[derive(Clone, Serialize, Deserialize)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

impl Jwks {
    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }
}

impl ToString for Jwks {
    fn to_string(&self) -> String {
        json!(self).to_string()
    }
}

impl FromStr for Jwks {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(serde_json::from_str(s)?)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: KeyType,
    pub alg: Option<KeyAlgorithm>,
    pub kid: Option<String>,
    pub n: String,
    pub e: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum KeyAlgorithm {
    Rs256,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum KeyType {
    Rsa,
}
