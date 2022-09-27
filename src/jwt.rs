use std::str::FromStr;

use crate::error::JwtError;

pub struct Jwt {
    header: serde_json::Value,
    payload: serde_json::Value,
    signature: Vec<u8>,
}

impl Jwt {
    pub fn header(&self) -> String {
        serde_json::to_string_pretty(&self.header).unwrap()
    }

    pub fn payload(&self) -> String {
        serde_json::to_string_pretty(&self.payload).unwrap()
    }
}

impl FromStr for Jwt {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split(".").collect();
        if parts.len() != 3 || parts.iter().any(|s| s.is_empty()) {
            return Err(JwtError::InvalidTokenFormat);
        }

        let header_buf = base64::decode_config(parts[0], base64::URL_SAFE_NO_PAD)?;
        let payload_buf = base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)?;
        let signature = base64::decode_config(parts[2], base64::URL_SAFE_NO_PAD)?;

        let header = serde_json::from_slice(&header_buf)?;
        let payload = serde_json::from_slice(&payload_buf)?;

        Ok(Self {
            header,
            payload,
            signature,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn missing_parts_error() {
        assert!(matches!(
            "".parse::<Jwt>(),
            Err(JwtError::InvalidTokenFormat)
        ));
        assert!(matches!(
            "..".parse::<Jwt>(),
            Err(JwtError::InvalidTokenFormat)
        ));
    }

    #[test]
    pub fn part_decode_error() {
        assert!(matches!(
            "a.b.c".parse::<Jwt>(),
            Err(JwtError::PartDecodeFailed(
                base64::DecodeError::InvalidLength
            ))
        ));

        assert!(matches!(
            "eyJraWQiOiJhYmNkZWYiLCJhbGciOiJSUzI1NiJ9.b.c".parse::<Jwt>(),
            Err(JwtError::PartDecodeFailed(
                base64::DecodeError::InvalidLength
            ))
        ));
        assert!(matches!(
            "eyJraWQiOiJhYmNkZWYiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTY2NDA5NzE0NywiZXhwIjoxNjY0MTQwMzQ3LCJzdWIiOiI4ZjllMTY5OS04ZTAxLTQ2MzMtODRlNy0wZDczYmVkNTI5MzcifQ.c".parse::<Jwt>(),
            Err(JwtError::PartDecodeFailed(
                base64::DecodeError::InvalidLength
            ))
        ));
    }

    #[test]
    pub fn valid_jwt_decodes() {
        let jwt = "eyJraWQiOiJhYmNkZWYiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTY2NDA5NzE0NywiZXhwIjoxNjY0MTQwMzQ3LCJzdWIiOiI4ZjllMTY5OS04ZTAxLTQ2MzMtODRlNy0wZDczYmVkNTI5MzcifQ.SQi7MOuvmybQZg_vU-VFG_EK0_U4DijRn-_Fmlw7qUo".parse::<Jwt>().unwrap();

        assert_eq!(r#"{"alg":"RS256","kid":"abcdef"}"#, jwt.header.to_string());
        assert_eq!(
            r#"{"aud":"audience","exp":1664140347,"iat":1664097147,"iss":"issuer","sub":"8f9e1699-8e01-4633-84e7-0d73bed52937"}"#,
            jwt.payload.to_string()
        );

        let signature = base64::decode_config(
            "SQi7MOuvmybQZg_vU-VFG_EK0_U4DijRn-_Fmlw7qUo",
            base64::URL_SAFE_NO_PAD,
        )
        .unwrap();
        assert_eq!(signature, jwt.signature);
    }
}
