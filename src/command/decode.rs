use std::fmt::Write;

use ansi_term::Color;
use base64::URL_SAFE_NO_PAD;
use copypasta::{ClipboardContext, ClipboardProvider};
use indenter::indented;
use openssl::{bn::BigNum, hash::MessageDigest, pkey::{Id, PKey, Public}, rsa::Rsa, sign::Verifier};

use crate::{error::{display_message_and_exit, JwtError}, jwks::{Jwk, Jwks}, jwt::Jwt};

pub fn run(token: Option<&str>, public_key: Option<&str>) {
    let mut from_clipboard = false;
    let jwt = match token {
        Some(token) => token.parse::<Jwt>().ok(),
        None => {
            if let Some(token) = get_clipboard_token() {
                from_clipboard = true;
                Some(token)
            } else {
                None
            }
        }
    };

    if let Some(jwt) = jwt {
        println!(
            "Token ({}):\n{}",
            if from_clipboard {
                "Clipboard"
            } else {
                "Argument"
            },
            indent(&format!(
                "{}.{}.{}",
                Color::Red.paint(jwt.header()),
                Color::Blue.paint(jwt.payload()),
                Color::Yellow.paint(jwt.signature())
            ))
        );
        println!("Header:\n{}", Color::Red.paint(indent(&jwt.header_json())));
        println!(
            "Payload:\n{}",
            Color::Blue.paint(indent(&jwt.payload_json()))
        );
        println!(
            "Signature:\n{}",
            Color::Yellow.paint(indent(&format!("{:02X?}", &jwt.signature_bytes())))
        );
        if let Some(public_key) = public_key {
            // Public key was provided.
            verify_jwt_and_report(&jwt, public_key);
        } else {
            // Try find a public key based on the JWT issuer.
            match get_issuer_name(&jwt) {
                Some(name) => {
                    if let Some(issuer_public_key) = find_issuer_public_key(&name) {
                        verify_jwt_and_report(&jwt, &issuer_public_key);
                    } else {
                        println!("\n  No public key found for issuer '{}', and no --signature-public-key KEY or SIGNATURE_PUBLIC_KEY environment variable specified, verification skipped.", name);
                    }
                }
                None => {
                    println!("\n  No 'iss' claim in JWT, and no --signature-public-key KEY or SIGNATURE_PUBLIC_KEY environment variable specified, verification skipped.");
                }
            }
        }
    } else {
        display_message_and_exit(
            "JWT should either be provided as an argument or via the clipboard",
        );
    }
}

fn verify_jwt_and_report(jwt: &Jwt, public_key: &str) {
    match verify_jwt(jwt, public_key) {
        Ok((passed, key)) => {
            println!("Signature Verification ({} bit {} key):", key.bits(), key_algorithm(key.clone()));
            let status = if passed {
                Color::Green.paint("PASSED")
            } else {
                Color::Red.paint("FAILED")
            };
            println!("  {}", status);
        }
        Err(e) => {
            println!("Signature Verification:\n  {}", Color::Red.paint(format!("FAILED ({})", e)));
        }
    };
}

fn key_algorithm(pkey: PKey<Public>) -> &'static str {
    match pkey.id() {
        Id::RSA => "RSA",
        Id::HMAC => "HMAC",
        Id::DSA => "DSA",
        Id::DH => "DH",
        Id::EC => "EC",
        Id::ED25519 => "Ed25519",
        Id::ED448 => "Ed448",
        _ => "unknown",
    }
}

fn verify_jwt(jwt: &Jwt, public_key: &str) -> Result<(bool, PKey<Public>), JwtError> {
    let public_key_bytes = public_key.trim().as_bytes();
    if let Ok(key) = derive_public_key(public_key_bytes) {
        let pkey = PKey::from_rsa(key).map_err(JwtError::SignatureVerificationError)?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).map_err(JwtError::SignatureVerificationError)?;
        let signed_data = format!("{}.{}", jwt.header(), jwt.payload());
        verifier.update(signed_data.as_bytes()).map_err(JwtError::SignatureVerificationError)?;
        Ok((verifier.verify(jwt.signature_bytes()).map_err(JwtError::SignatureVerificationError)?, pkey.clone()))
    } else {
        Err(JwtError::SignaturePublicKeyFormatError)
    }
}

fn derive_public_key(public_key_bytes: &[u8]) -> Result<Rsa<Public>, JwtError> {
    if let Ok(jwks) = serde_json::from_slice::<Jwks>(public_key_bytes) {
        if !jwks.keys().is_empty() {
            public_key_from_jwk(&jwks.keys()[0])
        } else {
            Err(JwtError::SignaturePublicKeyEmptyJwks)
        }
    } else if let Ok(jwk) = serde_json::from_slice::<Jwk>(public_key_bytes) {
        public_key_from_jwk(&jwk)
    } else if let Ok(public_key) = Rsa::public_key_from_pem(public_key_bytes) {
        Ok(public_key)
    } else if let Ok(public_key) = Rsa::public_key_from_der(public_key_bytes) {
        Ok(public_key)
    } else {
        Err(JwtError::SignaturePublicKeyFormatError)
    }
}

fn public_key_from_jwk(jwk: &Jwk) -> Result<Rsa<Public>, JwtError> {
    let n_bytes = base64::decode_config(&jwk.n, URL_SAFE_NO_PAD.decode_allow_trailing_bits(true))?;
    let e_bytes = base64::decode_config(&jwk.e, URL_SAFE_NO_PAD.decode_allow_trailing_bits(true))?;
    let n = BigNum::from_slice(&n_bytes)?;
    let e = BigNum::from_slice(&e_bytes)?;
    Ok(Rsa::from_public_components(n, e)?)
}

fn get_clipboard_token() -> Option<Jwt> {
    let contents = ClipboardContext::new()
        .and_then(|mut ctx| ctx.get_contents())
        .map(|s| clean_string(&s))
        .ok()?;
    contents.parse().ok()
}

fn get_issuer_name(jwt: &Jwt) -> Option<String> {
    jwt.claim("iss")
        .and_then(|iss| iss.as_str().map(|s| s.to_owned()))
}

fn find_issuer_public_key(_name: &str) -> Option<String> {
    None
}

fn clean_string(s: &str) -> String {
    s.trim().chars().filter(|c| !c.is_whitespace()).collect()
}

fn indent(s: &str) -> String {
    let mut output = String::new();
    write!(indented(&mut output).with_str("  "), "{}", s).ok();
    output
}
