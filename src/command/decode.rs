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
    if let Ok(key) = derive_public_key(public_key) {
        let pkey = PKey::from_rsa(key).map_err(JwtError::SignatureVerificationError)?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).map_err(JwtError::SignatureVerificationError)?;
        let signed_data = format!("{}.{}", jwt.header(), jwt.payload());
        verifier.update(signed_data.as_bytes()).map_err(JwtError::SignatureVerificationError)?;
        Ok((verifier.verify(jwt.signature_bytes()).map_err(JwtError::SignatureVerificationError)?, pkey.clone()))
    } else {
        Err(JwtError::SignaturePublicKeyFormatError)
    }
}

fn derive_public_key(public_key: &str) -> Result<Rsa<Public>, JwtError> {
    let public_key_bytes = public_key.as_bytes();
    if let Ok(jwks) = serde_json::from_slice::<Jwks>(public_key_bytes) {
        if !jwks.keys().is_empty() {
            public_key_from_jwk(&jwks.keys()[0])
        } else {
            Err(JwtError::SignaturePublicKeyEmptyJwks)
        }
    } else if let Ok(jwk) = serde_json::from_slice::<Jwk>(public_key_bytes) {
        public_key_from_jwk(&jwk)
    } else if let Ok(public_key) = Rsa::public_key_from_pem(as_pem(public_key).as_bytes()) {
        Ok(public_key)
    } else if let Ok(public_key) = Rsa::public_key_from_der(public_key_bytes) {
        Ok(public_key)
    } else {
        Err(JwtError::SignaturePublicKeyFormatError)
    }
}

fn as_pem(mut s: &str) -> String {
    const PUBLIC_KEY_PREFIX: &str = "-----BEGIN PUBLIC KEY-----";
    const PUBLIC_KEY_SUFFIX: &str = "-----END PUBLIC KEY-----";

    if let Some(index) = s.find(PUBLIC_KEY_PREFIX) {
        s = &s[(index + PUBLIC_KEY_PREFIX.len())..];
    }
    if let Some(index) = s.rfind(PUBLIC_KEY_SUFFIX) {
        s = &s[0..index];
    }

    let s = clean_string(s);
    let mut pem = String::new();

    // Break lines at 64 characters
    let mut i = 0;
    for c in s.chars() {
        i += 1;
        pem.push(c);
        if i == 64 {
            pem.push('\n');
            i = 0;
        }
    }
    if i < 64 {
        pem.push('\n');
    }

    format!("{}\n{}{}", PUBLIC_KEY_PREFIX, pem, PUBLIC_KEY_SUFFIX)
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
    s.replace("\\n", "\n").trim().chars().filter(|c| !c.is_whitespace()).collect()
}

fn indent(s: &str) -> String {
    let mut output = String::new();
    write!(indented(&mut output).with_str("  "), "{}", s).ok();
    output
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn base64_as_pem() {
        let b64 =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOl7/hDwBOap6Y0hEBCYooy5PeeblJbIzGTxzsgDW86dOX86AdbIuGQwCo1cVSidD/OArML8rS9RyyjUdHiWKk3bRSmxfzZqq1fevKC7dEygaNrWj5xkPEFDUmbSqpP3qxFq+tlaizAZF2ttBCGFYsW2KpWEE8Q+LsIfkgpUVHkVPYdBkAT5hFOA8bXrG6Ihrfp2K98xIv8XSIaw7TL4vF3M0AV0zqUZzWrkvDB7LgGicamDcZQfPetOHWdcmxShdPNhiUAugE/z2hNwk49hCV7G+lByVMrUPaayCB+/zzP1MJrCCfNPSaehmx0LOFb8JMst7PODcKqgTEdhvgDMYwIDAQAB";

        assert_eq!("-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOl7/hDwBOap6Y0hEBCY
ooy5PeeblJbIzGTxzsgDW86dOX86AdbIuGQwCo1cVSidD/OArML8rS9RyyjUdHiW
Kk3bRSmxfzZqq1fevKC7dEygaNrWj5xkPEFDUmbSqpP3qxFq+tlaizAZF2ttBCGF
YsW2KpWEE8Q+LsIfkgpUVHkVPYdBkAT5hFOA8bXrG6Ihrfp2K98xIv8XSIaw7TL4
vF3M0AV0zqUZzWrkvDB7LgGicamDcZQfPetOHWdcmxShdPNhiUAugE/z2hNwk49h
CV7G+lByVMrUPaayCB+/zzP1MJrCCfNPSaehmx0LOFb8JMst7PODcKqgTEdhvgDM
YwIDAQAB
-----END PUBLIC KEY-----", as_pem(b64))
    }

    #[test]
    pub fn pem_as_pem() {
        let b64 =
            "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOl7/hDwBOap6Y0hEBCY
ooy5PeeblJbIzGTxzsgDW86dOX86AdbIuGQwCo1cVSidD/OArML8rS9RyyjUdHiW
Kk3bRSmxfzZqq1fevKC7dEygaNrWj5xkPEFDUmbSqpP3qxFq+tlaizAZF2ttBCGF
YsW2KpWEE8Q+LsIfkgpUVHkVPYdBkAT5hFOA8bXrG6Ihrfp2K98xIv8XSIaw7TL4
vF3M0AV0zqUZzWrkvDB7LgGicamDcZQfPetOHWdcmxShdPNhiUAugE/z2hNwk49h
CV7G+lByVMrUPaayCB+/zzP1MJrCCfNPSaehmx0LOFb8JMst7PODcKqgTEdhvgDM
YwIDAQAB
-----END PUBLIC KEY-----";

        assert_eq!("-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOl7/hDwBOap6Y0hEBCY
ooy5PeeblJbIzGTxzsgDW86dOX86AdbIuGQwCo1cVSidD/OArML8rS9RyyjUdHiW
Kk3bRSmxfzZqq1fevKC7dEygaNrWj5xkPEFDUmbSqpP3qxFq+tlaizAZF2ttBCGF
YsW2KpWEE8Q+LsIfkgpUVHkVPYdBkAT5hFOA8bXrG6Ihrfp2K98xIv8XSIaw7TL4
vF3M0AV0zqUZzWrkvDB7LgGicamDcZQfPetOHWdcmxShdPNhiUAugE/z2hNwk49h
CV7G+lByVMrUPaayCB+/zzP1MJrCCfNPSaehmx0LOFb8JMst7PODcKqgTEdhvgDM
YwIDAQAB
-----END PUBLIC KEY-----", as_pem(b64))
    }

    #[test]
    pub fn single_line_pem_as_pem() {
        let b64 =
            "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOl7/hDwBOap6Y0hEBCYooy5PeeblJbIzGTxzsgDW86dOX86AdbIuGQwCo1cVSidD/OArML8rS9RyyjUdHiWKk3bRSmxfzZqq1fevKC7dEygaNrWj5xkPEFDUmbSqpP3qxFq+tlaizAZF2ttBCGFYsW2KpWEE8Q+LsIfkgpUVHkVPYdBkAT5hFOA8bXrG6Ihrfp2K98xIv8XSIaw7TL4vF3M0AV0zqUZzWrkvDB7LgGicamDcZQfPetOHWdcmxShdPNhiUAugE/z2hNwk49hCV7G+lByVMrUPaayCB+/zzP1MJrCCfNPSaehmx0LOFb8JMst7PODcKqgTEdhvgDMYwIDAQAB-----END PUBLIC KEY-----";

        assert_eq!("-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOl7/hDwBOap6Y0hEBCY
ooy5PeeblJbIzGTxzsgDW86dOX86AdbIuGQwCo1cVSidD/OArML8rS9RyyjUdHiW
Kk3bRSmxfzZqq1fevKC7dEygaNrWj5xkPEFDUmbSqpP3qxFq+tlaizAZF2ttBCGF
YsW2KpWEE8Q+LsIfkgpUVHkVPYdBkAT5hFOA8bXrG6Ihrfp2K98xIv8XSIaw7TL4
vF3M0AV0zqUZzWrkvDB7LgGicamDcZQfPetOHWdcmxShdPNhiUAugE/z2hNwk49h
CV7G+lByVMrUPaayCB+/zzP1MJrCCfNPSaehmx0LOFb8JMst7PODcKqgTEdhvgDM
YwIDAQAB
-----END PUBLIC KEY-----", as_pem(b64))
    }

    #[test]
    pub fn pem_bundle_as_pem() {
        let b64 =
            "-----BEGIN CERTIFICATE-----\nMIIDPzCCAiegAwIBAgIRAOlIendKihS02nPoQcqOrfUwDQYJKoZIhvcNAQELBQAw\nHDEaMBgGA1UEAwwRY2EudXAuc2VjdG9yNDIuaW8wHhcNMjIwODE5MDQwNzU4WhcN\nMjMwODE5MDQwNzU4WjAZMRcwFQYDVQQDDA51cC5zZWN0b3I0Mi5pbzCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBALzpe/4Q8ATmqemNIRAQmKKMuT3nm5SW\nyMxk8c7IA1vOnTl/OgHWyLhkMAqNXFUonQ/zgKzC/K0vUcso1HR4lipN20UpsX82\naqtX3rygu3RMoGja1o+cZDxBQ1Jm0qqT96sRavrZWoswGRdrbQQhhWLFtiqVhBPE\nPi7CH5IKVFR5FT2HQZAE+YRTgPG16xuiIa36divfMSL/F0iGsO0y+LxdzNAFdM6l\nGc1q5Lwwey4BonGpg3GUHz3rTh1nXJsUoXTzYYlALoBP89oTcJOPYQlexvpQclTK\n1D2msggfv88z9TCawgnzT0mnoZsdCzhW/CTLLezzg3CqoExHYb4AzGMCAwEAAaN/\nMH0wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCA+gwHQYDVR0lBBYwFAYIKwYB\nBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQr6nFHXPKU7wCWHrBZi+GxVvLyIjAf\nBgNVHSMEGDAWgBQZaWjztsaZNwSP5E9+t93pDakRQjANBgkqhkiG9w0BAQsFAAOC\nAQEASpP47qKcFw1VyYsHWGOdzIpc4TDOLQ6CyknyDLsEM36UU1QYog79RIX5YLez\nmeCe2VMZG13a6WGL56Hp4XFLHMipom09+0HhvXwfuQ9IbFE6tOgTtVExJpBwFKzk\nI+IftVQEpFLU1bfycdR+BjWz2e0J8ffCkbF/xvJUN2G0dG8w4pkaCfTRmmVFoBOZ\ndAUz+IIhTs/JUPknYl6icpLZ/R1dTKkcqOFMFK5enV3TnZnlynh12WJHSrY0uUqt\n8k7++u1h+sH22DmOuJQEvg8oQg3rE7Fe3rnLp0m95tYB6y/UZJ+M11MwO9PPrngu\nQ+n7Cf6hndxXn4c0lqkr5/tUQA==\n-----END CERTIFICATE-----\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAvOl7/hDwBOap6Y0hEBCYooy5PeeblJbIzGTxzsgDW86dOX86\nAdbIuGQwCo1cVSidD/OArML8rS9RyyjUdHiWKk3bRSmxfzZqq1fevKC7dEygaNrW\nj5xkPEFDUmbSqpP3qxFq+tlaizAZF2ttBCGFYsW2KpWEE8Q+LsIfkgpUVHkVPYdB\nkAT5hFOA8bXrG6Ihrfp2K98xIv8XSIaw7TL4vF3M0AV0zqUZzWrkvDB7LgGicamD\ncZQfPetOHWdcmxShdPNhiUAugE/z2hNwk49hCV7G+lByVMrUPaayCB+/zzP1MJrC\nCfNPSaehmx0LOFb8JMst7PODcKqgTEdhvgDMYwIDAQABAoIBAQCxnNAQGnqgEQK1\nbBQm14O6aJaNhmF3faEC0vGqGdFWktatxVmTew4ylze35BpokovBAI79X0JTzcaY\nPSYq72k4EwVSbJXOZio6OJ5ZOMGl4Zl7nCzYzxBKuo2CPtxYtk/ITdMIUCzZ6nnc\n1AqmNKIFMKBKP1LzhrF0It2t3/pTg/onxjfWJ37zsS0l1qcSiEOtWWXQtpdNOtvK\nTaNRtWw0it93TlISJEdSaOEWF+VQ+OUPPtdsPoM6/eK3lkPWj8VOx1hpabd2grQA\nHHswGiIoggpQfG123u7fFSJYq0DhMMXOGCA2QdibaxUFCoJ6jDeCntWAzIeTjeZw\n+gUJ66kJAoGBAOY9+/fzm5owL2htQbJOJHkxUeWXjSMW+i3STRmp4r/HIvI7cpQy\nk/zFxUEqEXxkaNT9u0s9XKoq8+1RFH9kCs7kq/NPgOJm0bDJuZcJXX9JLZ6WGFNs\n1+BBaZxUkm88G+8lvTWKypRkdeGRArvlvLXu7S8yLZKTVJ8wZV3WJRd9AoGBANIL\n0/aPqeLWJ0ZX+YFEpnxJZtH1DXtFQf6GhJWw5yRpwJGOgS5TUzASeBwWEff1LLSb\ncB8nqmHxmoanXiNhV9cIIYsH9gLQXZ3LgGESavD93iB7n6sgN/aywSPaZEwbP7ak\nf4S3sAuDDrlnZgGb2vmht7AusXtJSzXfxEJeH3lfAoGAaZIOULjwphhmBHnkX7+Y\n1cEZji6ZVneYqx38oEHXaJwEmBFODknKtWJxedmyPtlDgDX/hRZTwOsFAdHllivn\nEMqlVWEk9aqzh15XrLtslYqWUlr8OHR136veowHcSwjCvjsNsNk83iHaM11sZX+H\nsdwmATf+0XCgooVsVUR1qXkCgYB9DK+npcYllwuQ1IVlkWJwsh51tyfMkOIGTz2W\nBNjHk/Iidi2wT8lB4G0Dg5w0/BEegT/SPIIyh21Q50mjVKvACEY4CIhNCpIBhIss\nv5NNYEajHhZkAe1vgOJ9nuKBcOOQsAR/FgDICcF1Xfqb0JcgcUfzqwjc9jjBnTOx\ns2mXjwKBgCSVLjhPRaaU9acfa6sSsR/5Ifya1z4YqErdJaNhSDQBtCP9CI4GJn32\nfVOGd4RD0XmDLd7VLHiaJfsbvFFcrljvFjM/Iw+5yUiMCMD3k/yH75LfmwPYK8VP\nRuT9KYjqZBGFWi+lQLw1WWIholHdcnXDe4al/yU0uJaGI6hsHZr4\n-----END RSA PRIVATE KEY-----\n-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOl7/hDwBOap6Y0hEBCY\nooy5PeeblJbIzGTxzsgDW86dOX86AdbIuGQwCo1cVSidD/OArML8rS9RyyjUdHiW\nKk3bRSmxfzZqq1fevKC7dEygaNrWj5xkPEFDUmbSqpP3qxFq+tlaizAZF2ttBCGF\nYsW2KpWEE8Q+LsIfkgpUVHkVPYdBkAT5hFOA8bXrG6Ihrfp2K98xIv8XSIaw7TL4\nvF3M0AV0zqUZzWrkvDB7LgGicamDcZQfPetOHWdcmxShdPNhiUAugE/z2hNwk49h\nCV7G+lByVMrUPaayCB+/zzP1MJrCCfNPSaehmx0LOFb8JMst7PODcKqgTEdhvgDM\nYwIDAQAB\n-----END PUBLIC KEY-----\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAvOl7/hDwBOap6Y0hEBCYooy5PeeblJbIzGTxzsgDW86dOX86\nAdbIuGQwCo1cVSidD/OArML8rS9RyyjUdHiWKk3bRSmxfzZqq1fevKC7dEygaNrW\nj5xkPEFDUmbSqpP3qxFq+tlaizAZF2ttBCGFYsW2KpWEE8Q+LsIfkgpUVHkVPYdB\nkAT5hFOA8bXrG6Ihrfp2K98xIv8XSIaw7TL4vF3M0AV0zqUZzWrkvDB7LgGicamD\ncZQfPetOHWdcmxShdPNhiUAugE/z2hNwk49hCV7G+lByVMrUPaayCB+/zzP1MJrC\nCfNPSaehmx0LOFb8JMst7PODcKqgTEdhvgDMYwIDAQABAoIBAQCxnNAQGnqgEQK1\nbBQm14O6aJaNhmF3faEC0vGqGdFWktatxVmTew4ylze35BpokovBAI79X0JTzcaY\nPSYq72k4EwVSbJXOZio6OJ5ZOMGl4Zl7nCzYzxBKuo2CPtxYtk/ITdMIUCzZ6nnc\n1AqmNKIFMKBKP1LzhrF0It2t3/pTg/onxjfWJ37zsS0l1qcSiEOtWWXQtpdNOtvK\nTaNRtWw0it93TlISJEdSaOEWF+VQ+OUPPtdsPoM6/eK3lkPWj8VOx1hpabd2grQA\nHHswGiIoggpQfG123u7fFSJYq0DhMMXOGCA2QdibaxUFCoJ6jDeCntWAzIeTjeZw\n+gUJ66kJAoGBAOY9+/fzm5owL2htQbJOJHkxUeWXjSMW+i3STRmp4r/HIvI7cpQy\nk/zFxUEqEXxkaNT9u0s9XKoq8+1RFH9kCs7kq/NPgOJm0bDJuZcJXX9JLZ6WGFNs\n1+BBaZxUkm88G+8lvTWKypRkdeGRArvlvLXu7S8yLZKTVJ8wZV3WJRd9AoGBANIL\n0/aPqeLWJ0ZX+YFEpnxJZtH1DXtFQf6GhJWw5yRpwJGOgS5TUzASeBwWEff1LLSb\ncB8nqmHxmoanXiNhV9cIIYsH9gLQXZ3LgGESavD93iB7n6sgN/aywSPaZEwbP7ak\nf4S3sAuDDrlnZgGb2vmht7AusXtJSzXfxEJeH3lfAoGAaZIOULjwphhmBHnkX7+Y\n1cEZji6ZVneYqx38oEHXaJwEmBFODknKtWJxedmyPtlDgDX/hRZTwOsFAdHllivn\nEMqlVWEk9aqzh15XrLtslYqWUlr8OHR136veowHcSwjCvjsNsNk83iHaM11sZX+H\nsdwmATf+0XCgooVsVUR1qXkCgYB9DK+npcYllwuQ1IVlkWJwsh51tyfMkOIGTz2W\nBNjHk/Iidi2wT8lB4G0Dg5w0/BEegT/SPIIyh21Q50mjVKvACEY4CIhNCpIBhIss\nv5NNYEajHhZkAe1vgOJ9nuKBcOOQsAR/FgDICcF1Xfqb0JcgcUfzqwjc9jjBnTOx\ns2mXjwKBgCSVLjhPRaaU9acfa6sSsR/5Ifya1z4YqErdJaNhSDQBtCP9CI4GJn32\nfVOGd4RD0XmDLd7VLHiaJfsbvFFcrljvFjM/Iw+5yUiMCMD3k/yH75LfmwPYK8VP\nRuT9KYjqZBGFWi+lQLw1WWIholHdcnXDe4al/yU0uJaGI6hsHZr4\n-----END RSA PRIVATE KEY-----\n";

        assert_eq!("-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOl7/hDwBOap6Y0hEBCY
ooy5PeeblJbIzGTxzsgDW86dOX86AdbIuGQwCo1cVSidD/OArML8rS9RyyjUdHiW
Kk3bRSmxfzZqq1fevKC7dEygaNrWj5xkPEFDUmbSqpP3qxFq+tlaizAZF2ttBCGF
YsW2KpWEE8Q+LsIfkgpUVHkVPYdBkAT5hFOA8bXrG6Ihrfp2K98xIv8XSIaw7TL4
vF3M0AV0zqUZzWrkvDB7LgGicamDcZQfPetOHWdcmxShdPNhiUAugE/z2hNwk49h
CV7G+lByVMrUPaayCB+/zzP1MJrCCfNPSaehmx0LOFb8JMst7PODcKqgTEdhvgDM
YwIDAQAB
-----END PUBLIC KEY-----", as_pem(b64))
    }

    #[test]
    pub fn embedded_newlines_as_pem() {
        let b64 =
            "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOl7/hDwBOap6Y0hEBCY\\nooy5PeeblJbIzGTxzsgDW86dOX86AdbIuGQwCo1cVSidD/OArML8rS9RyyjUdHiW\\nKk3bRSmxfzZqq1fevKC7dEygaNrWj5xkPEFDUmbSqpP3qxFq+tlaizAZF2ttBCGF\\nYsW2KpWEE8Q+LsIfkgpUVHkVPYdBkAT5hFOA8bXrG6Ihrfp2K98xIv8XSIaw7TL4\\nvF3M0AV0zqUZzWrkvDB7LgGicamDcZQfPetOHWdcmxShdPNhiUAugE/z2hNwk49h\\nCV7G+lByVMrUPaayCB+/zzP1MJrCCfNPSaehmx0LOFb8JMst7PODcKqgTEdhvgDM\\nYwIDAQAB\\n-----END PUBLIC KEY-----";

        assert_eq!("-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOl7/hDwBOap6Y0hEBCY
ooy5PeeblJbIzGTxzsgDW86dOX86AdbIuGQwCo1cVSidD/OArML8rS9RyyjUdHiW
Kk3bRSmxfzZqq1fevKC7dEygaNrWj5xkPEFDUmbSqpP3qxFq+tlaizAZF2ttBCGF
YsW2KpWEE8Q+LsIfkgpUVHkVPYdBkAT5hFOA8bXrG6Ihrfp2K98xIv8XSIaw7TL4
vF3M0AV0zqUZzWrkvDB7LgGicamDcZQfPetOHWdcmxShdPNhiUAugE/z2hNwk49h
CV7G+lByVMrUPaayCB+/zzP1MJrCCfNPSaehmx0LOFb8JMst7PODcKqgTEdhvgDM
YwIDAQAB
-----END PUBLIC KEY-----", as_pem(b64))
    }
}
