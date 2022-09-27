use ansi_term::Color;

use crate::jwt::Jwt;

pub struct DecodeCommand;

pub fn run(token: &str, public_key: Option<&str>) {
    let jwt: Jwt = match token.parse() {
        Ok(jwt) => jwt,
        Err(e) => {
            eprintln!("failed to parse JWT: {}", e);
            return;
        }
    };

    println!("Header: {}", Color::Red.paint(jwt.header()));
    println!("Payload: {}", Color::Blue.paint(jwt.payload()));
}
