use std::fmt::Write;

use ansi_term::Color;
use copypasta::{ClipboardContext, ClipboardProvider};
use indenter::indented;

use crate::{error::display_message_and_exit, jwt::Jwt};

pub fn run(token: Option<&str>, _public_key: Option<&str>) {
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
    } else {
        display_message_and_exit(
            "JWT should either be provided as an argument or via the clipboard",
        );
    }
}

fn get_clipboard_token() -> Option<Jwt> {
    let contents = ClipboardContext::new()
        .and_then(|mut ctx| ctx.get_contents())
        .map(|s| clean_string(&s))
        .ok()?;
    contents.parse().ok()
}

fn clean_string(s: &str) -> String {
    s.trim().chars().filter(|c| !c.is_whitespace()).collect()
}

fn indent(s: &str) -> String {
    let mut output = String::new();
    write!(indented(&mut output).with_str("  "), "{}", s).ok();
    output
}
