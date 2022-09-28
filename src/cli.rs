use clap::{Parser, Subcommand};

use crate::command;

/// JWT toolkit.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    /// Disable colors, automatically disabled when not running with a TTY.
    #[clap(long, global = true)]
    pub no_color: bool,

    #[clap(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    /// Sets up environment by cloning an existing Git repository.
    Decode {
        /// The JWT to decode.
        token: Option<String>,
        /// Public key to use to verify the JWT signature.
        #[clap(long, env("SIGNATURE_PUBLIC_KEY"))]
        signature_public_key: Option<String>,
    },
}

impl Cli {
    pub fn run(&self) {
        if let Some(command) = &self.command {
            match command {
                CliCommand::Decode { token, signature_public_key } => {
                    command::decode::run(token.as_deref(), signature_public_key.as_deref())
                }
            }
        } else {
            // No command, print help.
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            cmd.print_help().ok();
        }
    }
}
