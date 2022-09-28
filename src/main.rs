use clap::Parser;

mod cli;
mod command;
mod error;
mod jwt;
mod jwks;

use cli::Cli;

fn main() {
    let mut cli = Cli::parse();

    if !atty::is(atty::Stream::Stdout) || !atty::is(atty::Stream::Stderr) {
        // We are not a terminal, do not use colors.
        cli.no_color = true;
    }

    if !cli.no_color {
        #[cfg(windows)]
        {
            // Windows needs you to explicitly turn it on.
            cli.no_color = !ansi_term::enable_ansi_support();
        }
    }

    cli.run();
}
