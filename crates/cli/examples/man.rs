//! Writes the man pages (`git-amaga.1` and one per subcommand) to the directory given as the
//! only argument.

use clap::CommandFactory;

#[allow(dead_code)]
#[path = "../src/cli.rs"]
mod cli;

fn main() -> std::io::Result<()> {
    let dir = std::env::args_os()
        .nth(1)
        .expect("usage: cargo run --example man -- <output-dir>");
    std::fs::create_dir_all(&dir)?;
    clap_mangen::generate_to(cli::Cli::command(), dir)
}
