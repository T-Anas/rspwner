mod analysis;
mod cli;
mod config;
mod core;
mod exploits;
mod tools;
mod utils;

use anyhow::Result;
use clap::Parser;
use cli::Cli;
use config::Config;
use core::orchestrator::Orchestrator;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    utils::logger::init();

    let cli = Cli::parse();

    if cli.config {
        Config::interactive_setup()?;
        return Ok(());
    }

    let Some(binary_path) = cli.binary.as_ref() else {
        Cli::command_error("missing --bin <PATH>; use --config for setup")?;
        return Ok(());
    };

    info!(binary = %binary_path.display(), "starting rspwner");

    let config = Config::load().ok();
    let mut orchestrator = Orchestrator::new(config);
    orchestrator.run(&cli).await
}
