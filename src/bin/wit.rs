use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::process::exit;
use tracing::metadata::LevelFilter;
use wit::commands::{
    AddCommand, BuildCommand, InitCommand, KeyCommand, PublishCommand, UpdateCommand,
};

fn version() -> &'static str {
    option_env!("WIT_VERSION_INFO").unwrap_or(env!("CARGO_PKG_VERSION"))
}

/// WIT package tool.
#[derive(Parser)]
#[clap(
    bin_name = "wit",
    version,
    propagate_version = true,
    arg_required_else_help = true
)]
#[command(version = version())]
struct Wit {
    /// Use verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[clap(subcommand)]
    command: Command,
}

impl Wit {
    fn init_tracing(&self) {
        tracing_subscriber::fmt()
            .with_max_level(match self.verbose {
                0 => LevelFilter::WARN,
                1 => LevelFilter::INFO,
                2 => LevelFilter::DEBUG,
                _ => LevelFilter::TRACE,
            })
            .with_target(false)
            .init();
    }
}

#[derive(Parser)]
pub enum Command {
    Init(InitCommand),
    Add(AddCommand),
    Build(BuildCommand),
    Publish(PublishCommand),
    Key(KeyCommand),
    Update(UpdateCommand),
}

#[tokio::main]
async fn main() -> Result<()> {
    let app = Wit::parse();
    app.init_tracing();

    if let Err(e) = match app.command {
        Command::Init(cmd) => cmd.exec().await,
        Command::Add(cmd) => cmd.exec().await,
        Command::Build(cmd) => cmd.exec().await,
        Command::Publish(cmd) => cmd.exec().await,
        Command::Key(cmd) => cmd.exec().await,
        Command::Update(cmd) => cmd.exec().await,
    } {
        eprintln!("{error}: {e:?}", error = "error".red());
        exit(1);
    }

    Ok(())
}
