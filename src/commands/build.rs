use crate::{
    build,
    config::{Config, CONFIG_FILE_NAME},
};
use anyhow::{Context, Result};
use clap::Args;
use colored::Colorize;
use std::{fs, path::PathBuf};

/// Build a binary WIT package.
#[derive(Args)]
pub struct BuildCommand {
    /// The output package path.
    #[clap(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

impl BuildCommand {
    /// Executes the command.
    pub async fn exec(self) -> Result<()> {
        tracing::debug!("executing build command");

        let (config, config_path) = Config::from_default_file()?
            .with_context(|| format!("failed to find configuration file `{CONFIG_FILE_NAME}`"))?;

        let (id, bytes) = build(&config, &config_path).await?;

        let output = self
            .output
            .unwrap_or_else(|| format!("{name}.wasm", name = id.name()).into());

        fs::write(&output, bytes).with_context(|| {
            format!(
                "failed to write output file `{output}`",
                output = output.display()
            )
        })?;

        println!(
            "{created} package `{output}`",
            created = "created".bright_green(),
            output = output.display(),
        );

        Ok(())
    }
}
