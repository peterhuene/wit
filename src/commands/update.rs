use crate::config::{Config, CONFIG_FILE_NAME};
use anyhow::{Context, Result};
use clap::Args;

/// Update dependencies as recorded in the lock file.
#[derive(Args)]
pub struct UpdateCommand {
    /// Don't actually write the lockfile
    #[clap(long = "dry-run")]
    pub dry_run: bool,
}

impl UpdateCommand {
    /// Executes the command.
    pub async fn exec(self) -> Result<()> {
        tracing::debug!("executing update command");

        let (config, config_path) = Config::from_default_file()?
            .with_context(|| format!("failed to find configuration file `{CONFIG_FILE_NAME}`"))?;

        crate::update_lockfile(&config, &config_path, self.dry_run).await
    }
}
