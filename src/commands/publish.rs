use crate::{
    config::{Config, CONFIG_FILE_NAME},
    publish,
    resolver::find_url,
    signing, PublishOptions,
};
use anyhow::{anyhow, Context, Result};
use clap::Args;
use url::Url;
use warg_crypto::signing::PrivateKey;
use warg_protocol::registry::PackageId;

/// Publish a WIT package to a registry.
#[derive(Args)]
pub struct PublishCommand {
    /// Don't actually publish the package.
    #[clap(long = "dry-run")]
    pub dry_run: bool,

    /// Initialize a new package in the registry.
    #[clap(long = "init")]
    pub init: bool,

    /// Use the specified registry name when publishing the package.
    #[clap(long = "registry", value_name = "REGISTRY")]
    pub registry: Option<String>,

    /// The key name to use for the signing key.
    #[clap(long, short, value_name = "KEY", default_value = "default")]
    pub key_name: String,

    /// Override the package name to publish.
    #[clap(long, value_name = "NAME")]
    pub package: Option<PackageId>,
}

impl PublishCommand {
    /// Executes the command.
    pub async fn exec(self) -> Result<()> {
        tracing::debug!("executing publish command");

        let (config, config_path) = Config::from_default_file()?
            .with_context(|| format!("failed to find configuration file `{CONFIG_FILE_NAME}`"))?;

        let warg_config = warg_client::Config::from_default_file()?.unwrap_or_default();

        let url = find_url(
            self.registry.as_deref(),
            &config.registries,
            warg_config.default_url.as_deref(),
        )?;

        let signing_key: PrivateKey = if let Ok(key) = std::env::var("WIT_PUBLISH_KEY") {
            key.parse().context(
                "failed to parse signing key from `WIT_PUBLISH_KEY` environment variable",
            )?
        } else {
            let url: Url = url
                .parse()
                .with_context(|| format!("failed to parse registry URL `{url}`"))?;

            signing::get_signing_key(
                url.host_str()
                    .ok_or_else(|| anyhow!("registry URL `{url}` has no host"))?,
                &self.key_name,
            )?
        };

        publish(PublishOptions {
            config: &config,
            config_path: &config_path,
            warg_config: &warg_config,
            url,
            signing_key: &signing_key,
            package: self.package.as_ref(),
            init: self.init,
            dry_run: self.dry_run,
        })
        .await
    }
}
