use crate::{
    config::{Config, Dependency, RegistryPackage, CONFIG_FILE_NAME},
    resolver::{DependencyResolution, DependencyResolver},
};
use anyhow::{bail, Context, Result};
use clap::Args;
use colored::Colorize;
use semver::VersionReq;
use warg_protocol::registry::PackageId;

async fn resolve_version(
    config: &Config,
    package: &PackageId,
    version: &Option<VersionReq>,
    registry: &Option<String>,
) -> Result<String> {
    let mut resolver = DependencyResolver::new(config, None)?;
    let dependency = Dependency::Package(RegistryPackage {
        id: Some(package.clone()),
        version: version.as_ref().unwrap_or(&VersionReq::STAR).clone(),
        registry: registry.clone(),
    });

    resolver.add_dependency(package, &dependency).await?;

    let dependencies = resolver.resolve().await?;
    assert_eq!(dependencies.len(), 1);

    match dependencies.values().next().expect("expected a resolution") {
        DependencyResolution::Registry(resolution) => Ok(version
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| resolution.version.to_string())),
        _ => unreachable!(),
    }
}

/// Adds a reference to a WIT package from a registry.
#[derive(Args)]
#[clap(disable_version_flag = true)]
pub struct AddCommand {
    /// Don't actually write the configuration file.
    #[clap(long = "dry-run")]
    pub dry_run: bool,

    /// The name of the registry to use for the package.
    #[clap(long = "registry", short = 'r', value_name = "REGISTRY")]
    pub registry: Option<String>,

    /// The version requirement of the dependency being added.
    #[clap(long = "version", value_name = "VERSION")]
    pub version: Option<VersionReq>,

    /// The id of the dependency to use; defaults to the package id.
    #[clap(long, value_name = "ID")]
    pub id: Option<PackageId>,

    /// The id of the package to add a dependency to.
    #[clap(value_name = "PACKAGE")]
    pub package: PackageId,
}

impl AddCommand {
    /// Executes the command.
    pub async fn exec(self) -> Result<()> {
        tracing::debug!("executing add command");

        let (mut config, config_path) = Config::from_default_file()?
            .with_context(|| format!("failed to find configuration file `{CONFIG_FILE_NAME}`"))?;

        let id = self.id.as_ref().unwrap_or(&self.package);
        if config.dependencies.contains_key(id) {
            bail!("cannot add dependency `{id}` as it conflicts with an existing dependency");
        }

        let version =
            resolve_version(&config, &self.package, &self.version, &self.registry).await?;

        let package = match &self.id {
            Some(id) => RegistryPackage {
                id: Some(id.clone()),
                version: version.parse()?,
                registry: self.registry,
            },
            None => version.parse()?,
        };

        config
            .dependencies
            .insert(id.clone(), Dependency::Package(package));

        if !self.dry_run {
            config.write(config_path)?;
        }

        println!(
            "{added} dependency `{id}` with version `{version}`{dry_run}",
            added = if self.dry_run { "would add" } else { "added" }.bright_green(),
            dry_run = if self.dry_run { " (dry run)" } else { "" },
        );

        Ok(())
    }
}
