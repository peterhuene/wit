//! The library for the WIT CLI tool.

#![deny(missing_docs)]

use crate::resolver::DecodedDependency;
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use colored::Colorize;
use config::Config;
use indexmap::{IndexMap, IndexSet};
use lock::{LockFile, LockedPackage, LockedPackageVersion};
use resolver::{create_client, DependencyResolution, DependencyResolutionMap, DependencyResolver};
use semver::Version;
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    time::Duration,
};
use warg_client::storage::{ContentStorage, PublishEntry, PublishInfo};
use warg_crypto::signing::PrivateKey;
use warg_protocol::registry::PackageId;
use wit_component::DecodedWasm;
use wit_parser::{PackageName, Resolve, UnresolvedPackage};

pub mod commands;
pub mod config;
mod lock;
mod resolver;
mod signing;

async fn resolve_dependencies(
    config: &Config,
    config_path: &Path,
) -> Result<DependencyResolutionMap> {
    let lock_file = LockFile::open(config_path)?.unwrap_or_default();
    let mut resolver = DependencyResolver::new(config, Some(&lock_file))?;

    for (id, dep) in &config.dependencies {
        resolver.add_dependency(id, dep).await?;
    }

    let resolution = resolver.resolve().await?;

    let new_lock_file = LockFile::from_resolution(&resolution);
    new_lock_file.update(config_path, &lock_file)?;

    Ok(resolution)
}

fn parse(
    dir: &Path,
    dependencies: &HashMap<PackageId, DependencyResolution>,
) -> Result<(Resolve, wit_parser::PackageId)> {
    let mut merged = Resolve::default();

    // Start by decoding all of the dependencies
    let mut deps = IndexMap::new();
    let mut unversioned: HashMap<_, Vec<_>> = HashMap::new();
    for (id, resolution) in dependencies {
        let decoded = resolution.decode()?;
        let name = decoded.package_name();

        let versionless = PackageName {
            namespace: name.namespace.clone(),
            name: name.name.clone(),
            version: None,
        };

        let (index, prev) = deps.insert_full(name.clone(), decoded);
        if let Some(prev) = prev {
            bail!(
                "duplicate definitions of package `{name}` found while decoding dependency `{id}`",
                name = prev.package_name()
            );
        }

        // We're storing the dependencies with versionless package ids
        // This allows us to resolve a versionless foreign dependency to a singular
        // versioned dependency, if there is one
        unversioned.entry(versionless).or_default().push(index);
    }

    // Parse the root package itself
    let mut root = UnresolvedPackage::parse_dir(dir).with_context(|| {
        format!(
            "failed to parse package from directory `{dir}`",
            dir = dir.display()
        )
    })?;

    let mut source_files: Vec<_> = root.source_files().map(Path::to_path_buf).collect();

    // Do a topological sort of the dependencies
    let mut order = IndexSet::new();
    let mut visiting = HashSet::new();
    for dep in deps.values() {
        visit(dep, &deps, &unversioned, &mut order, &mut visiting)?;
    }

    assert!(visiting.is_empty());

    // Merge all of the dependencies first
    let mut versions = HashMap::new();
    for name in order {
        let pkg = match deps.remove(&name).unwrap() {
            DecodedDependency::Wit {
                resolution,
                mut package,
            } => {
                fixup_foreign_deps(&mut package, &versions);
                source_files.extend(package.source_files().map(Path::to_path_buf));
                merged.push(package).with_context(|| {
                    format!("failed to merge dependency `{id}`", id = resolution.id())
                })?
            }
            DecodedDependency::Wasm {
                resolution,
                decoded,
            } => {
                let (resolve, pkg) = match decoded {
                    DecodedWasm::WitPackage(resolve, pkg) => (resolve, pkg),
                    DecodedWasm::Component(resolve, world) => {
                        let pkg = resolve.worlds[world].package.unwrap();
                        (resolve, pkg)
                    }
                };

                merged
                    .merge(resolve)
                    .with_context(|| {
                        format!(
                            "failed to merge world of dependency `{id}`",
                            id = resolution.id()
                        )
                    })?
                    .packages[pkg.index()]
            }
        };

        let pkg = &merged.packages[pkg];
        if let Some(version) = &pkg.name.version {
            versions
                .entry(PackageName {
                    namespace: pkg.name.namespace.clone(),
                    name: pkg.name.name.clone(),
                    version: None,
                })
                .or_default()
                .push(version.clone());
        }
    }

    fixup_foreign_deps(&mut root, &versions);

    let package = merged.push(root).with_context(|| {
        format!(
            "failed to merge package from directory `{dir}`",
            dir = dir.display()
        )
    })?;

    return Ok((merged, package));

    fn fixup_foreign_deps(
        package: &mut UnresolvedPackage,
        versions: &HashMap<PackageName, Vec<Version>>,
    ) {
        package.foreign_deps = std::mem::take(&mut package.foreign_deps)
            .into_iter()
            .map(|(mut k, v)| {
                match versions.get(&k) {
                    // Only assign the version if there's exactly one matching package
                    // Otherwise, let `wit-parser` handle the ambiguity
                    Some(versions) if versions.len() == 1 => {
                        k.version = Some(versions[0].clone());
                    }
                    _ => {}
                }

                (k, v)
            })
            .collect();
    }

    fn visit<'a>(
        dep: &'a DecodedDependency<'a>,
        deps: &'a IndexMap<PackageName, DecodedDependency>,
        unversioned: &HashMap<PackageName, Vec<usize>>,
        order: &mut IndexSet<PackageName>,
        visiting: &mut HashSet<&'a PackageName>,
    ) -> Result<()> {
        if order.contains(dep.package_name()) {
            return Ok(());
        }

        // Visit any unresolved foreign dependencies
        match dep {
            DecodedDependency::Wit {
                package,
                resolution,
            } => {
                for name in package.foreign_deps.keys() {
                    if !visiting.insert(name) {
                        bail!("foreign dependency `{name}` forms a dependency cycle while parsing dependency `{id}`", id = resolution.id());
                    }

                    // Only visit known dependencies
                    // wit-parser will error on unknown foreign dependencies when
                    // the package is resolved
                    match deps.get(name) {
                        Some(dep) => {
                            // Exact match on the dependency; visit it
                            visit(dep, deps, unversioned, order, visiting)?
                        }
                        None => match unversioned.get(name) {
                            // Only visit if there's exactly one unversioned dependency
                            // If there's more than one, it's ambiguous and wit-parser
                            // will error when the package is resolved.
                            Some(indexes) if indexes.len() == 1 => {
                                let dep = &deps[indexes[0]];
                                visit(dep, deps, unversioned, order, visiting)?;
                            }
                            _ => {}
                        },
                    }

                    assert!(visiting.remove(name));
                }
            }
            DecodedDependency::Wasm { .. } => {
                // No unresolved foreign dependencies for decoded wasm files
            }
        }

        assert!(order.insert(dep.package_name().clone()));

        Ok(())
    }
}

/// Builds a WIT package given the configuration and directory to parse.
async fn build(config: &Config, config_path: &Path) -> Result<(PackageId, Vec<u8>)> {
    let dependencies = resolve_dependencies(config, config_path).await?;

    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));

    let (mut resolve, package) = parse(dir, &dependencies)?;

    let pkg = &mut resolve.packages[package];
    if pkg.name.version.is_some() {
        bail!(
            "package parsed from `{dir}` has an explicit version",
            dir = dir.display()
        );
    }

    pkg.name.version = Some(config.version.clone());
    let id = format!("{ns}:{name}", ns = pkg.name.namespace, name = pkg.name.name).parse()?;

    let bytes = wit_component::encode(&resolve, package)?;

    let mut producers = wasm_metadata::Producers::empty();
    producers.add(
        "processed-by",
        env!("CARGO_PKG_NAME"),
        option_env!("WIT_VERSION_INFO").unwrap_or(env!("CARGO_PKG_VERSION")),
    );

    let bytes = producers
        .add_to_wasm(&bytes)
        .context("failed to add producers metadata to output WIT package")?;

    Ok((id, bytes))
}

struct PublishOptions<'a> {
    config: &'a Config,
    config_path: &'a Path,
    warg_config: &'a warg_client::Config,
    url: &'a str,
    signing_key: &'a PrivateKey,
    package: Option<&'a PackageId>,
    init: bool,
    dry_run: bool,
}

async fn publish(options: PublishOptions<'_>) -> Result<()> {
    let (id, bytes) = build(options.config, options.config_path).await?;

    let id = options.package.unwrap_or(&id);

    if !options.dry_run {
        let client = create_client(options.warg_config, options.url)?;

        let content = client
            .content()
            .store_content(
                Box::pin(futures::stream::once(async { Ok(Bytes::from(bytes)) })),
                None,
            )
            .await?;

        let mut info = PublishInfo {
            id: id.clone(),
            head: None,
            entries: Default::default(),
        };

        if options.init {
            info.entries.push(PublishEntry::Init);
        }

        info.entries.push(PublishEntry::Release {
            version: options.config.version.clone(),
            content,
        });

        println!(
            "{publishing} package `{id}` with version `{version}`...",
            publishing = "publishing".bright_green(),
            version = options.config.version,
        );

        let record_id = client.publish_with_info(options.signing_key, info).await?;
        client
            .wait_for_publish(id, &record_id, Duration::from_secs(1))
            .await?;
    }

    println!(
        "{published} package `{id}` with version `{version}`{dry_run}",
        published = if options.dry_run {
            "would publish"
        } else {
            "published"
        }
        .bright_green(),
        version = options.config.version,
        dry_run = if options.dry_run { " (dry run)" } else { "" },
    );

    Ok(())
}

/// Update the dependencies in the lock file.
pub async fn update_lockfile(config: &Config, config_path: &Path, dry_run: bool) -> Result<()> {
    // Resolve all dependencies as if the lock file does not exist
    let mut resolver = DependencyResolver::new(config, None)?;
    for (id, dep) in &config.dependencies {
        resolver.add_dependency(id, dep).await?;
    }

    let resolution = resolver.resolve().await?;

    // Now open the old lock file and compare it against the new resolution
    let orig_lock_file = LockFile::open(config_path)?.unwrap_or_default();
    let new_lock_file = LockFile::from_resolution(&resolution);

    // The lock file doesn't have transitive dependencies
    // So we expect the entries (and the version requirements) to be the same
    // Thus, only "updating" messages get printed for the packages that changed
    for old_pkg in &orig_lock_file.packages {
        let new_pkg_index = new_lock_file
            .packages
            .binary_search_by_key(&old_pkg.key(), LockedPackage::key)
            .expect("locked packages should remain the same");

        let new_pkg = &new_lock_file.packages[new_pkg_index];
        for old_ver in &old_pkg.versions {
            let new_ver_index = new_pkg
                .versions
                .binary_search_by_key(&old_ver.key(), LockedPackageVersion::key)
                .expect("version requirements should remain the same");

            let new_ver = &new_pkg.versions[new_ver_index];
            if old_ver.version != new_ver.version {
                println!(
                    "{updating} registry package `{id}` v{old} -> v{new}",
                    updating = "Updating".bright_green(),
                    id = old_pkg.id,
                    old = old_ver.version,
                    new = new_ver.version,
                );
            }
        }
    }

    if dry_run {
        println!(
            "{msg}",
            msg = "not updating lock file due to --dry-run option".yellow()
        );
    } else {
        new_lock_file.update(config_path, &orig_lock_file)?;
    }

    Ok(())
}
