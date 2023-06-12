use crate::{
    config::{Config, Dependency, DEFAULT_REGISTRY_NAME},
    lock::{LockFile, LockedPackage, LockedPackageVersion},
};
use anyhow::{anyhow, bail, Context, Result};
use colored::Colorize;
use futures::{stream::FuturesUnordered, StreamExt};
use indexmap::IndexMap;
use indicatif::{ProgressBar, ProgressStyle};
use semver::{Comparator, Op, Version, VersionReq};
use std::{
    collections::{hash_map, HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use url::Url;
use warg_client::{
    storage::{ContentStorage, PackageInfo, RegistryStorage},
    FileSystemClient, StorageLockResult,
};
use warg_crypto::hash::AnyHash;
use warg_protocol::registry::PackageId;
use wit_component::DecodedWasm;
use wit_parser::{PackageName, UnresolvedPackage};

pub(crate) fn find_url<'a>(
    name: Option<&str>,
    urls: &'a HashMap<String, Url>,
    default: Option<&'a str>,
) -> Result<&'a str> {
    let name = name.unwrap_or(DEFAULT_REGISTRY_NAME);
    match urls.get(name) {
        Some(url) => Ok(url.as_str()),
        None if name != DEFAULT_REGISTRY_NAME => {
            bail!("registry `{name}` does not exist in the configuration")
        }
        None => default.ok_or_else(|| anyhow!("a default registry has not been set")),
    }
}

pub(crate) fn create_client(config: &warg_client::Config, url: &str) -> Result<FileSystemClient> {
    match FileSystemClient::try_new_with_config(Some(url), config)? {
        StorageLockResult::Acquired(client) => Ok(client),
        StorageLockResult::NotAcquired(path) => {
            println!(
                "{blocking} on access to lock file `{path}`",
                blocking = "blocking".cyan(),
                path = path.display()
            );

            Ok(FileSystemClient::new_with_config(Some(url), config)?)
        }
    }
}

/// Represents information about a resolution of a registry package.
#[derive(Clone, Debug)]
pub struct RegistryResolution {
    /// The id of the dependency that was resolved.
    ///
    /// This may differ from the package id if the dependency was renamed.
    pub id: PackageId,
    /// The id of the package from the registry that was resolved.
    pub package: PackageId,
    /// The name of the registry used to resolve the package.
    ///
    /// A value of `None` indicates that the default registry was used.
    pub registry: Option<String>,
    /// The version requirement that was used to resolve the package.
    pub requirement: VersionReq,
    /// The package version that was resolved.
    pub version: Version,
    /// The digest of the package contents.
    pub digest: AnyHash,
    /// The path to the resolved dependency.
    pub path: PathBuf,
}

/// Represents information about a resolution of a local file.
#[derive(Clone, Debug)]
pub struct LocalResolution {
    /// The id of the dependency that was resolved.
    pub id: PackageId,
    /// The path to the resolved dependency.
    pub path: PathBuf,
}

/// Represents a resolution of a dependency.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum DependencyResolution {
    /// The dependency is resolved from a registry package.
    Registry(RegistryResolution),
    /// The dependency is resolved from a local path.
    Local(LocalResolution),
}

impl DependencyResolution {
    /// Gets the id of the dependency that was resolved.
    pub fn id(&self) -> &PackageId {
        match self {
            Self::Registry(res) => &res.id,
            Self::Local(res) => &res.id,
        }
    }

    /// Gets the path to the resolved dependency.
    pub fn path(&self) -> &Path {
        match self {
            Self::Registry(res) => &res.path,
            Self::Local(res) => &res.path,
        }
    }

    /// The key used in sorting and searching the lock file package list.
    ///
    /// Returns `None` if the dependency is not resolved from a registry package.
    pub(crate) fn key(&self) -> Option<(&PackageId, Option<&str>)> {
        match self {
            DependencyResolution::Registry(pkg) => Some((&pkg.package, pkg.registry.as_deref())),
            DependencyResolution::Local(_) => None,
        }
    }

    /// Decodes the resolved dependency.
    pub fn decode(&self) -> Result<DecodedDependency> {
        // If the dependency path is a directory, assume it contains wit to parse as a package.
        if self.path().is_dir() {
            return Ok(DecodedDependency::Wit {
                resolution: self,
                package: UnresolvedPackage::parse_dir(self.path()).with_context(|| {
                    format!(
                        "failed to parse dependency `{path}`",
                        path = self.path().display()
                    )
                })?,
            });
        }

        let bytes = fs::read(self.path()).with_context(|| {
            format!(
                "failed to read content of dependency `{id}` at path `{path}`",
                id = self.id(),
                path = self.path().display()
            )
        })?;

        if &bytes[0..4] != b"\0asm" {
            return Ok(DecodedDependency::Wit {
                resolution: self,
                package: UnresolvedPackage::parse(
                    self.path(),
                    std::str::from_utf8(&bytes).with_context(|| {
                        format!(
                            "dependency `{path}` is not UTF-8 encoded",
                            path = self.path().display()
                        )
                    })?,
                )?,
            });
        }

        Ok(DecodedDependency::Wasm {
            resolution: self,
            decoded: wit_component::decode(&bytes).with_context(|| {
                format!(
                    "failed to decode content of dependency `{id}` at path `{path}`",
                    id = self.id(),
                    path = self.path().display()
                )
            })?,
        })
    }
}

/// Represents a decoded dependency.
pub enum DecodedDependency<'a> {
    /// The dependency decoded from an unresolved WIT package.
    Wit {
        /// The resolution related to the decoded dependency.
        resolution: &'a DependencyResolution,
        /// The unresolved WIT package.
        package: UnresolvedPackage,
    },
    /// The dependency decoded from a Wasm file.
    Wasm {
        /// The resolution related to the decoded dependency.
        resolution: &'a DependencyResolution,
        /// The decoded Wasm file.
        decoded: DecodedWasm,
    },
}

impl<'a> DecodedDependency<'a> {
    /// Gets the package name of the decoded dependency.
    pub fn package_name(&self) -> &PackageName {
        match self {
            Self::Wit { package, .. } => &package.name,
            Self::Wasm { decoded, .. } => &decoded.resolve().packages[decoded.package()].name,
        }
    }
}

/// Represents a resolver for a lock file.
pub struct LockFileResolver<'a>(&'a LockFile);

impl<'a> LockFileResolver<'a> {
    /// Creates a new lock file resolver for the given workspace and lock file.
    pub fn new(lock_file: &'a LockFile) -> Self {
        Self(lock_file)
    }

    /// Resolves a package from the lock file.
    ///
    /// Returns `Ok(None)` if the package cannot be resolved.
    pub fn resolve(
        &'a self,
        registry: &str,
        id: &PackageId,
        requirement: &VersionReq,
    ) -> Result<Option<&'a LockedPackageVersion>> {
        if let Some(pkg) = self
            .0
            .packages
            .binary_search_by_key(&(id, registry), LockedPackage::key)
            .ok()
            .map(|i| &self.0.packages[i])
        {
            if let Ok(index) = pkg
                .versions
                .binary_search_by_key(&requirement.to_string().as_str(), LockedPackageVersion::key)
            {
                let locked = &pkg.versions[index];
                tracing::info!("dependency package `{id}` from registry `{registry}` with requirement `{requirement}` was resolved by the lock file to version {version}", version = locked.version);
                return Ok(Some(locked));
            }
        }

        tracing::info!("dependency package `{id}` from registry `{registry}` with requirement `{requirement}` was not in the lock file");
        Ok(None)
    }
}

/// Used to resolve dependencies for a WIT package.
pub struct DependencyResolver<'a> {
    config: &'a Config,
    warg_config: warg_client::Config,
    lock_file: Option<LockFileResolver<'a>>,
    registries: IndexMap<&'a str, Registry<'a>>,
    resolutions: HashMap<PackageId, DependencyResolution>,
}

impl<'a> DependencyResolver<'a> {
    /// Creates a new dependency resolver.
    pub fn new(
        config: &'a Config,
        lock_file: Option<&'a LockFile>,
    ) -> Result<DependencyResolver<'a>> {
        Ok(DependencyResolver {
            config,
            warg_config: warg_client::Config::from_default_file()?.unwrap_or_default(),
            lock_file: lock_file.map(LockFileResolver::new),
            registries: Default::default(),
            resolutions: Default::default(),
        })
    }

    /// Add a dependency to the resolver.
    pub async fn add_dependency(
        &mut self,
        id: &'a PackageId,
        dependency: &'a Dependency,
    ) -> Result<()> {
        match dependency {
            Dependency::Package(package) => {
                // Dependency comes from a registry, add a dependency to the resolver
                let registry_name = package.registry.as_deref().unwrap_or(DEFAULT_REGISTRY_NAME);
                let package_id = package.id.clone().unwrap_or_else(|| id.clone());

                // Resolve the version from the lock file if there is one
                let locked = match self.lock_file.as_ref().and_then(|resolver| {
                    resolver
                        .resolve(registry_name, &package_id, &package.version)
                        .transpose()
                }) {
                    Some(Ok(locked)) => Some(locked),
                    Some(Err(e)) => return Err(e),
                    _ => None,
                };

                let registry = match self.registries.entry(registry_name) {
                    indexmap::map::Entry::Occupied(e) => e.into_mut(),
                    indexmap::map::Entry::Vacant(e) => {
                        let url = find_url(
                            Some(registry_name),
                            &self.config.registries,
                            self.warg_config.default_url.as_deref(),
                        )?;
                        e.insert(Registry {
                            client: Arc::new(create_client(&self.warg_config, url)?),
                            packages: HashMap::new(),
                            dependencies: Vec::new(),
                            upserts: HashSet::new(),
                        })
                    }
                };

                registry
                    .add_dependency(id, package_id, &package.version, registry_name, locked)
                    .await?;
            }
            Dependency::Local(p) => {
                // A local path dependency, insert a resolution immediately
                let res = DependencyResolution::Local(LocalResolution {
                    id: id.clone(),
                    path: p.clone(),
                });

                let prev = self.resolutions.insert(id.clone(), res);
                assert!(prev.is_none());
            }
        }

        Ok(())
    }

    /// Resolve all dependencies.
    ///
    /// This will download all dependencies that are not already present in client storage.
    ///
    /// Returns the dependency resolution map.
    pub async fn resolve(self) -> Result<DependencyResolutionMap> {
        let Self {
            mut registries,
            mut resolutions,
            ..
        } = self;

        // Start by updating the packages that need updating
        // This will determine the contents that need to be downloaded
        let downloads = Self::update_packages(&mut registries).await?;

        // Finally, download and resolve the dependencies
        for resolution in Self::download_and_resolve(registries, downloads).await? {
            let prev = resolutions.insert(resolution.id().clone(), resolution);
            assert!(prev.is_none());
        }

        Ok(resolutions)
    }

    async fn update_packages(
        registries: &mut IndexMap<&'a str, Registry<'a>>,
    ) -> Result<DownloadMap<'a>> {
        let task_count = registries
            .iter()
            .filter(|(_, r)| !r.upserts.is_empty())
            .count();

        let progress = ProgressBar::new(task_count as u64);
        progress.set_style(
            ProgressStyle::with_template(&format!(
                "{updating} [{{bar:20}}] {{pos:>4}}/{{len}}: {{msg}}",
                updating = "updating".cyan()
            ))
            .unwrap()
            .progress_chars("=> "),
        );

        if task_count > 0 {
            println!(
                "{updating} registry package logs...",
                updating = "updating".bright_green()
            );

            progress.set_message("...");
        }

        let mut downloads = DownloadMap::new();
        let mut futures = FuturesUnordered::new();
        for (index, (name, registry)) in registries.iter_mut().enumerate() {
            let upserts = std::mem::take(&mut registry.upserts);
            if upserts.is_empty() {
                // No upserts needed, add the necessary downloads now
                registry.add_downloads(name, &mut downloads).await?;
                continue;
            }

            tracing::info!("updating package logs for registry `{name}`");

            let client = registry.client.clone();
            futures.push(tokio::spawn(async move {
                (index, client.upsert(upserts.iter()).await)
            }))
        }

        assert_eq!(futures.len(), task_count);

        let mut finished = 0;
        while let Some(res) = futures.next().await {
            let (index, res) = res.context("failed to join registry update task")?;
            let (name, registry) = registries
                .get_index_mut(index)
                .expect("out of bounds registry index");

            res.with_context(|| format!("failed to update package logs for registry `{name}`"))?;

            tracing::info!("package logs successfully updated for registry `{name}`");
            finished += 1;
            progress.inc(1);
            progress.set_message(format!("updated registry `{name}`"));
            registry.add_downloads(name, &mut downloads).await?;
        }

        assert_eq!(finished, task_count);

        Ok(downloads)
    }

    async fn download_and_resolve(
        mut registries: IndexMap<&'a str, Registry<'a>>,
        downloads: DownloadMap<'a>,
    ) -> Result<impl Iterator<Item = DependencyResolution> + 'a> {
        if !downloads.is_empty() {
            println!(
                "{downloading} registry packages...",
                downloading = "downloading".bright_green()
            );

            let count = downloads.len();
            let progress = ProgressBar::new(count as u64);
            progress.set_style(
                ProgressStyle::with_template(&format!(
                    "{downloading} [{{bar:20}}] {{pos:>4}}/{{len}}: {{msg}}",
                    downloading = "downloading".cyan()
                ))
                .unwrap()
                .progress_chars("=> "),
            );
            progress.set_message("...");

            let mut futures = FuturesUnordered::new();
            for ((registry_name, package, version), deps) in downloads {
                let registry_index = registries.get_index_of(registry_name).unwrap();
                let (_, registry) = registries.get_index(registry_index).unwrap();

                tracing::info!("downloading content for registry package `{package}` from registry `{registry_name}`");

                let client = registry.client.clone();
                futures.push(tokio::spawn(async move {
                    let res = client.download_exact(&package, &version).await;
                    (registry_index, package, version, deps, res)
                }))
            }

            assert_eq!(futures.len(), count);

            let mut finished = 0;
            while let Some(res) = futures.next().await {
                let (registry_index, id, version, deps, res) =
                    res.context("failed to join content download task")?;
                let (name, registry) = registries
                    .get_index_mut(registry_index)
                    .expect("out of bounds registry index");

                let download = res.with_context(|| {
                    format!("failed to download package `{id}` (v{version}) from registry `{name}`")
                })?;

                tracing::info!(
                    "downloaded contents of package `{id}` (v{version}) from registry `{name}`"
                );

                finished += 1;
                progress.inc(1);
                progress.set_message(format!("downloaded `{id}` (v{version})"));

                for index in deps {
                    let dependency = &mut registry.dependencies[index];
                    assert!(dependency.resolution.is_none());
                    dependency.resolution = Some(RegistryResolution {
                        id: dependency.id.clone(),
                        package: dependency.package.clone(),
                        registry: if *name == DEFAULT_REGISTRY_NAME {
                            None
                        } else {
                            Some(name.to_string())
                        },
                        requirement: dependency.version.clone(),
                        version: download.version.clone(),
                        digest: download.digest.clone(),
                        path: download.path.clone(),
                    });
                }
            }

            assert_eq!(finished, count);
        }

        Ok(registries
            .into_values()
            .flat_map(|r| r.dependencies.into_iter())
            .map(|d| {
                DependencyResolution::Registry(
                    d.resolution.expect("dependency should have been resolved"),
                )
            }))
    }
}

struct Registry<'a> {
    client: Arc<FileSystemClient>,
    packages: HashMap<PackageId, PackageInfo>,
    dependencies: Vec<RegistryDependency<'a>>,
    upserts: HashSet<PackageId>,
}

impl<'a> Registry<'a> {
    async fn add_dependency(
        &mut self,
        id: &'a PackageId,
        package: PackageId,
        version: &'a VersionReq,
        registry: &str,
        locked: Option<&LockedPackageVersion>,
    ) -> Result<()> {
        let dep = RegistryDependency {
            id,
            package: package.clone(),
            version,
            locked: locked.map(|l| (l.version.clone(), l.digest.clone())),
            resolution: None,
        };

        self.dependencies.push(dep);

        let mut needs_upsert = true;
        if let Some(locked) = locked {
            if let Some(package) =
                Self::load_package(&self.client, &mut self.packages, package.clone()).await?
            {
                if package
                    .state
                    .release(&locked.version)
                    .and_then(|r| r.content())
                    .is_some()
                {
                    // Don't need to upsert this package as it is present
                    // in the lock file and in client storage.
                    needs_upsert = false;
                }
            }
        }

        if needs_upsert && self.upserts.insert(package.clone()) {
            tracing::info!(
                "registry package `{package}` from registry `{registry}` needs to be updated"
            );
        }

        Ok(())
    }

    async fn add_downloads(
        &mut self,
        registry: &'a str,
        downloads: &mut DownloadMap<'a>,
    ) -> Result<()> {
        let Self {
            dependencies,
            packages,
            client,
            ..
        } = self;

        for (index, dependency) in dependencies.iter_mut().enumerate() {
            let package = Self::load_package(client, packages, dependency.package.clone())
                .await?
                .ok_or_else(|| {
                    anyhow!(
                        "registry package `{name}` not found in registry `{registry}`",
                        name = dependency.package
                    )
                })?;

            let release = match &dependency.locked {
                Some((version, digest)) => {
                    // The dependency had a lock file entry, so attempt to do an exact match first
                    let exact_req = VersionReq {
                        comparators: vec![Comparator {
                            op: Op::Exact,
                            major: version.major,
                            minor: Some(version.minor),
                            patch: Some(version.patch),
                            pre: version.pre.clone(),
                        }],
                    };

                    // If an exact match can't be found, fallback to the latest release to
                    // satisfy the version requirement; this can happen when packages are yanked
                    package.state.find_latest_release(&exact_req).map(|r| {
                        // Exact match, verify the content digests match
                        let content = r.content().expect("release must have content");
                        if content != digest {
                            bail!(
                                "registry package `{name}` (v`{version}`) has digest `{content}` but the lock file specifies digest `{digest}`",
                                name = dependency.package,
                            );
                        }
                        Ok(r)
                    }).transpose()?.or_else(|| package.state.find_latest_release(dependency.version))
                }
                None => package.state.find_latest_release(dependency.version),
            }.ok_or_else(|| anyhow!("registry package `{name}` has no release matching version requirement `{version}`", name = dependency.package, version = dependency.version))?;

            let digest = release.content().expect("release must have content");
            match client.content().content_location(digest) {
                Some(path) => {
                    // Content is already present, set the resolution
                    assert!(dependency.resolution.is_none());
                    dependency.resolution = Some(RegistryResolution {
                        id: dependency.id.clone(),
                        package: dependency.package.clone(),
                        registry: if registry == DEFAULT_REGISTRY_NAME {
                            None
                        } else {
                            Some(registry.to_string())
                        },
                        requirement: dependency.version.clone(),
                        version: release.version.clone(),
                        digest: digest.clone(),
                        path,
                    });

                    tracing::info!(
                        "version {version} of registry package `{name}` from registry `{registry}` is already in client storage",
                        name = dependency.package,
                        version = release.version,
                    );
                }
                None => {
                    // Content needs to be downloaded
                    let indexes = downloads
                        .entry((
                            registry,
                            dependency.package.clone(),
                            release.version.clone(),
                        ))
                        .or_default();

                    if indexes.is_empty() {
                        tracing::info!(
                            "version {version} of registry package `{name}` from registry `{registry}` needs to be downloaded",
                            name = dependency.package,
                            version = release.version,
                        );
                    }

                    indexes.push(index);
                }
            }
        }

        Ok(())
    }

    async fn load_package<'b>(
        client: &FileSystemClient,
        packages: &'b mut HashMap<PackageId, PackageInfo>,
        id: PackageId,
    ) -> Result<Option<&'b PackageInfo>> {
        match packages.entry(id) {
            hash_map::Entry::Occupied(e) => Ok(Some(e.into_mut())),
            hash_map::Entry::Vacant(e) => match client.registry().load_package(e.key()).await? {
                Some(p) => Ok(Some(e.insert(p))),
                None => Ok(None),
            },
        }
    }
}

type DownloadMapKey<'a> = (&'a str, PackageId, Version);
type DownloadMap<'a> = HashMap<DownloadMapKey<'a>, Vec<usize>>;

struct RegistryDependency<'a> {
    /// The package ID assigned in the configuration file.
    id: &'a PackageId,
    /// The package ID of the registry package.
    package: PackageId,
    version: &'a VersionReq,
    locked: Option<(Version, AnyHash)>,
    resolution: Option<RegistryResolution>,
}

pub type DependencyResolutionMap = HashMap<PackageId, DependencyResolution>;
