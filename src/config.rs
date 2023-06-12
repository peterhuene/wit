//! Module for WIT package configuration.

use anyhow::{Context, Result};
use semver::{Version, VersionReq};
use serde::{
    de::{self, value::MapAccessDeserializer},
    Deserialize, Serialize,
};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use url::Url;
use warg_protocol::registry::PackageId;

/// The name of the default registry in the registry map.
pub const DEFAULT_REGISTRY_NAME: &str = "default";
/// The default name of the configuration file.
pub const CONFIG_FILE_NAME: &str = "wit.toml";

fn find_config(cwd: &Path) -> Option<PathBuf> {
    let mut current = Some(cwd);

    while let Some(dir) = current {
        let config = dir.join(CONFIG_FILE_NAME);
        if config.is_file() {
            return Some(config);
        }

        current = dir.parent();
    }

    None
}

/// Used to construct a new WIT package configuration.
#[derive(Default)]
pub struct ConfigBuilder {
    version: Option<Version>,
    registries: HashMap<String, Url>,
}

impl ConfigBuilder {
    /// Creates a new configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the version to use in the configuration.
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self
    }

    /// Adds a registry to the configuration.
    pub fn with_registry(mut self, name: impl Into<String>, url: Url) -> Self {
        self.registries.insert(name.into(), url);
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Config {
        Config {
            version: self.version.unwrap_or_else(|| Version::new(0, 1, 0)),
            dependencies: Default::default(),
            registries: self.registries,
        }
    }
}

/// Represents a WIT package configuration.
#[derive(Serialize, Deserialize)]
pub struct Config {
    /// The current package version.
    pub version: Version,
    /// The package dependencies.
    pub dependencies: HashMap<PackageId, Dependency>,
    /// The registries to use for sourcing packages.
    pub registries: HashMap<String, Url>,
}

impl Config {
    /// Loads a WIT package configuration from a default file path.
    ///
    /// This will search for a configuration file in the current directory and
    /// all parent directories.
    ///
    /// Returns both the configuration file and the path it was located at.
    ///
    /// Returns `Ok(None)` if no configuration file was found.
    pub fn from_default_file() -> Result<Option<(Self, PathBuf)>> {
        if let Some(path) = find_config(&std::env::current_dir()?) {
            return Ok(Some((Self::from_file(&path)?, path)));
        }

        Ok(None)
    }

    /// Loads a WIT package configuration from the given file path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).with_context(|| {
            format!(
                "failed to read configuration file `{path}`",
                path = path.display()
            )
        })?;

        toml_edit::de::from_str(&contents).with_context(|| {
            format!(
                "failed to parse configuration file `{path}`",
                path = path.display()
            )
        })
    }

    /// Writes the configuration to the given file path.
    pub fn write(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();

        let contents = toml_edit::ser::to_string_pretty(self).with_context(|| {
            format!(
                "failed to serialize configuration file `{path}`",
                path = path.display()
            )
        })?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create parent directory for `{path}`",
                    path = path.display()
                )
            })?;
        }

        fs::write(path, contents).with_context(|| {
            format!(
                "failed to write configuration file `{path}`",
                path = path.display()
            )
        })?;

        Ok(())
    }
}

/// Represents a WIT package dependency.
pub enum Dependency {
    /// The dependency is a registry package.
    Package(RegistryPackage),

    /// The dependency is a path to a local directory or file.
    Local(PathBuf),
}

impl Serialize for Dependency {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Package(package) => {
                if package.id.is_none() && package.registry.is_none() {
                    let version = package.version.to_string();
                    version.trim_start_matches('^').serialize(serializer)
                } else {
                    #[derive(Serialize)]
                    struct Entry<'a> {
                        package: Option<&'a PackageId>,
                        version: &'a str,
                        registry: Option<&'a str>,
                    }

                    Entry {
                        package: package.id.as_ref(),
                        version: package.version.to_string().trim_start_matches('^'),
                        registry: package.registry.as_deref(),
                    }
                    .serialize(serializer)
                }
            }
            Self::Local(path) => path.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Dependency {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Dependency;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a string or a table")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Self::Value::Package(s.parse().map_err(de::Error::custom)?))
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                #[derive(Default, Deserialize)]
                #[serde(default, deny_unknown_fields)]
                struct Entry {
                    path: Option<PathBuf>,
                    package: Option<PackageId>,
                    version: Option<VersionReq>,
                    registry: Option<String>,
                }

                let entry = Entry::deserialize(MapAccessDeserializer::new(map))?;

                match (entry.path, entry.package, entry.version, entry.registry) {
                    (Some(path), None, None, None) => Ok(Self::Value::Local(path)),
                    (None, id, Some(version), registry) => {
                        Ok(Self::Value::Package(RegistryPackage {
                            id,
                            version,
                            registry,
                        }))
                    }
                    (Some(_), None, Some(_), _) => Err(de::Error::custom(
                        "cannot specify both `path` and `version` fields in a dependency entry",
                    )),
                    (Some(_), None, None, Some(_)) => Err(de::Error::custom(
                        "cannot specify both `path` and `registry` fields in a dependency entry",
                    )),
                    (Some(_), Some(_), _, _) => Err(de::Error::custom(
                        "cannot specify both `path` and `package` fields in a dependency entry",
                    )),
                    (None, None, _, _) => Err(de::Error::missing_field("package")),
                    (None, Some(_), None, _) => Err(de::Error::missing_field("version")),
                }
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

impl FromStr for Dependency {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self::Package(s.parse()?))
    }
}

/// Represents a reference to a registry package.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryPackage {
    /// The id of the package.
    ///
    /// If not specified, the id from the mapping will be used.
    pub id: Option<PackageId>,

    /// The version requirement of the package.
    pub version: VersionReq,

    /// The name of the component registry containing the package.
    ///
    /// If not specified, the default registry is used.
    pub registry: Option<String>,
}

impl FromStr for RegistryPackage {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self {
            id: None,
            version: s.parse()?,
            registry: None,
        })
    }
}
