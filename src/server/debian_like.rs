use std::env;
use std::fs;
use std::io;
use std::str;

use anyhow::Context;
use async_std::task;
use serde::Serialize;

use crate::process;
use crate::server::detect::{Lazy, ARCH};
use crate::server::distribution::{DistributionRef, Distribution};
use crate::server::docker::DockerCandidate;
use crate::server::install::{self, Operation, Command};
use crate::server::methods::InstallationMethods;
use crate::server::package::{RepositoryInfo, PackageCandidate, Package};
use crate::server::remote;
use crate::server::unix;
use crate::server::version::{Version, VersionSlot};


#[derive(Debug, Serialize)]
pub struct Debian {
    pub distro: &'static str,
    pub codename: String,
    #[serde(skip)]
    stable_repo: Lazy<Option<RepositoryInfo>>,
    #[serde(skip)]
    nightly_repo: Lazy<Option<RepositoryInfo>>,
}


fn sources_list_path(nightly: bool) -> &'static str {
    if nightly {
        "/etc/apt/sources.list.d/edgedb_server_install_nightly.list"
    } else {
        "/etc/apt/sources.list.d/edgedb_server_install.list"
    }
}

fn sources_list(codename: &str, nightly: bool) -> String {
    format!("deb https://packages.edgedb.com/apt {}{} main\n", codename,
        if nightly { ".nightly" } else { "" } )
}

impl Debian {
    pub fn new(distro: &'static str, codename: String) -> Debian {
        Debian {
            distro,
            codename,
            stable_repo: Lazy::lazy(),
            nightly_repo: Lazy::lazy(),
        }
    }
    pub fn get_repo(&self, nightly: bool)
        -> anyhow::Result<Option<&RepositoryInfo>>
    {
        if nightly {
            self.nightly_repo.get_or_try_init(|| {
                task::block_on(remote::get_json_opt(
                    &format!("https://packages.edgedb.com/apt/.jsonindexes/\
                            {}.nightly.json",
                            self.codename),
                    "failed to fetch repository index"))
            }).map(|opt| opt.as_ref())
        } else {
            self.stable_repo.get_or_try_init(|| {
                task::block_on(remote::get_json_opt(
                    &format!("https://packages.edgedb.com/apt/.jsonindexes/\
                            {}.json",
                            self.codename),
                    "failed to fetch repository index"))
            }).map(|opt| opt.as_ref())
        }
    }
    pub fn all_versions(&self, nightly: bool)
        -> anyhow::Result<Vec<DistributionRef>>
    {
        Ok(self.get_repo(nightly)?
            .map(|x| {
                x.packages.iter()
                .filter(|p| p.basename == "edgedb-server" && p.slot.is_some())
                .map(|p| p.into())
                .collect()
            }).unwrap_or_else(Vec::new))
    }
    pub fn get_available_methods(&self, refresh: bool)
        -> Result<InstallationMethods, anyhow::Error>
    {
        let version_supported = unix::cache_package_support(
            &self.distro, &self.codename, ARCH, refresh,
            || {
                let found = self.get_repo(false)?
                    .map(|repo| repo.packages.iter().any(|p| {
                        (p.basename == "edgedb" ||
                         p.basename == "edgedb-server")
                        && p.architecture == ARCH
                    }))
                    .unwrap_or(false);
                Ok(found)
            },
        )?;
        Ok(InstallationMethods {
            package: PackageCandidate {
                supported: version_supported,
                distro_name: self.distro.into(),
                distro_version: self.codename.clone(),
                distro_supported: true,
                version_supported,
            },
            docker: DockerCandidate::detect()?,
        })
    }
    pub fn install_operations(&self, settings: &install::Settings)
        -> anyhow::Result<Vec<Operation>>
    {
        let pkg = settings.distribution.downcast_ref::<Package>()
            .context("invalid debian package")?;
        let key = task::block_on(remote::get_string(install::KEY_FILE_URL))
            .context("downloading key file")?;
        let mut operations = Vec::new();
        operations.push(Operation::PrivilegedCmd(
            Command::new("apt-get")
                .arg("update")
        ));
        operations.push(Operation::PrivilegedCmd(
            Command::new("apt-get")
                .arg("install")
                .arg("-y")
                .args(&["gnupg", "apt-transport-https"])
        ));
        operations.push(Operation::FeedPrivilegedCmd {
            input: key.into(),
            cmd: Command::new("apt-key")
                // this supresses "output should not be parsed" warning
                .env("APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE", "1")
                .arg("add")
                .arg("-"),
        });
        let nightly = settings.distribution.version_slot().is_nightly();
        let sources_list = sources_list(&self.codename, nightly);
        let list_path = sources_list_path(nightly);
        let update_list = match fs::read(list_path) {
            Ok(data) => {
                let data_text = str::from_utf8(&data).map(|x| x.trim());
                data_text != Ok(sources_list.trim())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Err(e) => {
                log::warn!("Unable to read {} file: {:#}. Will replace...",
                    list_path, e);
                true
            }
        };
        if update_list {
            operations.push(Operation::WritePrivilegedFile {
                path: list_path.into(),
                data: sources_list.into(),
            });
        }
        operations.push(Operation::PrivilegedCmd(
            Command::new("apt-get")
                .arg("update")
                // TODO(tailhook) uncomment them we fix
                // https://github.com/edgedb/edgedb-pkg/issues/7
                //
                // .arg("--no-list-cleanup")
                // .arg("-o")
                //     .arg(format!("Dir::Etc::sourcelist={}", list_path))
                // .arg("-o").arg("Dir::Etc::sourceparts=-")
        ));
        operations.push(Operation::PrivilegedCmd(
            Command::new("apt-get")
            .arg("install")
            .arg("-y")
            // TODO(tailhook) version
            .arg(format!("edgedb-server-{}", pkg.slot.slot_name()))
            .env("_EDGEDB_INSTALL_SKIP_BOOTSTRAP", "1")
            .env("DEBIAN_FRONTEND",
                env::var("DEBIAN_FRONTEND")
                .unwrap_or_else(|_| "noninteractive".into()))
        ));
        return Ok(operations);
    }
    pub fn uninstall_operations(&self, distr: &DistributionRef)
        -> anyhow::Result<Vec<Operation>>
    {
        let pkg = distr.downcast_ref::<Package>()
            .context("invalid debian package")?;
        let mut operations = Vec::new();
        operations.push(Operation::PrivilegedCmd(
            Command::new("apt-get")
                .arg("remove")
                .arg("-y")
                .arg(format!("edgedb-server-{}", pkg.slot.slot_name()))
        ));
        return Ok(operations);
    }
}

pub fn get_installed() -> anyhow::Result<Vec<DistributionRef>> {
    let mut cmd = process::Native::new(
        "list packages", "apt-cache", "apt-cache");
    cmd.arg("policy");
    cmd.arg("^edgedb-server-[0-9]");
    let listing = cmd.get_stdout_text()?;
    let mut result = Vec::new();
    let mut current_slot = None;
    for line in listing.lines() {
        if let Some(package_line) = line.strip_prefix("edgedb-server-") {
            if let Some(slot) = package_line.strip_suffix(":") {
                current_slot = Some(slot);
            }
        } else if let Some(slot) = current_slot {
            let line = line.trim();
            if line.starts_with("Installed:") {
                let ver = line["Installed:".len()..].trim();
                if ver == "(none)" {
                    current_slot = None;
                    continue;
                }
                result.push(Package {
                    version: Version(ver.to_owned()),
                    slot: if ver.contains(".dev") {
                        VersionSlot::Nightly(Version(slot.into()))
                    } else {
                        VersionSlot::Stable(Version(slot.into()))
                    },
                }.into_ref());
                current_slot = None;
            }
        }
    }
    Ok(result)
}
