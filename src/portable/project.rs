use std::env;
use std::io;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::str::FromStr;

use anyhow::Context;
use clap::{ValueHint};
use fn_error_context::context;
use rand::{thread_rng, Rng};
use sha1::Digest;

use edgedb_cli_derive::EdbClap;
use edgedb_errors::DuplicateDatabaseDefinitionError;
use edgedb_tokio::Builder;
use edgeql_parser::helpers::quote_name;

use crate::connect::Connection;
use crate::cloud;
use crate::cloud::client::CloudClient;
use crate::commands::ExitCode;
use crate::connect::Connector;
use crate::credentials;
use crate::migrations;
use crate::platform::{path_bytes, bytes_to_path};
use crate::platform::{tmp_file_path, symlink_dir, config_dir};
use crate::portable::config;
use crate::portable::control;
use crate::portable::create;
use crate::portable::destroy;
use crate::portable::exit_codes;
use crate::portable::install;
use crate::portable::local::{InstanceInfo, Paths, allocate_port};
use crate::portable::options::{self, StartConf, Start, InstanceName};
use crate::portable::platform::{optional_docker_check};
use crate::portable::repository::{self, Channel, Query, PackageInfo};
use crate::portable::upgrade;
use crate::portable::ver;
use crate::portable::windows;
use crate::print::{self, echo, Highlight};
use crate::question;
use crate::table;



const DEFAULT_ESDL: &str = "\
    module default {\n\
    \n\
    }\n\
";

const FUTURES_ESDL: &str = "\
    # Disable the application of access policies within access policies\n\
    # themselves. This behavior will become the default in EdgeDB 3.0.\n\
    # See: https://www.edgedb.com/docs/reference/ddl/access_policies#nonrecursive\n\
    using future nonrecursive_access_policies;\n\
";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectInfo {
    instance_name: String,
    stash_dir: PathBuf,
}

#[derive(EdbClap, Debug, Clone)]
pub struct ProjectCommand {
    #[clap(subcommand)]
    pub subcommand: Command,
}

#[derive(EdbClap, Clone, Debug)]
pub enum Command {
    /// Initialize a new or existing project
    #[edb(inherit(crate::options::CloudOptions))]
    Init(Init),
    /// Clean-up the project configuration
    #[edb(inherit(crate::options::CloudOptions))]
    Unlink(Unlink),
    /// Get various metadata about the project
    Info(Info),
    /// Upgrade EdgeDB instance used for the current project
    ///
    /// This command has two modes of operation.
    ///
    /// Upgrade instance to a version specified in `edgedb.toml`:
    ///
    ///     project upgrade
    ///
    /// Update `edgedb.toml` to a new version and upgrade the instance:
    ///
    ///     project upgrade --to-latest
    ///     project upgrade --to-version=1-beta2
    ///     project upgrade --to-nightly
    ///
    /// In all cases your data is preserved and converted using dump/restore
    /// mechanism. This might fail if lower version is specified (for example
    /// if upgrading from nightly to the stable version).
    Upgrade(Upgrade),
}

#[derive(EdbClap, Debug, Clone)]
pub struct Init {
    /// Specifies a project root directory explicitly.
    #[clap(long, value_hint=ValueHint::DirPath)]
    pub project_dir: Option<PathBuf>,

    /// Specifies the desired EdgeDB server version
    #[clap(long)]
    pub server_version: Option<Query>,

    /// Specifies whether the existing EdgeDB server instance
    /// should be linked with the project
    #[clap(long)]
    pub link: bool,

    /// Specifies the EdgeDB server instance to be associated with the project
    #[clap(long)]
    pub server_instance: Option<InstanceName>,

    /// Specifies the default database for the project to use on that instance
    #[clap(long, short='d')]
    pub database: Option<String>,

    /// Deprecated. Has no action
    #[clap(long, hide=true, possible_values=&["auto", "manual"][..])]
    pub server_start_conf: Option<StartConf>,

    /// Skip running migrations
    ///
    /// There are two main use cases for this option:
    /// 1. With `--link` option to connect to a datastore with existing data
    /// 2. To initialize a new instance but then restore dump to it
    #[clap(long)]
    pub no_migrations: bool,

    /// Run in non-interactive mode (accepting all defaults)
    #[clap(long)]
    pub non_interactive: bool,
}

#[derive(EdbClap, Debug, Clone)]
pub struct Unlink {
    /// Specifies a project root directory explicitly.
    #[clap(long, value_hint=ValueHint::DirPath)]
    pub project_dir: Option<PathBuf>,

    /// If specified, the associated EdgeDB instance is destroyed by running
    /// `edgedb instance destroy`.
    #[clap(long, short='D')]
    pub destroy_server_instance: bool,

    #[clap(long)]
    pub non_interactive: bool,
}

#[derive(EdbClap, Debug, Clone)]
pub struct Info {
    /// Specifies a project root directory explicitly.
    #[clap(long, value_hint=ValueHint::DirPath)]
    pub project_dir: Option<PathBuf>,

    /// Display only the instance name (shortcut to `--get instance-name`)
    #[clap(long)]
    pub instance_name: bool,

    /// Output in JSON format
    #[clap(long)]
    pub json: bool,

    #[clap(long, possible_values=&[
        "instance-name",
        "cloud-profile",
    ][..])]
    /// Get specific value:
    ///
    /// * `instance-name` -- Name of the listance the project is linked to
    pub get: Option<String>,
}

#[derive(EdbClap, Debug, Clone)]
pub struct Upgrade {
    /// Specifies a project root directory explicitly.
    #[clap(long, value_hint=ValueHint::DirPath)]
    pub project_dir: Option<PathBuf>,

    /// Upgrade specified instance to the latest version
    #[clap(long)]
    #[clap(conflicts_with_all=&[
        "to_version", "to_testing", "to_nightly", "to_channel",
    ])]
    pub to_latest: bool,

    /// Upgrade specified instance to a specified version
    #[clap(long)]
    #[clap(conflicts_with_all=&[
        "to_testing", "to_latest", "to_nightly", "to_channel",
    ])]
    pub to_version: Option<ver::Filter>,

    /// Upgrade specified instance to a latest nightly version
    #[clap(long)]
    #[clap(conflicts_with_all=&[
        "to_version", "to_latest", "to_testing", "to_channel",
    ])]
    pub to_nightly: bool,

    /// Upgrade specified instance to a latest testing version
    #[clap(long)]
    #[clap(conflicts_with_all=&[
        "to_version", "to_latest", "to_nightly", "to_channel",
    ])]
    pub to_testing: bool,

    /// Upgrade specified instance to the specified channel
    #[clap(long, value_enum)]
    #[clap(conflicts_with_all=&[
        "to_version", "to_latest", "to_nightly", "to_testing",
    ])]
    pub to_channel: Option<Channel>,

    /// Verbose output
    #[clap(short='v', long)]
    pub verbose: bool,

    /// Force upgrade process even if there is no new version
    #[clap(long)]
    pub force: bool,
}

pub struct Handle<'a> {
    name: String,
    instance: InstanceKind<'a>,
    project_dir: PathBuf,
    schema_dir: PathBuf,
    database: Option<String>,
}

pub struct StashDir<'a> {
    project_dir: &'a Path,
    instance_name: &'a str,
    database: Option<&'a str>,
    cloud_profile: Option<&'a str>,
}

pub struct WslInfo {
}

pub enum InstanceKind<'a> {
    Remote,
    Portable(InstanceInfo),
    Wsl(WslInfo),
    Cloud {
        org_slug: String,
        name: String,
        cloud_client: &'a CloudClient,
    },
}

#[derive(serde::Serialize)]
#[serde(rename_all="kebab-case")]
struct JsonInfo<'a> {
    instance_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cloud_profile: Option<&'a str>,
    root: &'a Path,
}


pub fn init(options: &Init, opts: &crate::options::Options) -> anyhow::Result<()> {
    if optional_docker_check()? {
        print::error(
            "`edgedb project init` in a Docker container is not supported.",
        );
        return Err(ExitCode::new(exit_codes::DOCKER_CONTAINER))?;
    }

    if options.server_start_conf.is_some() {
        print::warn("The option `--server-start-conf` is deprecated. \
                     Use `edgedb instance start/stop` to control \
                     the instance.");
    }

    match &options.project_dir {
        Some(dir) => {
            let dir = fs::canonicalize(&dir)?;
            if dir.join("edgedb.toml").exists() {
                if options.link {
                    link(options, &dir, &opts.cloud_options)?
                } else {
                    init_existing(options, &dir, &opts.cloud_options)?
                }
            } else {
                if options.link {
                    anyhow::bail!(
                        "`edgedb.toml` was not found, unable to link an EdgeDB \
                        instance with uninitialized project, to initialize \
                        a new project run command without `--link` flag")
                }

                init_new(options, &dir, opts)?
            }
        }
        None => {
            let base_dir = env::current_dir()
                .context("failed to get current directory")?;
            if let Some(dir) = search_dir(&base_dir) {
                let dir = fs::canonicalize(&dir)?;
                if options.link {
                    link(options, &dir, &opts.cloud_options)?
                } else {
                    init_existing(options, &dir, &opts.cloud_options)?
                }
            } else {
                if options.link {
                    anyhow::bail!(
                        "`edgedb.toml` was not found, unable to link an EdgeDB \
                        instance with uninitialized project, to initialize \
                        a new project run command without `--link` flag")
                }

                let dir = fs::canonicalize(&base_dir)?;
                init_new(options, &dir, opts)?
            }
        }
    };
    Ok(())
}

fn ask_existing_instance_name(
    cloud_client: &mut CloudClient
) -> anyhow::Result<InstanceName> {
    let instances = credentials::all_instance_names()?;

    loop {
        let mut q =
            question::String::new("Specify the name of EdgeDB instance \
                                   to link with this project");
        let target_name = q.ask()?;

        let inst_name = match InstanceName::from_str(&target_name) {
            Ok(name) => name,
            Err(e) => {
                print::error(e);
                continue;
            }
        };
        let exists = match &inst_name {
            InstanceName::Local(name) => instances.contains(name),
            InstanceName::Cloud { org_slug, name } => {
                if !cloud_client.is_logged_in {
                    if let Err(e) = crate::cloud::ops::prompt_cloud_login(
                        cloud_client
                    ) {
                        print::error(e);
                        continue;
                    }
                }
                crate::cloud::ops::find_cloud_instance_by_name(
                    name, org_slug, cloud_client
                )?.is_some()
            }
        };
        if exists {
            return Ok(inst_name);
        } else {
            print::error(format!("Instance {:?} doesn't exist", target_name));
        }
    }
}

fn ask_database(project_dir: &Path, options: &Init) -> anyhow::Result<String> {
    if let Some(name) = &options.database {
        return Ok(name.clone());
    }
    let default = directory_to_name(project_dir, "edgedb");
    let mut q = question::String::new("Specify the name of the database:");
    q.default(&default);
    loop {
        let name = q.ask()?;
        if name.trim().is_empty() {
            print::error(format!("Non-empty name is required"));
        } else {
            return Ok(name.trim().into());
        }
    }
}

fn link(
    options: &Init, project_dir: &Path, cloud_options: &crate::options::CloudOptions
) -> anyhow::Result<ProjectInfo> {
    echo!("Found `edgedb.toml` in", project_dir.display());
    echo!("Linking project...");

    let stash_dir = stash_path(project_dir)?;
    if stash_dir.exists() {
        anyhow::bail!("Project is already linked");
    }

    let config_path = project_dir.join("edgedb.toml");
    let config = config::read(&config_path)?;
    let ver_query = config.edgedb.server_version;

    let mut client = CloudClient::new(cloud_options)?;
    let name = if let Some(name) = &options.server_instance {
        name.clone()
    } else if options.non_interactive {
        anyhow::bail!("Existing instance name should be specified \
                       with `--server-instance` argument when linking project \
                       in non-interactive mode")
    } else {
        ask_existing_instance_name(&mut client)?
    };
    let schema_dir = &config.project.schema_dir;
    let mut inst = Handle::probe(&name, project_dir, schema_dir, &client)?;
    if matches!(name, InstanceName::Cloud {..}) {
        inst.database = Some(ask_database(project_dir, options)?);
    } else {
        inst.database = options.database.clone();
    }
    inst.check_version(&ver_query);
    do_link(&inst, options, &stash_dir)
}

fn do_link(inst: &Handle, options: &Init, stash_dir: &Path)
    -> anyhow::Result<ProjectInfo>
{
    let mut stash = StashDir::new(&inst.project_dir, &inst.name);
    if let InstanceKind::Cloud { cloud_client, .. } = inst.instance {
        let profile = cloud_client.profile.as_deref().unwrap_or("default");
        stash.cloud_profile = Some(profile);
    };
    stash.database = inst.database.as_deref();
    stash.write(&stash_dir)?;

    if !options.no_migrations {
        migrate(inst, !options.non_interactive)?;
    } else {
        create_database(inst)?;
    }

    print::success("Project linked");
    if let Some(dir) = &options.project_dir {
        eprintln!(
            "To connect to {}, navigate to {} and run `edgedb`",
            inst.name,
            dir.display()
        );
    } else {
        eprintln!("To connect to {}, run `edgedb`", inst.name);
    }

    Ok(ProjectInfo {
        instance_name: inst.name.clone(),
        stash_dir: stash_dir.into(),
    })
}

fn directory_to_name(path: &Path, default: &str) -> String {
    let path_stem = path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(default);
    let stem = path_stem
        .replace(|c: char| !c.is_ascii_alphanumeric(), "_");
    let stem = stem.trim_matches('_');
    if stem.is_empty() {
        return default.into();
    } else {
        return stem.into();
    }
}

fn ask_name(
    dir: &Path, options: &Init, cloud_client: &mut CloudClient
) -> anyhow::Result<(InstanceName, bool)> {
    let instances = credentials::all_instance_names()?;
    let default_name = if let Some(name) = &options.server_instance {
        name.clone()
    } else {
        let base_name = directory_to_name(dir, "instance");
        let mut name = base_name.clone();

        while instances.contains(&name) {
            name = format!("{}_{:04}",
                base_name, thread_rng().gen_range(0..10000));
        }
        InstanceName::Local(name)
    };
    if options.non_interactive {
        let exists = match &default_name {
            InstanceName::Local(name) => instances.contains(name),
            InstanceName::Cloud { org_slug, name } => {
                cloud_client.ensure_authenticated()?;
                let inst = crate::cloud::ops::find_cloud_instance_by_name(
                    name,
                    org_slug,
                    cloud_client,
                )?;
                inst.is_some()
            }
        };
        if exists {
            anyhow::bail!(format!("Instance {:?} already exists, \
                               to link project with it pass `--link` \
                               flag explicitly", default_name.to_string()))
        }
        return Ok((default_name, false));
    }
    let mut q = question::String::new(
        "Specify the name of EdgeDB instance to use with this project"
    );
    let default_name_str = default_name.to_string();
    q.default(&default_name_str);
    loop {
        let default_name_clone = default_name.clone();
        let mut q = question::String::new(
            "Specify the name of EdgeDB instance to use with this project"
        );
        let default_name_str = default_name_clone.to_string();
        let target_name = q.default(&default_name_str).ask()?;
        let inst_name = match InstanceName::from_str(&target_name) {
            Ok(name) => name,
            Err(e) => {
                print::error(e);
                continue;
            }
        };
        let exists = match &inst_name {
            InstanceName::Local(name) => instances.contains(name),
            InstanceName::Cloud { org_slug, name } => {
                if !cloud_client.is_logged_in {
                    if let Err(e) = crate::cloud::ops::prompt_cloud_login(
                        cloud_client
                    ) {
                        print::error(e);
                        continue;
                    }
                }
                crate::cloud::ops::find_cloud_instance_by_name(
                    name, org_slug, cloud_client
                )?.is_some()
            }
        };
        if exists {
            let confirm = question::Confirm::new(
                format!("Do you want to use existing instance {:?} \
                         for the project?",
                         target_name)
            );
            if confirm.ask()? {
                return Ok((inst_name, true));
            }
        } else {
            return Ok((inst_name, false))
        }
    }
}

pub fn init_existing(options: &Init, project_dir: &Path, cloud_options: &crate::options::CloudOptions)
    -> anyhow::Result<ProjectInfo>
{
    echo!("Found `edgedb.toml` in", project_dir.display());
    echo!("Initializing project...");

    let stash_dir = stash_path(project_dir)?;
    if stash_dir.exists() {
        // TODO(tailhook) do more checks and probably cleanup the dir
        anyhow::bail!("Project is already initialized.");
    }

    let config_path = project_dir.join("edgedb.toml");
    let config = config::read(&config_path)?;
    let schema_dir = config.project.schema_dir;
    let schema_dir_path = project_dir.join(&schema_dir);
    let schema_dir_path =
        if schema_dir_path.exists() {
            fs::canonicalize(&schema_dir_path)
                .with_context(|| {
                    format!("failed to canonicalize dir {:?}", schema_dir_path)
                })?
        } else {
            schema_dir_path
        };
    let schema_files = find_schema_files(&schema_dir_path)?;

    let ver_query = if let Some(sver) = &options.server_version {
        sver.clone()
    } else {
        config.edgedb.server_version
    };
    let mut client = CloudClient::new(cloud_options)?;
    let (name, exists) = ask_name(project_dir, options, &mut client)?;

    if exists {
        let mut inst = Handle::probe(&name, project_dir, &schema_dir, &client)?;
        inst.check_version(&ver_query);
        if matches!(name, InstanceName::Cloud { .. }) {
            inst.database = Some(ask_database(project_dir, options)?);
        } else {
            inst.database = options.database.clone();
        }
        return do_link(&inst, options, &stash_dir);
    }

    match &name {
        InstanceName::Cloud { org_slug, name } => {
            echo!("Checking EdgeDB cloud versions...");

            let ver = cloud::versions::get_version(&ver_query, &client)
                .with_context(|| "could not initialize project")?;
            let database = ask_database(project_dir, options)?;

            table::settings(&[
                ("Project directory", &project_dir.display().to_string()),
                ("Project config", &config_path.display().to_string()),
                (&format!("Schema dir {}",
                          if schema_files { "(non-empty)" } else { "(empty)" }),
                 &schema_dir_path.display().to_string()),
                ("Database name", &database.to_string()),
                ("Version", &ver.to_string()),
                ("Instance name", &name.to_string()),
            ]);

            if !schema_files {
                write_schema_default(&schema_dir, &ver_query)?;
            }
            do_cloud_init(
                name.to_owned(),
                org_slug.to_owned(),
                &stash_dir,
                &project_dir,
                &schema_dir,
                &ver,
                &database,
                options,
                &client)
        }
        InstanceName::Local(name) => {
            echo!("Checking EdgeDB versions...");

            let pkg = repository::get_server_package(&ver_query)?
                .with_context(||
                    format!("cannot find package matching {}", ver_query.display()))?;

            let meth = if cfg!(windows) {
                "WSL"
            } else {
                "portable package"
            };
            table::settings(&[
                ("Project directory", &project_dir.display().to_string()),
                ("Project config", &config_path.display().to_string()),
                (&format!("Schema dir {}",
                          if schema_files { "(non-empty)" } else { "(empty)" }),
                 &schema_dir_path.display().to_string()),
                ("Installation method", meth),
                ("Version", &pkg.version.to_string()),
                ("Instance name", name),
            ]);

            if !schema_files {
                write_schema_default(&schema_dir, &ver_query)?;
            }

            do_init(name, &pkg, &stash_dir, &project_dir, &schema_dir, options)
        }
    }
}

fn do_init(name: &str, pkg: &PackageInfo,
           stash_dir: &Path, project_dir: &Path, schema_dir: &Path, options: &Init)
    -> anyhow::Result<ProjectInfo>
{
    let port = allocate_port(name)?;
    let paths = Paths::get(&name)?;
    let inst_name = InstanceName::Local(name.to_owned());

    let instance = if cfg!(windows) {
        let q = repository::Query::from_version(&pkg.version.specific())?;
        windows::create_instance(&options::Create {
            name: Some(inst_name.clone()),
            nightly: false,
            channel: q.cli_channel(),
            version: q.version,
            region: None,
            port: Some(port),
            start_conf: None,
            default_database: "edgedb".into(),
            default_user: "edgedb".into(),
            non_interactive: true,
        }, name, port, &paths)?;
        create::create_service(&InstanceInfo {
            name: name.into(),
            installation: None,
            port,
        })?;
        InstanceKind::Wsl(WslInfo {})
    } else {
        let inst = install::package(&pkg).context("error installing EdgeDB")?;
        let info = InstanceInfo {
            name: name.into(),
            installation: Some(inst),
            port,
        };
        create::bootstrap(&paths, &info, "edgedb", "edgedb")?;
        match create::create_service(&info) {
            Ok(()) => {},
            Err(e) => {
                log::warn!("Error running EdgeDB as a service: {e:#}");
                print::warn("EdgeDB will not start on next login. \
                             Trying to start database in the background...");
                control::start(&Start {
                    name: None,
                    instance: Some(inst_name.clone()),
                    foreground: false,
                    auto_restart: false,
                    managed_by: None,
                })?;
            }
        }
        InstanceKind::Portable(info)
    };


    let handle = Handle {
        name: name.into(),
        project_dir: project_dir.into(),
        schema_dir: schema_dir.into(),
        instance,
        database: options.database.clone(),
    };

    let mut stash = StashDir::new(project_dir, &name);
    stash.database = handle.database.as_deref();
    stash.write(&stash_dir)?;

    if !options.no_migrations {
        migrate(&handle, false)?;
    } else {
        create_database(&handle)?;
    }
    print_initialized(&name, &options.project_dir);
    Ok(ProjectInfo {
        instance_name: name.into(),
        stash_dir: stash_dir.into(),
    })
}

fn do_cloud_init(
    name: String,
    org: String,
    stash_dir: &Path,
    project_dir: &Path,
    schema_dir: &Path,
    version: &ver::Specific,
    database: &str,
    options: &Init,
    client: &CloudClient,
) -> anyhow::Result<ProjectInfo> {
    let request = crate::cloud::ops::CloudInstanceCreate {
        name: name.clone(),
        org: org.clone(),
        version: version.to_string(),
        region: None,
    };
    crate::cloud::ops::create_cloud_instance(client, &request)?;
    let full_name = format!("{}/{}", org, name);

    let handle = Handle {
        name: full_name.clone(),
        schema_dir: schema_dir.into(),
        instance: InstanceKind::Remote,
        project_dir: project_dir.into(),
        database: Some(database.to_owned()),
    };

    let mut stash = StashDir::new(project_dir, &full_name);
    stash.cloud_profile = client.profile.as_deref().or_else(|| Some("default"));
    stash.database = handle.database.as_deref();
    stash.write(stash_dir)?;

    if !options.no_migrations {
        migrate(&handle, false)?;
    } else {
        create_database(&handle)?;
    }
    print_initialized(&full_name, &options.project_dir);
    Ok(ProjectInfo {
        instance_name: full_name,
        stash_dir: stash_dir.into(),
    })
}

pub fn init_new(options: &Init, project_dir: &Path, opts: &crate::options::Options)
    -> anyhow::Result<ProjectInfo>
{
    eprintln!("No `edgedb.toml` found in `{}` or above",
              project_dir.display());

    let stash_dir = stash_path(project_dir)?;
    if stash_dir.exists() {
        anyhow::bail!("Project was already initialized \
                       but then `edgedb.toml` was deleted. \
                       Please run `edgedb project unlink -D` to \
                       cleanup old database instance.");
    }

    if options.non_interactive {
        eprintln!("Initializing new project...");
    } else {
        let mut q = question::Confirm::new(
            "Do you want to initialize a new project?"
        );
        q.default(true);
        if !q.ask()? {
            return Err(ExitCode::new(0).into());
        }
    }

    let config_path = project_dir.join("edgedb.toml");
    let schema_dir = Path::new("dbschema");
    let schema_dir_path = project_dir.join(schema_dir);
    let schema_files = find_schema_files(&schema_dir)?;

    let mut client = CloudClient::new(&opts.cloud_options)?;
    let (inst_name, exists) = ask_name(project_dir, options, &mut client)?;

    if exists {
        let mut inst;
        inst = Handle::probe(&inst_name, project_dir, &schema_dir, &client)?;
        let ver = Query::from_version(&inst.get_version()?.specific())?;
        write_config(&config_path, &ver)?;
        if !schema_files {
            write_schema_default(&schema_dir_path, &ver)?;
        }
        if matches!(inst_name, InstanceName::Cloud { .. }) {
            inst.database = Some(ask_database(project_dir, options)?);
        } else {
            inst.database = options.database.clone();
        }
        return do_link(&mut inst, options, &stash_dir);
    };

    match &inst_name {
        InstanceName::Cloud { org_slug, name } => {
            echo!("Checking EdgeDB cloud versions...");
            client.ensure_authenticated()?;

            let (ver_query, version) = ask_cloud_version(options, &client)?;
            if let Some(filter) = &ver_query.version {
                if !filter.matches_exact(&version) {
                    echo!("Latest version compatible with the specification",
                        "\""; filter; "\"",
                        "is", version.emphasize());
                }
            }
            let database = ask_database(project_dir, options)?;
            table::settings(&[
                ("Project directory", &project_dir.display().to_string()),
                ("Project config", &config_path.display().to_string()),
                (&format!("Schema dir {}",
                          if schema_files { "(non-empty)" } else { "(empty)" }),
                 &schema_dir_path.display().to_string()),
                ("Database", &database.to_string()),
                ("Version", &version.to_string()),
                ("Instance name", &name),
            ]);
            write_config(&config_path, &ver_query)?;
            if !schema_files {
                write_schema_default(&schema_dir_path, &ver_query)?;
            }

            do_cloud_init(
                name.to_owned(),
                org_slug.to_owned(),
                &stash_dir,
                &project_dir,
                &schema_dir,
                &version,
                &database,
                options,
                &client,
            )
        }
        InstanceName::Local(name) => {
            echo!("Checking EdgeDB versions...");
            let (ver_query, pkg) = ask_local_version(options)?;
            if let Some(filter) = &ver_query.version {
                if !filter.matches_exact(&pkg.version.specific()) {
                    echo!("Latest version compatible with the specification",
                        "\""; filter; "\"",
                        "is", pkg.version.emphasize());
                }
            }

            let meth = if cfg!(windows) {
                "WSL"
            } else {
                "portable package"
            };
            table::settings(&[
                ("Project directory", &project_dir.display().to_string()),
                ("Project config", &config_path.display().to_string()),
                (&format!("Schema dir {}",
                          if schema_files { "(non-empty)" } else { "(empty)" }),
                 &schema_dir_path.display().to_string()),
                ("Installation method", meth),
                ("Version", &pkg.version.to_string()),
                ("Instance name", &name),
            ]);

            write_config(&config_path, &ver_query)?;
            if !schema_files {
                write_schema_default(&schema_dir_path, &ver_query)?;
            }

            do_init(&name, &pkg, &stash_dir, &project_dir, &schema_dir, options)
        }
    }
}

pub fn search_dir(base: &Path) -> Option<PathBuf> {
    let mut path = base;
    if path.join("edgedb.toml").exists() {
        return Some(path.into());
    }
    while let Some(parent) = path.parent() {
        if parent.join("edgedb.toml").exists() {
            return Some(parent.into());
        }
        path = parent;
    }
    None
}

fn hash(path: &Path) -> anyhow::Result<String> {
    Ok(hex::encode(sha1::Sha1::new_with_prefix(path_bytes(path)?).finalize()))
}

fn stash_name(path: &Path) -> anyhow::Result<OsString> {
    let hash = hash(path)?;
    let base = path.file_name().ok_or_else(|| anyhow::anyhow!("bad path"))?;
    let mut base = base.to_os_string();
    base.push("-");
    base.push(&hash);
    return Ok(base);
}

pub fn stash_base() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("projects"))
}

pub fn stash_path(project_dir: &Path) -> anyhow::Result<PathBuf> {
    let hname = stash_name(project_dir)?;
    Ok(stash_base()?.join(hname))
}

fn run_and_migrate(info: &Handle) -> anyhow::Result<()> {
    match &info.instance {
        InstanceKind::Portable(inst) => {
            control::ensure_runstate_dir(&info.name)?;
            let mut cmd = control::get_server_cmd(inst, false)?;
            cmd.background_for(|| Ok(migrate_async(info, false)))?;
            Ok(())
        }
        InstanceKind::Wsl(_) => {
            let mut cmd = windows::server_cmd(&info.name, false)?;
            cmd.background_for(|| Ok(migrate_async(info, false)))?;
            Ok(())
        }
        InstanceKind::Remote => {
            anyhow::bail!("remote instance is not running, \
                          cannot run migrations");
        }
        InstanceKind::Cloud { .. } => todo!(),
    }
}

fn start(handle: &Handle) -> anyhow::Result<()> {
    match &handle.instance {
        InstanceKind::Portable(inst) => {
            control::do_start(&inst)?;
            Ok(())
        }
        InstanceKind::Wsl(_) => {
            windows::daemon_start(&handle.name)?;
            Ok(())
        }
        InstanceKind::Remote => {
            anyhow::bail!("remote instance is not running, \
                          cannot run migrations");
        }
        InstanceKind::Cloud { .. } => todo!(),
    }
}

#[tokio::main]
async fn create_database(inst: &Handle<'_>) -> anyhow::Result<()> {
    create_database_async(inst).await
}

async fn ensure_database(cli: &mut Connection, name: &str)
    -> anyhow::Result<()>
{
    let name = quote_name(name);
    match cli.execute(&format!("CREATE DATABASE {name}"), &()).await {
        Ok(_) => Ok(()),
        Err(e) if e.is::<DuplicateDatabaseDefinitionError>() => Ok(()),
        Err(e) => Err(e)?,
    }
}

async fn create_database_async(inst: &Handle<'_>) -> anyhow::Result<()> {
    let Some(name) = &inst.database else { return Ok(()) };
    let config = inst.get_default_builder()?.build_env().await?;
    if name == config.database() {
        return Ok(());
    }
    let mut conn = Connection::connect(&config).await?;
    ensure_database(&mut conn, name).await?;
    Ok(())
}

#[tokio::main]
async fn migrate(inst: &Handle<'_>, ask_for_running: bool)
    -> anyhow::Result<()>
{
    migrate_async(inst, ask_for_running).await
}

async fn migrate_async(inst: &Handle<'_>, ask_for_running: bool)
    -> anyhow::Result<()>
{
    use crate::commands::Options;
    use crate::migrations::options::{Migrate, MigrationConfig};
    use Action::*;

    #[derive(Clone, Copy)]
    enum Action {
        Retry,
        Service,
        Run,
        Skip,
    }

    echo!("Applying migrations...");

    let mut conn = loop {
        match inst.get_default_connection().await {
            Ok(conn) => break conn,
            Err(e) if ask_for_running && inst.instance.is_local() => {
                print::error(e);
                let mut q = question::Numeric::new(
                    format!(
                        "Cannot connect to an instance {:?}. What to do?",
                        inst.name,
                    )
                );
                q.option("Start the service (if possible).",
                    Service);
                q.option("Start in the foreground, \
                          apply migrations and shutdown.",
                    Run);
                q.option("I have just started it manually. Try again!",
                    Retry);
                q.option("Skip migrations.",
                    Skip);
                match q.async_ask().await? {
                    Service => match start(inst) {
                        Ok(()) => continue,
                        Err(e) => {
                            print::error(e);
                            continue;
                        }
                    }
                    Run => {
                        run_and_migrate(inst)?;
                        return Ok(());
                    }
                    Retry => continue,
                    Skip => {
                        print::warn("Skipping migrations.");
                        echo!("Once service is running, \
                            you can apply migrations by running:\n  \
                              edgedb migrate");
                        return Ok(());
                    }
                }
            }
            Err(e) => return Err(e)?,
        };
    };
    if let Some(database) = &inst.database {
        ensure_database(&mut conn, database).await?;
        conn = inst.get_connection().await?;
    }

    migrations::migrate(
        &mut conn,
        &Options {
            command_line: true,
            styler: None,
            conn_params: Connector::new(
                inst.get_builder()?.build_env().await
                .map_err(Into::into)
            ),
        },
        &Migrate {
            cfg: MigrationConfig {
                schema_dir: Some(inst.project_dir.join(&inst.schema_dir)),
            },
            quiet: false,
            to_revision: None,
            dev_mode: false,
        }).await?;
    Ok(())
}

impl<'a> StashDir<'a> {
    fn new(project_dir: &'a Path, instance_name: &'a str) -> StashDir<'a> {
        StashDir {
            project_dir,
            instance_name,
            database: None,
            cloud_profile: None,
        }
    }
    #[context("error writing project dir {:?}", dir)]
    fn write(&self, dir: &Path) -> anyhow::Result<()> {
        let tmp = tmp_file_path(&dir);
        fs::create_dir_all(&tmp)?;
        fs::write(&tmp.join("project-path"), path_bytes(self.project_dir)?)?;
        fs::write(&tmp.join("instance-name"), self.instance_name.as_bytes())?;
        if let Some(profile) = self.cloud_profile {
            fs::write(&tmp.join("cloud-profile"), profile.as_bytes())?;
        }
        if let Some(database) = &self.database {
            fs::write(&tmp.join("database"), database.as_bytes())?;
        }

        let lnk = tmp.join("project-link");
        symlink_dir(self.project_dir, &lnk)
            .map_err(|e| {
                log::info!("Error symlinking project at {:?}: {}", lnk, e);
            }).ok();
        fs::rename(&tmp, dir)?;
        Ok(())
    }
}

impl InstanceKind<'_> {
    fn is_local(&self) -> bool {
        match self {
            InstanceKind::Wsl(_) => true,
            InstanceKind::Portable(_) => true,
            InstanceKind::Remote => false,
            InstanceKind::Cloud { .. } => false,
        }
    }
}

impl Handle<'_> {
    pub fn probe<'a>(
        name: &InstanceName,
        project_dir: &Path,
        schema_dir: &Path,
        cloud_client: &'a CloudClient,
    ) -> anyhow::Result<Handle<'a>> {
        match name {
            InstanceName::Local(name) => match InstanceInfo::try_read(name)? {
                Some(info) => Ok(Handle {
                    name: name.into(),
                    instance: InstanceKind::Portable(info),
                    project_dir: project_dir.into(),
                    schema_dir: schema_dir.into(),
                    database: None,
                }),
                None => Ok(Handle {
                    name: name.into(),
                    instance: InstanceKind::Remote,
                    project_dir: project_dir.into(),
                    schema_dir: schema_dir.into(),
                    database: None,
                })
            }
            InstanceName::Cloud { org_slug, name: inst_name } => Ok(Handle {
                name: name.to_string(),
                instance: InstanceKind::Cloud {
                    org_slug: org_slug.to_owned(),
                    name: inst_name.to_owned(),
                    cloud_client,
                },
                database: None,
                project_dir: project_dir.into(),
                schema_dir: schema_dir.into(),
            })
        }
    }
    pub fn get_builder(&self) -> anyhow::Result<Builder> {
        let mut builder = Builder::new();
        builder.instance(&self.name)?;
        if let Some(database) = &self.database {
            builder.database(database)?;
        }
        Ok(builder)
    }
    pub fn get_default_builder(&self) -> anyhow::Result<Builder> {
        let mut builder = Builder::new();
        builder.instance(&self.name)?;
        Ok(builder)
    }
    pub async fn get_default_connection(&self) -> anyhow::Result<Connection> {
        Ok(Connection::connect(
            &self.get_default_builder()?.build_env().await?
        ).await?)
    }
    pub async fn get_connection(&self) -> anyhow::Result<Connection> {
        Ok(Connection::connect(&self.get_builder()?.build_env().await?).await?)
    }
    #[tokio::main(flavor="current_thread")]
    pub async fn get_version(&self) -> anyhow::Result<ver::Build> {
        let mut conn = self.get_default_connection().await?;
        anyhow::Ok(conn.get_version().await?.clone())
    }
    fn check_version(&self, ver_query: &Query) {
        match self.get_version() {
            Ok(inst_ver) if ver_query.matches(&inst_ver) => {}
            Ok(inst_ver) => {
                print::warn(format!(
                    "WARNING: existing instance has version {}, \
                    but {} is required by `edgedb.toml`",
                    inst_ver, ver_query.display(),
                ));
            }
            Err(e) => {
                log::warn!("Could not check instance's version: {:#}", e);
            }
        }
    }
}

#[context("cannot read schema directory `{}`", path.display())]
fn find_schema_files(path: &Path) -> anyhow::Result<bool> {
    let dir = match fs::read_dir(&path) {
        Ok(dir) => dir,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(e) => return Err(e)?,
    };
    for item in dir {
        let entry = item?;
        let is_esdl = entry.file_name().to_str()
            .map(|x| x.ends_with(".esdl"))
            .unwrap_or(false);
        if is_esdl {
            return Ok(true);
        }
    }
    return Ok(false);
}

fn print_initialized(name: &str, dir_option: &Option<PathBuf>)
{
    print::success("Project initialized.");
    if let Some(dir) = dir_option {
        echo!("To connect to", name.emphasize();
              ", navigate to", dir.display(), "and run `edgedb`");
    } else {
        echo!("To connect to", name.emphasize(); ", run `edgedb`");
    }
}

#[context("cannot create default schema in `{}`", dir.display())]
fn write_schema_default(dir: &Path, version: &Query) -> anyhow::Result<()> {
    fs::create_dir_all(&dir)?;
    fs::create_dir_all(&dir.join("migrations"))?;
    let default = dir.join("default.esdl");
    let tmp = tmp_file_path(&default);
    fs::remove_file(&tmp).ok();
    fs::write(&tmp, DEFAULT_ESDL)?;
    fs::rename(&tmp, &default)?;
    if version.is_nonrecursive_access_policies_needed() {
        let futures = dir.join("futures.esdl");
        let tmp = tmp_file_path(&futures);
        fs::remove_file(&tmp).ok();
        fs::write(&tmp, FUTURES_ESDL)?;
        fs::rename(&tmp, &futures)?;
    };
    Ok(())
}

#[context("cannot write config `{}`", path.display())]
fn write_config(path: &Path, version: &Query) -> anyhow::Result<()> {
    let text = config::format_config(version);
    let tmp = tmp_file_path(path);
    fs::remove_file(&tmp).ok();
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn parse_ver_and_find(value: &str)
    -> anyhow::Result<Option<(Query, PackageInfo)>>
{
    let filter = value.parse()?;
    let query = Query::from_filter(&filter)?;
    if let Some(pkg) = repository::get_server_package(&query)? {
        Ok(Some((query, pkg)))
    } else {
        Ok(None)
    }
}

fn ask_local_version(options: &Init) -> anyhow::Result<(Query, PackageInfo)> {
    let ver_query = options.server_version.clone().unwrap_or(Query::stable());
    if options.non_interactive || options.server_version.is_some() {
        let pkg = repository::get_server_package(&ver_query)?
            .with_context(|| format!("no package matching {} found",
                                     ver_query.display()))?;
        if options.server_version.is_some() {
            return Ok((ver_query, pkg));
        } else {
            return Ok((Query::from_version(&pkg.version.specific())?, pkg));
        }
    }
    let default = repository::get_server_package(&ver_query)?;
    let default_ver = if let Some(pkg) = &default {
        Query::from_version(&pkg.version.specific())?.as_config_value()
    } else {
        String::new()
    };
    let mut q = question::String::new(
        "Specify the version of EdgeDB to use with this project"
    );
    q.default(&default_ver);
    loop {
        let value = q.ask()?;
        let value = value.trim();
        if value == "nightly" {
            match repository::get_server_package(&Query::nightly()) {
                Ok(Some(pkg)) => return Ok((Query::nightly(), pkg)),
                Ok(None) => {
                    print::error("No nightly versions found");
                    continue;
                }
                Err(e) => {
                    print::error(format!(
                        "Cannot find nightly version: {}", e
                    ));
                    continue;
                }
            }
        } else if value == "testing" {
            match repository::get_server_package(&Query::testing()) {
                Ok(Some(pkg)) => return Ok((Query::testing(), pkg)),
                Ok(None) => {
                    print::error("No testing versions found");
                    continue;
                }
                Err(e) => {
                    print::error(format!(
                        "Cannot find testing version: {}", e
                    ));
                    continue;
                }
            }
        } else {
            match parse_ver_and_find(&value) {
                Ok(Some(pair)) => return Ok(pair),
                Ok(None) => {
                    print::error("No matching packages found");
                    print_versions("Available versions")?;
                    continue;
                }
                Err(e) => {
                    print::error(e);
                    print_versions("Available versions")?;
                    continue;
                }
            }
        }
    }
}

fn print_versions(title: &str) -> anyhow::Result<()> {
    let mut avail = repository::get_server_packages(Channel::Stable)?;
    avail.sort_by(|a, b| b.version.cmp(&a.version));
    println!("{}: {}{}",
        title,
        avail.iter()
            .filter_map(|p| Query::from_version(&p.version.specific()).ok())
            .take(5)
            .map(|v| v.as_config_value())
            .collect::<Vec<_>>()
            .join(", "),
        if avail.len() > 5 { " ..." } else { "" },
    );
    Ok(())
}

fn parse_ver_and_find_cloud(value: &str, client: &CloudClient)
    -> anyhow::Result<(Query, ver::Specific)>
{
    let filter = value.parse()?;
    let query = Query::from_filter(&filter)?;
    let version = cloud::versions::get_version(&query, client)?;
    Ok((query, version))
}

fn ask_cloud_version(options: &Init, client: &CloudClient) -> anyhow::Result<(Query, ver::Specific)> {
    let ver_query = options.server_version.clone().unwrap_or(Query::stable());
    if options.non_interactive || options.server_version.is_some() {
        let version = cloud::versions::get_version(&ver_query, client)?;
        return Ok((ver_query, version));
    }
    let default = cloud::versions::get_version(&Query::stable(), client)?;
    let default_ver = Query::from_version(&default)?.as_config_value();
    let mut q = question::String::new(
        "Specify the version of EdgeDB to use with this project"
    );
    q.default(&default_ver);
    loop {
        let value = q.ask()?;
        let value = value.trim();
        if value == "nightly" {
            match cloud::versions::get_version(&Query::nightly(), client) {
                Ok(v) => return Ok((Query::nightly(), v)),
                Err(e) => {
                    print::error(format!("{}", e));
                    continue;
                }
            }
        } else if value == "testing" {
            match cloud::versions::get_version(&Query::testing(), client) {
                Ok(v) => return Ok((Query::testing(), v)),
                Err(e) => {
                    print::error(format!("{}", e));
                    continue;
                }
            }
        } else {
            match parse_ver_and_find_cloud(&value, client) {
                Ok(pair) => return Ok(pair),
                Err(e) => {
                    print::error(e);
                    print_cloud_versions("Available versions", client)?;
                    continue;
                }
            }
        }
    }
}

fn print_cloud_versions(title: &str, client: &CloudClient) -> anyhow::Result<()> {
    let mut avail: Vec<ver::Specific> = cloud::ops::get_versions(client)?.into_iter()
        .map(|v| v.version.parse::<ver::Specific>().unwrap()).collect();
    avail.sort();
    println!("{}: {}{}",
        title,
        avail.iter()
            .filter_map(|p| Query::from_version(&p).ok())
            .take(5)
            .map(|v| v.as_config_value())
            .collect::<Vec<_>>()
            .join(", "),
        if avail.len() > 5 { " ..." } else { "" },
    );
    Ok(())
}

fn search_for_unlink(base: &Path) -> anyhow::Result<PathBuf> {
    let mut path = base;
    while let Some(parent) = path.parent() {
        let canon = fs::canonicalize(&path)
            .with_context(|| {
                format!("failed to canonicalize dir {:?}", parent)
            })?;
        let stash_dir = stash_path(&canon)?;
        if stash_dir.exists() || path.join("edgedb.toml").exists() {
            return Ok(stash_dir)
        }
        path = parent;
    }
    anyhow::bail!("no project directory found");
}

#[context("cannot read instance name of {:?}", stash_dir)]
fn instance_name(stash_dir: &Path) -> anyhow::Result<InstanceName> {
    let inst = fs::read_to_string(&stash_dir.join("instance-name"))?;
    Ok(InstanceName::from_str(inst.trim())?)
}

#[context("cannot read database name of {:?}", stash_dir)]
fn database_name(stash_dir: &Path) -> anyhow::Result<Option<String>> {
    let inst = match fs::read_to_string(&stash_dir.join("database")) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(e) => return Err(e)?,
    };
    Ok(Some(inst.trim().into()))
}

pub fn unlink(options: &Unlink, opts: &crate::options::Options) -> anyhow::Result<()> {
    let stash_path = if let Some(dir) = &options.project_dir {
        let canon = fs::canonicalize(&dir)
            .with_context(|| format!("failed to canonicalize dir {:?}", dir))?;
        stash_path(&canon)?
    } else {
        let base = env::current_dir()
            .context("failed to get current directory")?;
        search_for_unlink(&base)?
    };

    if stash_path.exists() {
        if options.destroy_server_instance {
            let inst = instance_name(&stash_path)?;
            if !options.non_interactive {
                let q = question::Confirm::new_dangerous(
                    format!("Do you really want to unlink \
                             and delete instance {}?", inst)
                );
                if !q.ask()? {
                    print::error("Canceled.");
                    return Ok(())
                }
            }
            let inst_name = inst.to_string();
            let mut project_dirs = find_project_dirs_by_instance(&inst_name)?;
            if project_dirs.len() > 1 {
                project_dirs.iter().position(|d| d == &stash_path)
                    .map(|pos| project_dirs.remove(pos));
                destroy::print_warning(&inst_name, &project_dirs);
                return Err(ExitCode::new(exit_codes::NEEDS_FORCE))?;
            }
            if options.destroy_server_instance {
                destroy::force_by_name(&inst, opts)?;
            }
        } else {
            match fs::read_to_string(&stash_path.join("instance-name")) {
                Ok(name) => {
                    echo!("Unlinking instance", name.emphasize());
                }
                Err(e) => {
                    print::error(format!("Cannot read instance name: {}", e));
                    eprintln!("Removing project configuration directory...");
                }
            };
        }
        fs::remove_dir_all(&stash_path)?;
    } else {
        log::warn!("no project directory exists");
    }
    Ok(())
}


pub fn project_dir(cli_option: Option<&Path>) -> anyhow::Result<PathBuf> {
    project_dir_opt(cli_option)?
    .ok_or_else(|| {
        anyhow::anyhow!("no `edgedb.toml` found")
    })
}

pub fn project_dir_opt(cli_options: Option<&Path>)
    -> anyhow::Result<Option<PathBuf>>
{
    match cli_options {
        Some(dir) => {
            if dir.join("edgedb.toml").exists() {
                let canon = fs::canonicalize(&dir)
                    .with_context(|| {
                        format!("failed to canonicalize dir {:?}", dir)
                    })?;
                Ok(Some(canon))
            } else {
                anyhow::bail!("no `edgedb.toml` found in {:?}", dir);
            }
        }
        None => {
            let dir = env::current_dir()
                .context("failed to get current directory")?;
            if let Some(ancestor) = search_dir(&dir) {
                let canon = fs::canonicalize(&ancestor)
                    .with_context(|| {
                        format!("failed to canonicalize dir {:?}", ancestor)
                    })?;
                Ok(Some(canon))
            } else {
                Ok(None)
            }
        }
    }
}

pub fn info(options: &Info) -> anyhow::Result<()> {
    let root = project_dir(options.project_dir.as_ref().map(|x| x.as_path()))?;
    let stash_dir = stash_path(&root)?;
    if !stash_dir.exists() {
        echo!(print::err_marker(),
            "Project is not initialized.".emphasize(),
            "Run `edgedb project init`.");
        return Err(ExitCode::new(1).into());
    }
    let instance_name = fs::read_to_string(stash_dir.join("instance-name"))?;
    let cloud_profile_file = stash_dir.join("cloud-profile");
    let cloud_profile = cloud_profile_file
        .exists()
        .then(|| fs::read_to_string(cloud_profile_file))
        .transpose()?;

    let item = options.get.as_deref()
        .or(options.instance_name.then(|| "instance-name"));
    if let Some(item) = item {
        match item {
            "instance-name" => {
                if options.json {
                    println!("{}", serde_json::to_string(&instance_name)?);
                } else {
                    println!("{}", instance_name);
                }
            }
            "cloud-profile" => {
                if options.json {
                    println!("{}", serde_json::to_string(&cloud_profile)?);
                } else if let Some(profile) = cloud_profile {
                    println!("{}", profile);
                }
            }
            _ => unreachable!(),
        }
    } else if options.json {
        println!("{}", serde_json::to_string_pretty(&JsonInfo {
            instance_name: &instance_name,
            cloud_profile: cloud_profile.as_deref(),
            root: &root,
        })?);
    } else {
        let root = root.display().to_string();
        let mut rows = vec![
            ("Instance name", instance_name.as_str()),
            ("Project root", root.as_str()),
        ];
        if let Some(profile) = cloud_profile.as_deref() {
            rows.push(("Cloud profile", profile));
        }
        table::settings(rows.as_slice());
    }
    Ok(())
}

pub fn find_project_dirs_by_instance(name: &str) -> anyhow::Result<Vec<PathBuf>> {
    find_project_stash_dirs("instance-name", |val| name == val, true)
        .map(|projects| projects.into_values().flatten().collect())
}

#[context("could not read project dir {:?}", stash_base())]
pub fn find_project_stash_dirs(
    get: &str,
    f: impl Fn(&str) -> bool,
    verbose: bool,
) -> anyhow::Result<HashMap<String, Vec<PathBuf>>> {
    let mut res = HashMap::new();
    let dir = match fs::read_dir(stash_base()?) {
        Ok(dir) => dir,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(res);
        }
        Err(e) => return Err(e)?,
    };
    for item in dir {
        let entry = item?;
        let sub_dir = entry.path();
        if sub_dir.file_name()
            .and_then(|f| f.to_str())
            .map(|n| n.starts_with("."))
            .unwrap_or(true)
        {
            // skip hidden files, most likely .DS_Store (see #689)
            continue;
        }
        let path = sub_dir.join(get);
        let value = match fs::read_to_string(&path) {
            Ok(value) => value.trim().to_string(),
            Err(e) => {
                if verbose {
                    log::warn!("Error reading {:?}: {}", path, e);
                }
                continue;
            }
        };
        if f(&value) {
            res.entry(value).or_default().push(entry.path());
        }
    }
    Ok(res)
}

pub fn print_instance_in_use_warning(name: &str, project_dirs: &[PathBuf]) {
    print::warn(format!(
        "Instance {:?} is used by the following project{}:",
        name,
        if project_dirs.len() > 1 { "s" } else { "" },
    ));
    for dir in project_dirs {
        let dest = match read_project_path(dir) {
            Ok(path) => path,
            Err(e) => {
                print::error(e);
                continue;
            }
        };
        eprintln!("  {}", dest.display());
    }
}

#[context("cannot read {:?}", project_dir)]
pub fn read_project_path(project_dir: &Path) -> anyhow::Result<PathBuf> {
    let bytes = fs::read(&project_dir.join("project-path"))?;
    Ok(bytes_to_path(&bytes)?.to_path_buf())
}

pub fn upgrade(options: &Upgrade, opts: &crate::options::Options)
    -> anyhow::Result<()>
{
    let (query, version_set) = Query::from_options(
        repository::QueryOptions {
            nightly: options.to_nightly,
            stable: options.to_latest,
            testing: options.to_testing,
            version: options.to_version.as_ref(),
            channel: options.to_channel,
        },
        || Ok(Query::stable()))?;
    if version_set {
        update_toml(options, opts, query)
    } else {
        upgrade_instance(options, opts)
    }
}

pub fn update_toml(
    options: &Upgrade, opts: &crate::options::Options, query: Query,
) -> anyhow::Result<()> {
    let root = project_dir(options.project_dir.as_ref().map(|x| x.as_path()))?;
    let config_path = root.join("edgedb.toml");
    let config = config::read(&config_path)?;
    let schema_dir = &config.project.schema_dir;

    let pkg = repository::get_server_package(&query)?.with_context(||
        format!("cannot find package matching {}", query.display()))?;
    let pkg_ver = pkg.version.specific();

    let stash_dir = stash_path(&root)?;
    if !stash_dir.exists() {
        log::warn!("No associated instance found.");

        if config::modify(&config_path, &query)? {
            print::success("Config updated successfully.");
        } else {
            print::success("Config is up to date.");
        }
        echo!("Run", "edgedb project init".command_hint(),
              "to initialize an instance.");
    } else {
        let name = instance_name(&stash_dir)?;
        let database = database_name(&stash_dir)?;
        let client = CloudClient::new(&opts.cloud_options)?;
        let mut inst = Handle::probe(&name, &root, &schema_dir, &client)?;
        inst.database = database;
        let inst = match inst.instance {
            InstanceKind::Remote
                => anyhow::bail!("remote instances cannot be upgraded"),
            InstanceKind::Portable(inst) => inst,
            InstanceKind::Wsl(_) => todo!(),
            InstanceKind::Cloud { .. } => todo!(),
        };
        let inst_ver = inst.get_version()?.specific();

        if pkg_ver > inst_ver || options.force {
            if cfg!(windows) {
                windows::upgrade(&options::Upgrade {
                    to_latest: false,
                    to_version: query.version.clone(),
                    to_channel: None,
                    to_testing: false,
                    to_nightly: false,
                    name: None,
                    instance: Some(name.clone()),
                    verbose: false,
                    force: options.force,
                    force_dump_restore: options.force,
                    non_interactive: true,
                }, &inst.name)?;
            } else {
                // When force is used we might upgrade to the same version, but
                // since some selector like `--to-latest` was specified we
                // assume user want to treat this upgrade as incompatible and
                // do the upgrade.  This is mostly for testing.
                if pkg_ver.is_compatible(&inst_ver) && !options.force {
                    upgrade::upgrade_compatible(inst, pkg)?;
                } else {
                    migrations::upgrade_check::to_version(&pkg, &config)?;
                    upgrade::upgrade_incompatible(inst, pkg)?;
                }
            }
            let config_version = if query.is_nightly() {
                query.clone()
            } else {
                // on `--to-latest` which is equivalent to `server-version="*"`
                // we put specific version instead
                Query::from_version(&pkg_ver)?
            };

            if config::modify(&config_path, &config_version)? {
                echo!("Remember to commit it to version control.");
            }
            let name_str = name.to_string();
            print_other_project_warning(&name_str, &root, &query)?;
        } else {
            echo!("Latest version found", pkg.version.to_string() + ",",
                  "current instance version is",
                  inst.get_version()?.emphasize().to_string() + ".",
                  "Already up to date.");
        }
    };
    Ok(())
}

fn print_other_project_warning(name: &str, project_path: &Path,
                               to_version: &Query)
    -> anyhow::Result<()>
{
    let mut project_dirs = Vec::new();
    for pd in find_project_dirs_by_instance(name)? {
        let real_pd = match read_project_path(&pd) {
            Ok(path) => path,
            Err(e) => {
                print::error(e);
                continue;
            }
        };
        if real_pd != project_path {
            project_dirs.push(real_pd);
        }
    }
    if !project_dirs.is_empty() {
        print::warn(format!(
            "Warning: the instance {} is still used by the following \
            projects:", name
        ));
        for pd in &project_dirs {
            eprintln!("  {}", pd.display());
        }
        eprintln!("Run the following commands to update them:");
        for pd in &project_dirs {
            upgrade::print_project_upgrade_command(&to_version, &None, pd);
        }
    }
    Ok(())
}

pub fn upgrade_instance(
    options: &Upgrade, opts: &crate::options::Options
) -> anyhow::Result<()> {
    let root = project_dir(options.project_dir.as_ref().map(|x| x.as_path()))?;
    let config_path = root.join("edgedb.toml");
    let config = config::read(&config_path)?;
    let cfg_ver = &config.edgedb.server_version;
    let schema_dir = &config.project.schema_dir;

    let stash_dir = stash_path(&root)?;
    if !stash_dir.exists() {
        anyhow::bail!("No instance initialized.");
    }

    let instance_name = instance_name(&stash_dir)?;
    let database = database_name(&stash_dir)?;
    let client = CloudClient::new(&opts.cloud_options)?;
    let mut inst = Handle::probe(&instance_name, &root, &schema_dir, &client)?;
    inst.database = database;
    let inst = match inst.instance {
        InstanceKind::Remote
            => anyhow::bail!("remote instances cannot be upgraded"),
        InstanceKind::Portable(inst) => inst,
        InstanceKind::Wsl(_) => todo!(),
        InstanceKind::Cloud { .. } => todo!(),
    };
    let inst_ver = inst.get_version()?.specific();

    let pkg = repository::get_server_package(&cfg_ver)?.with_context(||
        format!("cannot find package matching {}", cfg_ver.display()))?;
    let pkg_ver = pkg.version.specific();

    if pkg_ver > inst_ver || options.force {
        if cfg!(windows) {
            windows::upgrade(&options::Upgrade {
                to_latest: false,
                to_version: cfg_ver.version.clone(),
                to_channel: None,
                to_nightly: false,
                to_testing: false,
                name: None,
                instance: Some(instance_name.into()),
                verbose: false,
                force: options.force,
                force_dump_restore: options.force,
                non_interactive: true,
            }, &inst.name)?;
        } else {
            // When force is used we might upgrade to the same version, but
            // since some selector like `--to-latest` was specified we assume
            // user want to treat this upgrade as incompatible and do the
            // upgrade. This is mostly for testing.
            if pkg_ver.is_compatible(&inst_ver) {
                upgrade::upgrade_compatible(inst, pkg)?;
            } else {
                migrations::upgrade_check::to_version(&pkg, &config)?;
                upgrade::upgrade_incompatible(inst, pkg)?;
            }
        }
    } else {
        echo!("EdgeDB instance is up to date with \
               the specification in the `edgedb.toml`.");
        if cfg_ver.channel != Channel::Nightly {
            if let Some(pkg) =repository::get_server_package(&Query::stable())?
            {
                if pkg.version.specific() > inst_ver {
                    echo!("New major version is available:",
                          pkg.version.emphasize());
                    echo!("To update `edgedb.toml` and upgrade to this version, \
                           run:\n    edgedb project upgrade --to-latest");
                }
            }
        }
    }
    Ok(())
}
