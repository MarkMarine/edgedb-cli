#[cfg(not(windows))]
#[macro_use] extern crate pretty_assertions;

use std::sync::Mutex;
use std::convert::TryInto;
use std::io::{BufReader, BufRead};
use std::fs;
use std::sync::mpsc::sync_channel;
use std::thread::{self, JoinHandle};
use std::process;
use std::env;
use std::path::Path;

use assert_cmd::Command;
use once_cell::sync::Lazy;
use serde_json::from_str;

// Can't run server on windows
#[cfg(not(windows))]
mod dump_restore;
#[cfg(not(windows))]
mod configure;
#[cfg(not(windows))]
mod non_interactive;
#[cfg(not(windows))]
mod migrations;
#[cfg(not(windows))]
mod instance_link;

// for some reason rexpect doesn't work on macos
// and also something wrong on musl libc
#[cfg(all(target_os="linux", not(target_env="musl")))]
mod interactive;

#[path="../util.rs"]
mod util;
mod help;

pub struct Config {
    dir: tempfile::TempDir,
}

#[cfg(not(windows))]
fn term_process(proc: &mut process::Child) {
    use nix::unistd::Pid;
    use nix::sys::signal::{self, Signal};

    if let Err(e) = signal::kill(
        Pid::from_raw(proc.id() as libc::pid_t), Signal::SIGTERM
    ) {
        eprintln!("could not send SIGTERM to edgedb-server: {:?}", e);
    };
}

#[cfg(windows)]
fn term_process(proc: &mut process::Child) {
    // This is suboptimal -- ideally we need to close the process
    // gracefully on Windows too.
    if let Err(e) = proc.kill() {
        eprintln!("could not kill edgedb-server: {:?}", e);
    }
}

pub static SHUTDOWN_INFO: Lazy<Mutex<Vec<ShutdownInfo>>> =
    Lazy::new(|| Mutex::new(Vec::new()));
pub static SERVER: Lazy<ServerGuard> = Lazy::new(|| ServerGuard::start());

#[cfg(not(windows))]
#[test]
fn simple_query() {
    let cmd = SERVER.admin_cmd().arg("query").arg("SELECT 1+7").assert();
    cmd.success().stdout("8\n");
}

#[cfg(not(windows))]
#[test]
fn version() {
    let cmd = SERVER.admin_cmd().arg("--version").assert();
    cmd.success()
        .stdout(concat!("EdgeDB CLI ", env!("CARGO_PKG_VERSION"), "\n"));
}

pub struct ShutdownInfo {
    process: process::Child,
    thread: Option<JoinHandle<()>>,
}

pub struct ServerGuard {
    pub port: u16,
    runstate_dir: String,
    tls_cert_file: String,
}

impl ServerGuard {
    fn start() -> ServerGuard {
        use std::process::{Command, Stdio};

        let bin_name = if let Ok(ver) = env::var("EDGEDB_MAJOR_VERSION") {
            format!("edgedb-server-{}", ver)
        } else {
            "edgedb-server".to_string()
        };
        let mut cmd = Command::new(&bin_name);
        cmd.env("EDGEDB_SERVER_INSECURE_DEV_MODE", "1"); // deprecated
        cmd.env("EDGEDB_SERVER_SECURITY", "insecure_dev_mode");
        cmd.arg("--temp-dir");
        cmd.arg("--testmode");
        cmd.arg("--echo-runtime-info");
        cmd.arg("--port=auto");
        cmd.arg("--generate-self-signed-cert");
        #[cfg(unix)]
        if unsafe { libc::geteuid() } == 0 {
            use std::os::unix::process::CommandExt;
            // This is moslty true in vagga containers, so run edgedb/postgres
            // by any non-root user
            cmd.uid(1);
        }
        cmd.stdout(Stdio::piped());

        let mut process = cmd.spawn()
            .expect(&format!("Can run {}", bin_name));
        let process_in = process.stdout.take().expect("stdout is pipe");
        let (tx, rx) = sync_channel(1);
        let thread = thread::spawn(move || {
            let buf = BufReader::new(process_in);
            for line in buf.lines() {
                match line {
                    Ok(line) => {
                        if line.starts_with("EDGEDB_SERVER_DATA:") {
                            let data: serde_json::Value = from_str(
                                &line["EDGEDB_SERVER_DATA:".len()..])
                                .expect("valid server data");
                            println!("Server data {:?}", data);
                            let port = data.get("port")
                                .and_then(|x| x.as_u64())
                                .and_then(|x| x.try_into().ok())
                                .expect("valid server data");
                            let runstate_dir = data.get("runstate_dir")
                                .and_then(|x| x.as_str())
                                .map(|x| x.to_owned())
                                .expect("valid server data");
                            let tls_cert_file = data.get("tls_cert_file")
                                .and_then(|x| x.as_str())
                                .map(|x| x.to_owned())
                                .expect("valid server data");
                            tx.send((port, runstate_dir, tls_cert_file))
                                .expect("valid channel");
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading from server: {}", e);
                        break;
                    }
                }
            }
        });
        let (port, runstate_dir, tls_cert_file) = rx.recv().expect("valid port received");

        let mut sinfo = SHUTDOWN_INFO.lock().expect("shutdown mutex works");
        if sinfo.is_empty() {
            shutdown_hooks::add_shutdown_hook(stop_processes);
        }
        sinfo.push(ShutdownInfo {
            process,
            thread: Some(thread),
        });

        ServerGuard {
            port,
            runstate_dir,
            tls_cert_file,
        }
    }

    pub fn admin_cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("edgedb").expect("binary found");
        cmd.arg("--no-cli-update-check");
        cmd.arg("--admin");
        cmd.arg("--unix-path").arg(&self.runstate_dir);
        cmd.arg("--port").arg(self.port.to_string());
        cmd.env("CLICOLOR", "0");
        return cmd
    }

    pub fn admin_cmd_deprecated(&self) -> Command {
        let mut cmd = Command::cargo_bin("edgedb").expect("binary found");
        cmd.arg("--no-cli-update-check");
        cmd.arg("--admin");
        // test deprecated --host /unix/path
        cmd.arg("--host").arg(&self.runstate_dir);
        cmd.arg("--port").arg(self.port.to_string());
        cmd.env("CLICOLOR", "0");
        return cmd
    }

    pub fn raw_cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("edgedb").expect("binary found");
        cmd.arg("--no-cli-update-check");
        cmd.env("CLICOLOR", "0");
        return cmd
    }

    #[cfg(not(windows))]
    pub fn admin_interactive(&self) -> rexpect::session::PtySession {
        use assert_cmd::cargo::CommandCargoExt;
        use rexpect::session::spawn_command;

        let mut cmd = process::Command::cargo_bin("edgedb")
            .expect("binary found");
        cmd.arg("--no-cli-update-check");
        cmd.arg("--admin");
        cmd.arg("--unix-path").arg(&self.runstate_dir);
        cmd.arg("--port").arg(self.port.to_string());
        return spawn_command(cmd, Some(10000)).expect("start interactive");
    }
    #[cfg(not(windows))]
    pub fn custom_interactive(&self, f: impl FnOnce(&mut process::Command))
        -> rexpect::session::PtySession
    {
        use assert_cmd::cargo::CommandCargoExt;
        use rexpect::session::spawn_command;

        let mut cmd = process::Command::cargo_bin("edgedb")
            .expect("binary found");
        cmd.arg("--no-cli-update-check");
        cmd.arg("--admin");
        cmd.arg("--unix-path").arg(&self.runstate_dir);
        cmd.arg("--port").arg(self.port.to_string());
        cmd.arg("--tls-ca-file").arg(&self.tls_cert_file);
        cmd.env("CLICOLOR", "0");
        f(&mut cmd);
        return spawn_command(cmd, Some(10000)).expect("start interactive");
    }

    pub fn database_cmd(&self, database_name: &str) -> Command {
        let mut cmd = Command::cargo_bin("edgedb").expect("binary found");
        cmd.arg("--no-cli-update-check");
        cmd.arg("--admin");
        cmd.arg("--unix-path").arg(&self.runstate_dir);
        cmd.arg("--port").arg(self.port.to_string());
        cmd.arg("--database").arg(database_name);
        cmd.arg("--tls-ca-file").arg(&self.tls_cert_file);
        return cmd
    }
}

extern fn stop_processes() {
    let mut items = SHUTDOWN_INFO.lock().expect("shutdown mutex works");
    for item in items.iter_mut() {
        term_process(&mut item.process);
    }
    for item in items.iter_mut() {
        item.process.wait().ok();
        item.thread.take().expect("not yet joined").join().ok();
    }
}

impl Config {
    pub fn new(data: &str) -> Config {
        let tmp_dir = tempfile::tempdir().expect("tmpdir");
        let dir = tmp_dir.path().join("edgedb");
        fs::create_dir(&dir).expect("mkdir");
        fs::write(dir.join("cli.toml"), data.as_bytes()).expect("config");
        Config {
            dir: tmp_dir,
        }
    }
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}
