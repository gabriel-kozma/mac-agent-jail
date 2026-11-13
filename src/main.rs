mod agents;
mod cli;
mod config;
mod env;
mod policy;
mod process;
mod profile;
mod proxy;
mod ps_shim;

use std::{
    ffi::OsString,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use agents::Agent;
use cli::Action;
use config::NetworkMode;

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const DEFAULT_SHELL: &str = "/bin/zsh";

fn main() {
    if ps_shim::is_invoked_as_ps() {
        std::process::exit(ps_shim::run());
    }
    let args: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(OsString::into_string)
        .collect::<Result<_, _>>()
    {
        Ok(args) => args,
        Err(arg) => fail(&format!("argument is not valid UTF-8: {arg:?}")),
    };
    match run(args) {
        Ok(code) => std::process::exit(code),
        Err(message) => fail(&message),
    }
}

fn fail(message: &str) -> ! {
    eprintln!("mac-agent-jail: error: {message}");
    std::process::exit(125);
}

fn warn(message: &str) {
    eprintln!("mac-agent-jail: warning: {message}");
}

fn run(args: Vec<String>) -> Result<i32, String> {
    let cli = cli::parse(args)?;
    match cli.action {
        Action::Help => {
            print!("{}", cli::USAGE);
            return Ok(0);
        }
        Action::Version => {
            println!("mac-agent-jail {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }
        Action::PrintConfig => {
            print!("{}", config::EXAMPLE);
            return Ok(0);
        }
        Action::Run => {}
    }

    let host_env: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(k, v)| {
            Some((k.into_string().ok()?, v.into_string().ok()?))
        })
        .collect();
    let getenv = |key: &str| {
        host_env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };

    let home = home_dir(getenv("HOME"))?;
    let config_path = cli.config.clone().unwrap_or_else(|| {
        config::default_path(&home, getenv("XDG_CONFIG_HOME").as_deref())
    });
    let config_file = config::load(&config_path)?;

    // --- what to run -----------------------------------------------------
    let host_path: Vec<PathBuf> = getenv("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    let (agent, program_name, user_args) = match cli.command.split_first() {
        Some((program, rest)) => {
            (Agent::detect(program), program.clone(), rest.to_vec())
        }
        None => (None, DEFAULT_SHELL.to_string(), Vec::new()),
    };
    let mut settings = config_file.settings_for(agent.map(Agent::name));
    settings.merge(&cli.settings);
    let network = settings.network_mode()?;

    let program_name = match agent {
        Some(agent) => agent.resolve_program(&program_name, &|name| {
            find_program(name, &host_path).is_some()
        }),
        None => program_name,
    };
    let program = find_program(&program_name, &host_path)
        .ok_or_else(|| format!("command not found: {program_name}"))?;
    let mut args = Vec::new();
    if let Some(agent) = agent {
        if let Some(message) = agent.nested_sandbox_warning(&user_args) {
            warn(&message);
        }
        if let Some(message) = agent.provider_warning(&getenv, &settings) {
            warn(&message);
        }
        args.extend(agent.nested_sandbox_args(&user_args));
    }
    args.extend(settings.args.iter().cloned());
    args.extend(user_args);
    let shell_mode = cli.command.is_empty();
    if shell_mode {
        args.push("-i".into());
    }

    // --- where -----------------------------------------------------------
    let project = match &cli.project {
        Some(dir) => dir.clone(),
        None => std::env::current_dir()
            .map_err(|e| format!("cannot read the current directory: {e}"))?,
    };
    let project = std::fs::canonicalize(&project)
        .map_err(|e| format!("project {}: {e}", project.display()))?;
    if !project.is_dir() {
        return Err(format!(
            "project {} is not a directory",
            project.display()
        ));
    }
    if home.starts_with(&project) {
        return Err(format!(
            "refusing to use {} as the project: it would make your whole \
             home writable. cd into a project directory first.",
            project.display()
        ));
    }

    if !cli.dry_run && !Path::new(SANDBOX_EXEC).is_file() {
        return Err(format!(
            "{SANDBOX_EXEC} not found; mac-agent-jail requires macOS"
        ));
    }

    // --- per-run resources -----------------------------------------------
    let session = Session::create(cli.dry_run)?;
    let session_dir = session.as_ref().map(|s| s.dir.clone());
    if let Some(dir) = &session_dir
        && !cli.dry_run
    {
        prepare_session(dir, agent, shell_mode)?;
    }

    let mut hosts: Vec<String> = settings.allow_hosts.clone();
    if let Some(agent) = agent {
        hosts.extend(agent.api_hosts().iter().map(|h| h.to_string()));
    }
    let allow = proxy::AllowList::new(&hosts);
    let proxy = if network == NetworkMode::Filtered && !cli.dry_run {
        Some(
            proxy::start(allow.clone())
                .map_err(|e| format!("cannot start egress proxy: {e}"))?,
        )
    } else {
        None
    };
    let proxy_port = match (&proxy, network) {
        (Some(proxy), _) => Some(proxy.port),
        (None, NetworkMode::Filtered) => Some(0),
        _ => None,
    };

    let use_pty = !cli.no_pty
        && !cli.dry_run
        && process::is_tty(libc::STDIN_FILENO)
        && process::is_tty(libc::STDOUT_FILENO);
    let pty = if use_pty {
        Some(
            process::Pty::open()
                .map_err(|e| format!("cannot allocate a PTY: {e}"))?,
        )
    } else {
        None
    };

    // --- policy ----------------------------------------------------------
    let host = policy::Host {
        home: home.clone(),
        uid: unsafe { libc::getuid() },
        user_cache_dir: darwin_dir(DarwinDir::Cache),
        session_dir: session_dir.clone(),
        exe: std::env::current_exe().ok().map(|p| policy::canon(&p)),
        config: std::path::absolute(&config_path)
            .ok()
            .map(|p| policy::canon(&p)),
        path: host_path.clone(),
        ssh_auth_sock: getenv("SSH_AUTH_SOCK").map(PathBuf::from),
    };
    let request = policy::Request {
        settings: &settings,
        agent,
        project: &project,
        program: Some(&program),
        tty: pty.as_ref().map(|p| p.path.as_path()),
        proxy_port,
        env: &getenv,
    };
    let (profile, warnings) = policy::resolve(&host, &request)?;
    for message in &warnings {
        warn(message);
    }
    let profile_text = profile::render(&profile);

    let shim_dir = session_dir
        .as_ref()
        .filter(|_| agent == Some(Agent::Codex))
        .map(|dir| dir.join("bin"));
    let zdotdir = session_dir.as_ref().filter(|_| shell_mode).cloned();
    let child_env = env::build(&env::Input {
        host: &host_env,
        settings: &settings,
        agent,
        session_dir: session_dir.as_deref(),
        proxy_port,
        path_prefix: shim_dir.as_deref(),
        zdotdir: zdotdir.as_deref(),
    })?;

    if cli.dry_run {
        print_dry_run(&DryRun {
            agent,
            project: &project,
            program: &program,
            args: &args,
            network,
            allow: &allow,
            keychain: policy::keychain_enabled(&settings, agent),
            env: &child_env,
            profile: &profile_text,
        });
        return Ok(0);
    }
    if cli.verbose {
        eprintln!("{profile_text}");
    }

    let mut cmd = Command::new(SANDBOX_EXEC);
    cmd.arg("-p")
        .arg(&profile_text)
        .arg("--")
        .arg(&program)
        .args(&args)
        .current_dir(&project)
        .env_clear()
        .envs(child_env);

    let status = match pty {
        Some(pty) => pty.run(cmd),
        None => process::run_plain(cmd),
    }
    .map_err(|e| format!("cannot run {}: {e}", program.display()))?;

    if let Some(proxy) = &proxy {
        let blocked = proxy.blocked.lock().unwrap();
        if !blocked.is_empty() {
            let list: Vec<&str> = blocked.iter().map(String::as_str).collect();
            warn(&format!(
                "filtered egress blocked: {} (allow with --allow-host)",
                list.join(", ")
            ));
        }
    }
    drop(session);
    Ok(process::exit_code(status))
}

fn home_dir(value: Option<String>) -> Result<PathBuf, String> {
    let home = value
        .filter(|h| Path::new(h).is_absolute())
        .ok_or("HOME must be set to an absolute path")?;
    std::fs::canonicalize(&home).map_err(|e| format!("HOME {home}: {e}"))
}

fn find_program(name: &str, path: &[PathBuf]) -> Option<PathBuf> {
    let is_exec = |p: &Path| {
        p.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if name.contains('/') {
        let p = PathBuf::from(name);
        let p = if p.is_absolute() {
            p
        } else {
            std::env::current_dir().ok()?.join(p)
        };
        return is_exec(&p).then_some(p);
    }
    path.iter()
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|p| is_exec(p))
}

/// This run's private TMPDIR, removed when the run ends.
struct Session {
    dir: PathBuf,
    remove: bool,
}

impl Session {
    fn create(dry_run: bool) -> Result<Option<Session>, String> {
        let Some(root) = darwin_dir(DarwinDir::Temp) else {
            warn("no per-user temp directory; TMPDIR access disabled");
            return Ok(None);
        };
        let dir = root.join(format!("mac-agent-jail.{}", std::process::id()));
        if dry_run {
            return Ok(Some(Session { dir, remove: false }));
        }
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot secure {}: {e}", dir.display()))?;
        Ok(Some(Session { dir, remove: true }))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.remove {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn prepare_session(
    dir: &Path,
    agent: Option<Agent>,
    shell_mode: bool,
) -> Result<(), String> {
    if agent == Some(Agent::Codex) {
        let bin = dir.join("bin");
        let exe = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|e| format!("cannot locate mac-agent-jail: {e}"))?;
        std::fs::create_dir(&bin)
            .and_then(|_| std::os::unix::fs::symlink(&exe, bin.join("ps")))
            .map_err(|e| format!("cannot install the Codex ps helper: {e}"))?;
    }
    if shell_mode {
        std::fs::write(
            dir.join(".zshrc"),
            "PROMPT='%F{yellow}(jail)%f %~ %# '\n",
        )
        .map_err(|e| format!("cannot write shell rc: {e}"))?;
    }
    Ok(())
}

enum DarwinDir {
    Temp,
    Cache,
}

/// Darwin's per-user temp or cache directory (`getconf DARWIN_USER_*_DIR`),
/// accepted only when owned by us and not writable by others.
#[cfg(target_os = "macos")]
fn darwin_dir(which: DarwinDir) -> Option<PathBuf> {
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

    let name = match which {
        DarwinDir::Temp => libc::_CS_DARWIN_USER_TEMP_DIR,
        DarwinDir::Cache => libc::_CS_DARWIN_USER_CACHE_DIR,
    };
    let len = unsafe { libc::confstr(name, std::ptr::null_mut(), 0) };
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    if unsafe { libc::confstr(name, buf.as_mut_ptr().cast(), buf.len()) } == 0 {
        return None;
    }
    buf.truncate(len - 1);
    let dir = std::fs::canonicalize(std::ffi::OsStr::from_bytes(&buf)).ok()?;
    let meta = dir.metadata().ok()?;
    (meta.is_dir()
        && meta.uid() == unsafe { libc::geteuid() }
        && meta.mode() & 0o022 == 0)
        .then_some(dir)
}

#[cfg(not(target_os = "macos"))]
fn darwin_dir(which: DarwinDir) -> Option<PathBuf> {
    match which {
        DarwinDir::Temp => std::fs::canonicalize(std::env::temp_dir()).ok(),
        DarwinDir::Cache => None,
    }
}

struct DryRun<'a> {
    agent: Option<Agent>,
    project: &'a Path,
    program: &'a Path,
    args: &'a [String],
    network: NetworkMode,
    allow: &'a proxy::AllowList,
    keychain: bool,
    env: &'a [(String, String)],
    profile: &'a str,
}

fn print_dry_run(d: &DryRun) {
    println!(
        "# agent:    {}",
        d.agent.map(Agent::name).unwrap_or("(none)")
    );
    println!("# project:  {}", d.project.display());
    println!(
        "# keychain: {}",
        if d.keychain { "allowed" } else { "blocked" }
    );
    match d.network {
        NetworkMode::Filtered => {
            println!("# network:  filtered ({})", d.allow.entries().join(", "))
        }
        mode => println!("# network:  {}", mode.as_str()),
    }
    let mut line = format!(
        "{SANDBOX_EXEC} -p '<profile>' -- {}",
        quote(&d.program.to_string_lossy())
    );
    for arg in d.args {
        line.push(' ');
        line.push_str(&quote(arg));
    }
    println!("# command:  {line}");
    let names: Vec<&str> = d.env.iter().map(|(k, _)| k.as_str()).collect();
    println!("# env:      {}", names.join(" "));
    println!();
    print!("{}", d.profile);
}

fn quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,@+".contains(c))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(quote("--yolo"), "--yolo");
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), "'it'\\''s'");
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn find_program_searches_path() {
        let found = find_program(
            "sh",
            &[PathBuf::from("relative"), PathBuf::from("/bin")],
        );
        assert_eq!(found, Some(PathBuf::from("/bin/sh")));
        assert_eq!(
            find_program("/bin/sh", &[]),
            Some(PathBuf::from("/bin/sh"))
        );
        assert_eq!(
            find_program("definitely-not-a-command", &[PathBuf::from("/bin")]),
            None
        );
    }

    #[test]
    fn home_must_be_absolute() {
        assert!(home_dir(None).is_err());
        assert!(home_dir(Some("relative".into())).is_err());
        assert!(home_dir(Some("/".into())).is_ok());
    }
}
