//! Trusted user configuration: `~/.config/mac-agent-jail/config.toml`.
//!
//! There is deliberately no per-project config file: a repository is the
//! thing being sandboxed and must not be able to widen its own sandbox.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkMode {
    /// Any TCP/UDP destination; Unix sockets and loopback stay closed
    /// unless listed.
    Full,
    /// Only hosts on the allow-list, through a local CONNECT proxy.
    Filtered,
    /// No network at all.
    None,
}

impl NetworkMode {
    pub fn parse(value: &str) -> Result<NetworkMode, String> {
        match value {
            "full" | "on" => Ok(NetworkMode::Full),
            "filtered" | "proxy" => Ok(NetworkMode::Filtered),
            "none" | "off" => Ok(NetworkMode::None),
            other => Err(format!(
                "invalid network mode '{other}' (expected full, filtered, or none)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NetworkMode::Full => "full",
            NetworkMode::Filtered => "filtered",
            NetworkMode::None => "none",
        }
    }
}

/// One layer of settings. The config file base table, each
/// `[agents.<name>]` table, and the command line are all `Settings`; later
/// layers override scalars and extend lists.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Settings {
    pub network: Option<String>,
    pub allow_hosts: Vec<String>,
    pub localhost: Option<bool>,
    pub local_ports: Vec<u16>,
    pub keychain: Option<bool>,
    pub agent_state: Option<bool>,
    pub ssh_agent: Option<bool>,
    pub gh: Option<bool>,
    pub open_urls: Option<bool>,
    pub clipboard: Option<bool>,
    pub git_hooks: Option<bool>,
    pub default_hide: Option<bool>,
    pub inherit_env: Option<bool>,
    pub footer: Option<bool>,
    pub ro: Vec<String>,
    pub rw: Vec<String>,
    pub deny: Vec<String>,
    pub hide: Vec<String>,
    pub env: Vec<String>,
    pub unix_sockets: Vec<String>,
    pub mach_services: Vec<String>,
    pub args: Vec<String>,
}

impl Settings {
    pub fn merge(&mut self, other: &Settings) {
        fn scalar<T: Clone>(target: &mut Option<T>, value: &Option<T>) {
            if value.is_some() {
                target.clone_from(value);
            }
        }
        scalar(&mut self.network, &other.network);
        scalar(&mut self.localhost, &other.localhost);
        scalar(&mut self.keychain, &other.keychain);
        scalar(&mut self.agent_state, &other.agent_state);
        scalar(&mut self.ssh_agent, &other.ssh_agent);
        scalar(&mut self.gh, &other.gh);
        scalar(&mut self.open_urls, &other.open_urls);
        scalar(&mut self.clipboard, &other.clipboard);
        scalar(&mut self.git_hooks, &other.git_hooks);
        scalar(&mut self.default_hide, &other.default_hide);
        scalar(&mut self.inherit_env, &other.inherit_env);
        scalar(&mut self.footer, &other.footer);
        self.allow_hosts.extend(other.allow_hosts.iter().cloned());
        self.local_ports.extend(other.local_ports.iter().copied());
        self.ro.extend(other.ro.iter().cloned());
        self.rw.extend(other.rw.iter().cloned());
        self.deny.extend(other.deny.iter().cloned());
        self.hide.extend(other.hide.iter().cloned());
        self.env.extend(other.env.iter().cloned());
        self.unix_sockets.extend(other.unix_sockets.iter().cloned());
        self.mach_services
            .extend(other.mach_services.iter().cloned());
        self.args.extend(other.args.iter().cloned());
    }

    /// Without an explicit mode, a non-empty allow-list means filtered
    /// egress; otherwise the network is fully open.
    pub fn network_mode(&self) -> Result<NetworkMode, String> {
        match &self.network {
            Some(mode) => NetworkMode::parse(mode),
            None if !self.allow_hosts.is_empty() => Ok(NetworkMode::Filtered),
            None => Ok(NetworkMode::Full),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ConfigFile {
    #[serde(flatten)]
    pub base: Settings,
    pub agents: BTreeMap<String, Settings>,
}

impl ConfigFile {
    pub fn parse(text: &str) -> Result<ConfigFile, String> {
        let file: ConfigFile =
            toml::from_str(text).map_err(|e| e.to_string())?;
        for name in file.agents.keys() {
            if crate::agents::Agent::from_name(name).is_none() {
                return Err(format!(
                    "unknown agent table [agents.{name}] \
                     (expected claude, codex, cursor, or opencode)"
                ));
            }
        }
        Ok(file)
    }

    /// Base settings with the agent's table, if any, merged on top.
    pub fn settings_for(&self, agent: Option<&str>) -> Settings {
        let mut settings = self.base.clone();
        if let Some(table) = agent.and_then(|name| self.agents.get(name)) {
            settings.merge(table);
        }
        settings
    }
}

pub fn default_path(home: &Path, xdg_config_home: Option<&str>) -> PathBuf {
    xdg_config_home
        .filter(|dir| Path::new(dir).is_absolute())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
        .join("mac-agent-jail/config.toml")
}

/// Load the config file. A missing file is an empty config; an unreadable,
/// unsafe, or invalid one is an error, because silently dropping policy
/// would weaken the sandbox.
pub fn load(path: &Path) -> Result<ConfigFile, String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ConfigFile::default());
        }
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if !metadata.is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(format!(
            "{}: not owned by the current user",
            path.display()
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "{}: writable by group or others; run chmod go-w on it",
            path.display()
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    ConfigFile::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

pub const EXAMPLE: &str = r#"# mac-agent-jail configuration (~/.config/mac-agent-jail/config.toml)
# Command-line flags override everything here.

# Network: "full" (default), "filtered" (allow-list through a local proxy),
# or "none". A non-empty allow_hosts implies "filtered" unless set.
# network = "full"
# allow_hosts = ["github.com", "registry.npmjs.org"]

# In "full" mode, loopback (127.0.0.1, ::1) stays closed: services there
# are host processes outside the jail. Open single ports, or all of it.
# local_ports = [3000, 5173]
# localhost = false

# macOS Keychain access (login keychain, Touch ID prompts). On by default
# only for agents that keep their login there (claude, cursor); the
# Keychain also holds every other credential saved on this Mac.
# keychain = false

# Share the agent's own state dir (~/.claude, ~/.codex, ~/.cursor,
# opencode's XDG directories).
# agent_state = true

# Optional host capabilities, all off by default.
# ssh_agent = false   # forward $SSH_AUTH_SOCK (git over SSH)
# gh = false          # read the GitHub CLI config (~/.config/gh), so `gh`
#                     # works as you; its token is in the Keychain
# open_urls = false   # let `open https://...` reach the host browser
# clipboard = false   # pasteboard read/write (image paste)
# git_hooks = false   # allow writing .git/hooks and .git/config, and
#                     # creating repositories (git clone, git init)

# A line on the last row of the terminal saying the agent is jailed.
# footer = true

# Extra paths ("~" is expanded).
# ro = ["~/work/shared-libs"]
# rw = ["~/.local/state/my-tool"]
# deny = ["~/work/secrets"]

# Project files hidden from the agent (basename globs, or project-relative
# paths containing '/'). ".env" and ".env.*" are hidden by default; set
# default_hide = false to turn that off.
# hide = ["*.pem", "config/credentials.yml"]

# Environment: NAME forwards a host variable, NAME=VALUE sets one.
# env = ["GITHUB_TOKEN", "NODE_ENV=development"]

# Unix sockets the agent may connect to (e.g. Docker; root-equivalent).
# unix_sockets = ["~/.docker/run/docker.sock"]

# Per-agent tables merge over the base: scalars override, lists append.
# [agents.claude]
# args = ["--dangerously-skip-permissions"]
#
# [agents.codex]
# allow_hosts = ["github.com"]
#
# [agents.cursor]
# rw = ["~/.cursor-server"]
#
# [agents.opencode]
# allow_hosts = ["openrouter.ai"]   # your model provider, in filtered mode
# local_ports = [11434]             # a local model server such as Ollama
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses_to_defaults() {
        let file = ConfigFile::parse(EXAMPLE).unwrap();
        assert_eq!(file.base, Settings::default());
        assert!(file.agents.is_empty());
    }

    #[test]
    fn agent_table_merges_over_base() {
        let file = ConfigFile::parse(
            r#"
            network = "filtered"
            allow_hosts = ["github.com"]
            keychain = true
            [agents.codex]
            allow_hosts = ["pypi.org"]
            keychain = false
            local_ports = [3000]
            args = ["--yolo"]
            "#,
        )
        .unwrap();
        let codex = file.settings_for(Some("codex"));
        assert_eq!(codex.allow_hosts, vec!["github.com", "pypi.org"]);
        assert_eq!(codex.keychain, Some(false));
        assert_eq!(codex.args, vec!["--yolo"]);
        assert_eq!(codex.local_ports, vec![3000]);
        let claude = file.settings_for(Some("claude"));
        assert_eq!(claude.allow_hosts, vec!["github.com"]);
        assert_eq!(claude.keychain, Some(true));
    }

    #[test]
    fn unknown_agent_table_is_rejected() {
        let err = ConfigFile::parse("[agents.gemini]\nkeychain = false\n")
            .unwrap_err();
        assert!(err.contains("agents.gemini"));
    }

    #[test]
    fn network_mode_defaults() {
        let mut settings = Settings::default();
        assert_eq!(settings.network_mode(), Ok(NetworkMode::Full));
        settings.allow_hosts.push("github.com".into());
        assert_eq!(settings.network_mode(), Ok(NetworkMode::Filtered));
        settings.network = Some("none".into());
        assert_eq!(settings.network_mode(), Ok(NetworkMode::None));
        settings.network = Some("bogus".into());
        assert!(settings.network_mode().is_err());
    }

    #[test]
    fn invalid_toml_is_an_error() {
        assert!(ConfigFile::parse("network = [").is_err());
        assert!(ConfigFile::parse("keychain = \"yes\"").is_err());
    }

    #[test]
    fn missing_file_is_empty_and_loose_permissions_fail() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir()
            .join(format!("maj-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        assert!(load(&path).unwrap().agents.is_empty());
        std::fs::write(&path, "keychain = false\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert_eq!(load(&path).unwrap().base.keychain, Some(false));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .unwrap();
        assert!(load(&path).unwrap_err().contains("writable"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn default_path_prefers_absolute_xdg() {
        let home = Path::new("/Users/me");
        assert_eq!(
            default_path(home, None),
            PathBuf::from("/Users/me/.config/mac-agent-jail/config.toml")
        );
        assert_eq!(
            default_path(home, Some("/x")),
            PathBuf::from("/x/mac-agent-jail/config.toml")
        );
        assert_eq!(
            default_path(home, Some("relative")),
            PathBuf::from("/Users/me/.config/mac-agent-jail/config.toml")
        );
    }
}
