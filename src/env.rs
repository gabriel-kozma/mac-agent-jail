//! The environment handed to the sandboxed command. By default only an
//! allow-list of terminal, locale, and toolchain variables crosses over, so
//! unrelated secrets exported in the host shell stay outside.

use std::{collections::BTreeMap, path::Path};

use crate::{agents::Agent, config::Settings};

const BASE: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "COLORTERM",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "TERMINFO",
    "LANG",
    "TZ",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "LESS",
    "NO_COLOR",
    "FORCE_COLOR",
    "CLICOLOR",
    "COLUMNS",
    "LINES",
    "__CF_USER_TEXT_ENCODING",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "DEVELOPER_DIR",
    "SDKROOT",
    "HOMEBREW_PREFIX",
    "HOMEBREW_CELLAR",
    "HOMEBREW_REPOSITORY",
    "NVM_DIR",
    "NVM_BIN",
    "NVM_INC",
    "VOLTA_HOME",
    "FNM_DIR",
    "FNM_MULTISHELL_PATH",
    "PNPM_HOME",
    "BUN_INSTALL",
    "DENO_INSTALL",
    "GOPATH",
    "GOROOT",
    "GOBIN",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "JAVA_HOME",
    "PYENV_ROOT",
    "PYENV_VERSION",
    "RBENV_ROOT",
    "ASDF_DIR",
    "ASDF_DATA_DIR",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
];

const BASE_PREFIXES: &[&str] = &["LC_", "MISE_"];

const PROXY_VARS: &[&str] = &[
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
];

pub struct Input<'a> {
    pub host: &'a [(String, String)],
    pub settings: &'a Settings,
    pub agent: Option<Agent>,
    pub session_dir: Option<&'a Path>,
    pub proxy_port: Option<u16>,
    /// Directory prepended to PATH (the Codex `ps` shim).
    pub path_prefix: Option<&'a Path>,
    /// ZDOTDIR for the default interactive shell.
    pub zdotdir: Option<&'a Path>,
}

pub fn build(input: &Input) -> Result<Vec<(String, String)>, String> {
    let host: BTreeMap<&str, &str> = input
        .host
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let s = input.settings;
    let mut env: BTreeMap<String, String> = BTreeMap::new();

    if s.inherit_env.unwrap_or(false) {
        for (key, value) in &host {
            env.insert(key.to_string(), value.to_string());
        }
    } else {
        for (key, value) in &host {
            if BASE.contains(key)
                || BASE_PREFIXES.iter().any(|p| key.starts_with(p))
            {
                env.insert(key.to_string(), value.to_string());
            }
        }
    }
    if let Some(agent) = input.agent {
        for key in agent.env_passthrough() {
            if let Some(value) = host.get(key) {
                env.insert(key.to_string(), value.to_string());
            }
        }
    }
    if s.ssh_agent.unwrap_or(false)
        && let Some(sock) = host.get("SSH_AUTH_SOCK")
    {
        env.insert("SSH_AUTH_SOCK".into(), sock.to_string());
    }
    for entry in &s.env {
        let (name, value) = parse_entry(entry)?;
        match value {
            Some(value) => {
                env.insert(name.to_string(), value.to_string());
            }
            None => {
                if let Some(value) = host.get(name) {
                    env.insert(name.to_string(), value.to_string());
                }
            }
        }
    }
    if let Some(agent) = input.agent {
        for (key, value) in agent.env_overrides() {
            env.entry(key.to_string())
                .or_insert_with(|| value.to_string());
        }
    }

    // Forced last: the user cannot point these elsewhere.
    env.insert("MAC_AGENT_JAIL".into(), "1".into());
    if let Some(dir) = input.session_dir {
        env.insert("TMPDIR".into(), with_slash(dir));
    }
    if let Some(dir) = input.zdotdir {
        env.insert("ZDOTDIR".into(), dir.to_string_lossy().into_owned());
    }
    if let Some(prefix) = input.path_prefix {
        let path = env.get("PATH").cloned().unwrap_or_default();
        let joined = if path.is_empty() {
            prefix.to_string_lossy().into_owned()
        } else {
            format!("{}:{path}", prefix.to_string_lossy())
        };
        env.insert("PATH".into(), joined);
    }
    if let Some(port) = input.proxy_port {
        for key in PROXY_VARS {
            env.remove(*key);
        }
        let url = format!("http://127.0.0.1:{port}");
        for key in &PROXY_VARS[..4] {
            env.insert(key.to_string(), url.clone());
        }
        // Node's built-in fetch ignores *_proxy unless asked to honor it.
        env.insert("NODE_USE_ENV_PROXY".into(), "1".into());
    }
    Ok(env.into_iter().collect())
}

fn parse_entry(entry: &str) -> Result<(&str, Option<&str>), String> {
    let (name, value) = match entry.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (entry, None),
    };
    let valid = !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Err(format!("invalid --env entry '{entry}'"));
    }
    Ok((name, value))
}

fn with_slash(dir: &Path) -> String {
    let mut text = dir.to_string_lossy().into_owned();
    if !text.ends_with('/') {
        text.push('/');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Vec<(String, String)> {
        [
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/Users/me"),
            ("USER", "me"),
            ("LC_ALL", "en_US.UTF-8"),
            ("AWS_SECRET_ACCESS_KEY", "s3cr3t"),
            ("ANTHROPIC_API_KEY", "sk-ant"),
            ("OPENAI_API_KEY", "sk-oai"),
            ("SSH_AUTH_SOCK", "/tmp/agent.sock"),
            ("HTTPS_PROXY", "http://corp:3128"),
            ("CUSTOM", "value"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn run(
        settings: &Settings,
        agent: Option<Agent>,
    ) -> BTreeMap<String, String> {
        let host = host();
        let input = Input {
            host: &host,
            settings,
            agent,
            session_dir: Some(Path::new("/private/var/folders/T/s")),
            proxy_port: None,
            path_prefix: None,
            zdotdir: None,
        };
        build(&input).unwrap().into_iter().collect()
    }

    #[test]
    fn allowlist_drops_unrelated_secrets() {
        let env = run(&Settings::default(), None);
        assert_eq!(env["PATH"], "/usr/bin:/bin");
        assert_eq!(env["USER"], "me");
        assert_eq!(env["LC_ALL"], "en_US.UTF-8");
        assert_eq!(env["TMPDIR"], "/private/var/folders/T/s/");
        assert_eq!(env["MAC_AGENT_JAIL"], "1");
        for key in [
            "AWS_SECRET_ACCESS_KEY",
            "ANTHROPIC_API_KEY",
            "SSH_AUTH_SOCK",
            "HTTPS_PROXY",
            "CUSTOM",
        ] {
            assert!(!env.contains_key(key), "{key} leaked");
        }
    }

    #[test]
    fn agents_get_only_their_own_keys() {
        let env = run(&Settings::default(), Some(Agent::Claude));
        assert_eq!(env["ANTHROPIC_API_KEY"], "sk-ant");
        assert_eq!(env["DISABLE_AUTOUPDATER"], "1");
        assert!(!env.contains_key("OPENAI_API_KEY"));
        let env = run(&Settings::default(), Some(Agent::Codex));
        assert_eq!(env["OPENAI_API_KEY"], "sk-oai");
        assert!(!env.contains_key("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn explicit_entries_and_ssh_agent() {
        let settings = Settings {
            env: vec!["CUSTOM".into(), "NEW=1".into(), "MISSING".into()],
            ssh_agent: Some(true),
            ..Settings::default()
        };
        let env = run(&settings, None);
        assert_eq!(env["CUSTOM"], "value");
        assert_eq!(env["NEW"], "1");
        assert!(!env.contains_key("MISSING"));
        assert_eq!(env["SSH_AUTH_SOCK"], "/tmp/agent.sock");
    }

    #[test]
    fn user_cannot_override_forced_values() {
        let settings = Settings {
            env: vec!["TMPDIR=/tmp".into(), "MAC_AGENT_JAIL=0".into()],
            ..Settings::default()
        };
        let env = run(&settings, None);
        assert_eq!(env["TMPDIR"], "/private/var/folders/T/s/");
        assert_eq!(env["MAC_AGENT_JAIL"], "1");
    }

    #[test]
    fn inherit_env_passes_everything() {
        let settings = Settings {
            inherit_env: Some(true),
            ..Settings::default()
        };
        let env = run(&settings, None);
        assert_eq!(env["AWS_SECRET_ACCESS_KEY"], "s3cr3t");
        assert_eq!(env["HTTPS_PROXY"], "http://corp:3128");
    }

    #[test]
    fn filtered_mode_points_every_proxy_variable_at_the_jail_proxy() {
        let host = host();
        let settings = Settings {
            env: vec!["https_proxy=http://evil:1".into()],
            ..Settings::default()
        };
        let input = Input {
            host: &host,
            settings: &settings,
            agent: None,
            session_dir: None,
            proxy_port: Some(4444),
            path_prefix: Some(Path::new("/s/bin")),
            zdotdir: None,
        };
        let env: BTreeMap<_, _> = build(&input).unwrap().into_iter().collect();
        for key in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
            assert_eq!(env[key], "http://127.0.0.1:4444");
        }
        assert_eq!(env["NODE_USE_ENV_PROXY"], "1");
        assert_eq!(env["PATH"], "/s/bin:/usr/bin:/bin");
    }

    #[test]
    fn invalid_entries_are_rejected() {
        for bad in ["", "=x", "1A", "A-B=c"] {
            assert!(parse_entry(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_entry("A_1=x=y").unwrap(), ("A_1", Some("x=y")));
    }
}
