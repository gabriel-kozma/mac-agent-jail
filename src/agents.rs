//! Built-in knowledge about the agents this jail is tuned for.
//!
//! Each agent contributes the host state it needs to start logged in
//! (read-write), its self-managed installation (read-only, so an agent
//! cannot replace the binary the host will run next), the API hosts used by
//! filtered egress, and a handful of environment tweaks.

use std::path::{Path, PathBuf};

use crate::config::Settings;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Codex,
    Cursor,
    Opencode,
}

/// Host paths an agent needs, resolved against a home directory and the
/// agent's own environment overrides (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
/// `OPENCODE_CONFIG_DIR`, the XDG base directories).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AgentPaths {
    /// Credential/config/session state, mounted read-write.
    pub state: Vec<PathBuf>,
    /// Self-managed installations, readable but never writable.
    pub install: Vec<PathBuf>,
    /// Paths inside `state` that stay write-protected because the host
    /// executes them outside the jail.
    pub write_protected: Vec<PathBuf>,
    /// Paths inside `state` hidden from the agent.
    pub hidden: Vec<PathBuf>,
}

impl Agent {
    pub const ALL: [Agent; 4] =
        [Agent::Claude, Agent::Codex, Agent::Cursor, Agent::Opencode];

    /// Identify the agent from the program name (basename of argv\[0\]).
    pub fn detect(program: &str) -> Option<Agent> {
        let name = Path::new(program).file_name()?.to_str()?;
        match name {
            "claude" => Some(Agent::Claude),
            "codex" => Some(Agent::Codex),
            "cursor-agent" | "cursor" | "agent" => Some(Agent::Cursor),
            "opencode" => Some(Agent::Opencode),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
            Agent::Cursor => "cursor",
            Agent::Opencode => "opencode",
        }
    }

    pub fn from_name(name: &str) -> Option<Agent> {
        Agent::ALL.into_iter().find(|agent| agent.name() == name)
    }

    pub fn paths(
        self,
        home: &Path,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> AgentPaths {
        let from_env = |key: &str, default: &str| {
            env(key)
                .filter(|value| !value.is_empty())
                .map(|value| expand_home(&value, home))
                .unwrap_or_else(|| home.join(default))
        };
        match self {
            Agent::Claude => AgentPaths {
                state: vec![
                    from_env("CLAUDE_CONFIG_DIR", ".claude"),
                    home.join(".claude.json"),
                ],
                install: vec![home.join(".local/share/claude")],
                ..AgentPaths::default()
            },
            Agent::Codex => AgentPaths {
                state: vec![from_env("CODEX_HOME", ".codex")],
                ..AgentPaths::default()
            },
            Agent::Cursor => {
                let state_dir = home.join(".cursor");
                AgentPaths {
                    write_protected: vec![
                        // Shared with the Cursor IDE, which loads and runs
                        // both outside the jail.
                        state_dir.join("extensions"),
                        state_dir.join("argv.json"),
                    ],
                    state: vec![state_dir, home.join(".config/cursor")],
                    install: vec![home.join(".local/share/cursor-agent")],
                    hidden: Vec::new(),
                }
            }
            Agent::Opencode => {
                // opencode follows the XDG base directories: login and
                // sessions under data, config and plugins under config.
                let xdg = |key: &str, default: &str| {
                    env(key)
                        .filter(|value| Path::new(value).is_absolute())
                        .map(PathBuf::from)
                        .unwrap_or_else(|| home.join(default))
                        .join("opencode")
                };
                // `~/.opencode` is a global config directory too, and
                // holds the binary when installed with the install script.
                let dot_dir = home.join(".opencode");
                let config = xdg("XDG_CONFIG_HOME", ".config");
                // The password of the host's background server, which
                // runs tools outside the jail.
                let hidden = vec![config.join("service.json")];
                let mut state = vec![
                    xdg("XDG_DATA_HOME", ".local/share"),
                    config,
                    xdg("XDG_STATE_HOME", ".local/state"),
                    xdg("XDG_CACHE_HOME", ".cache"),
                    dot_dir.clone(),
                ];
                for key in ["OPENCODE_CONFIG_DIR", "OPENCODE_CONFIG"] {
                    if let Some(value) = env(key).filter(|v| !v.is_empty()) {
                        state.push(expand_home(&value, home));
                    }
                }
                AgentPaths {
                    state,
                    install: Vec::new(),
                    write_protected: vec![dot_dir.join("bin")],
                    hidden,
                }
            }
        }
    }

    /// Whether the agent keeps its login in the macOS Keychain. The
    /// Keychain cannot be scoped to one item, so it is only opened by
    /// default for agents that cannot start authenticated without it.
    /// Codex keeps its login in `$CODEX_HOME/auth.json`, opencode in
    /// `auth.json` in its data directory.
    pub fn uses_keychain(self) -> bool {
        match self {
            Agent::Claude | Agent::Cursor => true,
            Agent::Codex | Agent::Opencode => false,
        }
    }

    /// Hosts the agent needs for login and inference. Used as the default
    /// allow-list in filtered network mode; every entry also matches its
    /// subdomains.
    pub fn api_hosts(self) -> &'static [&'static str] {
        match self {
            Agent::Claude => &["anthropic.com", "claude.ai", "claude.com"],
            Agent::Codex => &["openai.com", "chatgpt.com"],
            Agent::Cursor => &["cursor.sh", "cursor.com", "cursorapi.com"],
            // opencode's own services and its model catalog. The model
            // provider is the user's choice; its host goes in allow_hosts.
            Agent::Opencode => &["opencode.ai", "models.dev"],
        }
    }

    /// Host variables the agent reads for credentials or routing. They are
    /// forwarded on top of the base allow-list when set.
    pub fn env_passthrough(self) -> &'static [&'static str] {
        match self {
            Agent::Claude => &[
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "ANTHROPIC_BASE_URL",
                "ANTHROPIC_MODEL",
                "ANTHROPIC_SMALL_FAST_MODEL",
                "CLAUDE_CONFIG_DIR",
                "CLAUDE_CODE_USE_BEDROCK",
                "CLAUDE_CODE_USE_VERTEX",
                "AWS_REGION",
                "CLOUD_ML_REGION",
                "ANTHROPIC_VERTEX_PROJECT_ID",
            ],
            Agent::Codex => {
                &["OPENAI_API_KEY", "OPENAI_BASE_URL", "CODEX_HOME"]
            }
            Agent::Cursor => &["CURSOR_API_KEY"],
            Agent::Opencode => &[
                "OPENCODE_API_KEY",
                "OPENCODE_CONFIG",
                "OPENCODE_CONFIG_DIR",
                "OPENCODE_CONFIG_CONTENT",
                "ANTHROPIC_API_KEY",
                "OPENAI_API_KEY",
                "OPENROUTER_API_KEY",
                "GEMINI_API_KEY",
                "GOOGLE_GENERATIVE_AI_API_KEY",
            ],
        }
    }

    /// A warning when the agent is routed to a cloud provider whose
    /// credentials the jail hides. They are never shared implicitly: the
    /// same credentials reach everything else in the account.
    pub fn provider_warning(
        self,
        env: &dyn Fn(&str) -> Option<String>,
        settings: &Settings,
    ) -> Option<String> {
        if self != Agent::Claude || settings.inherit_env.unwrap_or(false) {
            return None;
        }
        let enabled = |key: &str| {
            env(key).is_some_and(|v| !matches!(v.as_str(), "" | "0" | "false"))
        };
        let shared = |prefix: &str, dir: &str| {
            settings.env.iter().any(|entry| entry.starts_with(prefix))
                || settings
                    .ro
                    .iter()
                    .chain(&settings.rw)
                    .any(|path| path.contains(dir))
        };
        if enabled("CLAUDE_CODE_USE_BEDROCK") && !shared("AWS_", ".aws") {
            return Some(
                "CLAUDE_CODE_USE_BEDROCK is set, but the jail hides AWS \
                 credentials (~/.aws and AWS_* variables), so Claude cannot \
                 authenticate. Share them explicitly, for example \
                 --env AWS_PROFILE --ro ~/.aws"
                    .into(),
            );
        }
        if enabled("CLAUDE_CODE_USE_VERTEX") && !shared("GOOGLE_", "gcloud") {
            return Some(
                "CLAUDE_CODE_USE_VERTEX is set, but the jail hides Google \
                 Cloud credentials (~/.config/gcloud and GOOGLE_* \
                 variables), so Claude cannot authenticate. Share them \
                 explicitly, for example --ro ~/.config/gcloud"
                    .into(),
            );
        }
        None
    }

    /// Fixed variables set for the agent inside the jail.
    pub fn env_overrides(self) -> &'static [(&'static str, &'static str)] {
        match self {
            // The installation is read-only inside the jail, so in-jail
            // self-updates can only fail. Update from the host instead.
            Agent::Claude => &[("DISABLE_AUTOUPDATER", "1")],
            Agent::Opencode => &[("OPENCODE_DISABLE_AUTOUPDATE", "1")],
            Agent::Codex | Agent::Cursor => &[],
        }
    }

    /// The program to execute when the user typed `program`. `cursor` is
    /// the IDE launcher on macOS, so it maps to the Cursor CLI agent.
    pub fn resolve_program(
        self,
        program: &str,
        on_path: &dyn Fn(&str) -> bool,
    ) -> String {
        if self == Agent::Cursor && program == "cursor" {
            return ["cursor-agent", "agent"]
                .into_iter()
                .find(|candidate| on_path(candidate))
                .unwrap_or("cursor-agent")
                .to_string();
        }
        program.to_string()
    }

    /// Whether this invocation needs a private opencode server.
    ///
    /// opencode is a client of a server it reaches over loopback TCP. By
    /// default that is a background service shared by every session of the
    /// user: one started outside the jail would run the agent's tools
    /// unjailed, and one started inside would outlive the jail and serve
    /// later sessions. The jail runs its own server on a port it picks and
    /// points the client at it, unless the user manages the server.
    pub fn wants_private_server(self, args: &[String]) -> bool {
        const SERVER_FLAGS: &[&str] = &["--server", "--standalone"];
        const NO_SERVER: &[&str] =
            &["--help", "-h", "--version", "-v", "--completions"];
        const NO_SERVER_COMMANDS: &[&str] =
            &["serve", "service", "upgrade", "update", "uninstall"];
        if self != Agent::Opencode {
            return false;
        }
        fn flag(arg: &str) -> &str {
            arg.split('=').next().unwrap_or_default()
        }
        let command = args.iter().find(|arg| !arg.starts_with('-'));
        !args.iter().any(|arg| {
            SERVER_FLAGS.contains(&flag(arg)) || NO_SERVER.contains(&flag(arg))
        }) && !command.is_some_and(|c| NO_SERVER_COMMANDS.contains(&c.as_str()))
    }

    /// A warning when the user's own server choice cannot work in the jail.
    pub fn server_warning(self, args: &[String]) -> Option<String> {
        (self == Agent::Opencode
            && args.iter().any(|arg| arg == "--standalone"))
        .then(|| {
            "opencode --standalone listens on a random loopback port, which \
             the jail keeps closed. Drop the flag (the jail already runs a \
             private server) or pass --localhost."
                .into()
        })
    }

    /// Arguments prepended to the agent's own so it does not try to start a
    /// nested Seatbelt sandbox, which macOS refuses inside `sandbox-exec`.
    pub fn nested_sandbox_args(self, args: &[String]) -> Vec<String> {
        match self {
            Agent::Codex if !codex_sandbox_chosen(args) => vec![
                "-c".to_string(),
                "sandbox_mode=\"danger-full-access\"".to_string(),
            ],
            _ => Vec::new(),
        }
    }

    /// A warning when the agent's own arguments ask for a nested sandbox.
    pub fn nested_sandbox_warning(self, args: &[String]) -> Option<String> {
        if self != Agent::Codex {
            return None;
        }
        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            let mode = match arg.as_str() {
                "--full-auto" => Some("workspace-write"),
                "-s" | "--sandbox" => iter.peek().map(|s| s.as_str()),
                other => other.strip_prefix("--sandbox="),
            };
            if let Some(mode) = mode
                && mode != "danger-full-access"
            {
                return Some(format!(
                    "codex sandbox mode '{mode}' starts a nested Seatbelt \
                     sandbox, which macOS refuses inside the jail; commands \
                     will fail. Use --sandbox danger-full-access (the jail \
                     is the sandbox)."
                ));
            }
        }
        None
    }
}

fn codex_sandbox_chosen(args: &[String]) -> bool {
    args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "-s" | "--sandbox"
                | "--full-auto"
                | "--yolo"
                | "--dangerously-bypass-approvals-and-sandbox"
        ) || arg.starts_with("--sandbox=")
            || arg.contains("sandbox_mode=")
    })
}

pub fn expand_home(value: &str, home: &Path) -> PathBuf {
    if value == "~" {
        home.to_path_buf()
    } else if let Some(rest) = value.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn detects_agents_by_basename() {
        assert_eq!(Agent::detect("claude"), Some(Agent::Claude));
        assert_eq!(
            Agent::detect("/Users/me/.local/bin/claude"),
            Some(Agent::Claude)
        );
        assert_eq!(Agent::detect("codex"), Some(Agent::Codex));
        assert_eq!(Agent::detect("cursor-agent"), Some(Agent::Cursor));
        assert_eq!(Agent::detect("cursor"), Some(Agent::Cursor));
        assert_eq!(Agent::detect("agent"), Some(Agent::Cursor));
        assert_eq!(Agent::detect("opencode"), Some(Agent::Opencode));
        assert_eq!(Agent::detect("bash"), None);
    }

    #[test]
    fn claude_state_honors_config_dir_override() {
        let home = Path::new("/Users/me");
        let paths = Agent::Claude.paths(home, &no_env);
        assert_eq!(
            paths.state,
            vec![home.join(".claude"), home.join(".claude.json")]
        );
        let env = |key: &str| {
            (key == "CLAUDE_CONFIG_DIR").then(|| "~/alt-claude".to_string())
        };
        let paths = Agent::Claude.paths(home, &env);
        assert_eq!(paths.state[0], home.join("alt-claude"));
    }

    #[test]
    fn codex_state_honors_codex_home() {
        let home = Path::new("/Users/me");
        let env =
            |key: &str| (key == "CODEX_HOME").then(|| "/opt/codex".to_string());
        let paths = Agent::Codex.paths(home, &env);
        assert_eq!(paths.state, vec![PathBuf::from("/opt/codex")]);
    }

    #[test]
    fn opencode_state_follows_the_xdg_directories() {
        let home = Path::new("/Users/me");
        let paths = Agent::Opencode.paths(home, &no_env);
        for dir in [
            ".local/share/opencode",
            ".config/opencode",
            ".local/state/opencode",
            ".cache/opencode",
            ".opencode",
        ] {
            assert!(paths.state.contains(&home.join(dir)), "{dir}");
        }
        assert_eq!(paths.write_protected, vec![home.join(".opencode/bin")]);

        let env = |key: &str| match key {
            "XDG_DATA_HOME" => Some("/data".to_string()),
            "XDG_CONFIG_HOME" => Some("relative".to_string()),
            "OPENCODE_CONFIG_DIR" => Some("~/oc".to_string()),
            _ => None,
        };
        let paths = Agent::Opencode.paths(home, &env);
        assert!(paths.state.contains(&PathBuf::from("/data/opencode")));
        assert!(paths.state.contains(&home.join(".config/opencode")));
        assert!(paths.state.contains(&home.join("oc")));
    }

    #[test]
    fn opencode_gets_a_private_server_unless_the_user_manages_one() {
        let wants = |args: &[&str]| {
            let args: Vec<String> =
                args.iter().map(|s| s.to_string()).collect();
            Agent::Opencode.wants_private_server(&args)
        };
        assert!(wants(&[]));
        assert!(wants(&["run", "serve the docs"]));
        assert!(wants(&["--auto", "models"]));
        for direct in [
            &["serve", "--port", "4096"][..],
            &["service", "status"],
            &["--version"],
            &["--server", "http://127.0.0.1:4096"],
            &["--server=http://127.0.0.1:4096", "run", "hi"],
            &["--standalone"],
        ] {
            assert!(!wants(direct), "{direct:?}");
        }
        assert!(!Agent::Claude.wants_private_server(&[]));
        let standalone = vec!["--standalone".to_string()];
        assert!(Agent::Opencode.server_warning(&standalone).is_some());
        assert!(Agent::Opencode.server_warning(&[]).is_none());
        let paths = Agent::Opencode.paths(Path::new("/Users/me"), &no_env);
        assert_eq!(
            paths.hidden,
            vec![PathBuf::from("/Users/me/.config/opencode/service.json")]
        );
    }

    #[test]
    fn cursor_protects_ide_executed_state() {
        let home = Path::new("/Users/me");
        let paths = Agent::Cursor.paths(home, &no_env);
        assert!(paths.state.contains(&home.join(".cursor")));
        assert!(
            paths
                .write_protected
                .contains(&home.join(".cursor/extensions"))
        );
    }

    #[test]
    fn cloud_provider_routing_warns_until_credentials_are_shared() {
        let bedrock = |key: &str| {
            (key == "CLAUDE_CODE_USE_BEDROCK").then(|| "1".to_string())
        };
        let hidden = Settings::default();
        let warning = Agent::Claude.provider_warning(&bedrock, &hidden);
        assert!(warning.unwrap().contains("~/.aws"));
        assert!(Agent::Codex.provider_warning(&bedrock, &hidden).is_none());
        assert!(Agent::Claude.provider_warning(&no_env, &hidden).is_none());
        for shared in [
            Settings {
                env: vec!["AWS_PROFILE".into()],
                ..Settings::default()
            },
            Settings {
                ro: vec!["~/.aws".into()],
                ..Settings::default()
            },
            Settings {
                inherit_env: Some(true),
                ..Settings::default()
            },
        ] {
            assert!(
                Agent::Claude.provider_warning(&bedrock, &shared).is_none()
            );
        }
        let vertex = |key: &str| {
            (key == "CLAUDE_CODE_USE_VERTEX").then(|| "1".to_string())
        };
        let warning = Agent::Claude.provider_warning(&vertex, &hidden);
        assert!(warning.unwrap().contains("gcloud"));
    }

    #[test]
    fn cursor_resolves_to_cli_agent() {
        let only_agent = |name: &str| name == "agent";
        assert_eq!(
            Agent::Cursor.resolve_program("cursor", &only_agent),
            "agent"
        );
        let both = |_: &str| true;
        assert_eq!(
            Agent::Cursor.resolve_program("cursor", &both),
            "cursor-agent"
        );
        assert_eq!(
            Agent::Cursor.resolve_program("/x/cursor-agent", &both),
            "/x/cursor-agent"
        );
    }

    #[test]
    fn codex_gets_nested_sandbox_bypass_unless_user_chose() {
        let args: Vec<String> = vec!["exec".into(), "hi".into()];
        assert_eq!(
            Agent::Codex.nested_sandbox_args(&args),
            vec!["-c", "sandbox_mode=\"danger-full-access\""]
        );
        for chosen in [
            vec!["--sandbox", "read-only"],
            vec!["--yolo"],
            vec!["-c", "sandbox_mode=read-only"],
        ] {
            let args: Vec<String> =
                chosen.into_iter().map(String::from).collect();
            assert!(Agent::Codex.nested_sandbox_args(&args).is_empty());
        }
        assert!(Agent::Claude.nested_sandbox_args(&args).is_empty());
    }

    #[test]
    fn codex_warns_about_nested_sandbox_modes() {
        let warn = |args: &[&str]| {
            let args: Vec<String> =
                args.iter().map(|s| s.to_string()).collect();
            Agent::Codex.nested_sandbox_warning(&args)
        };
        assert!(warn(&["--full-auto"]).is_some());
        assert!(warn(&["-s", "workspace-write"]).is_some());
        assert!(warn(&["--sandbox=read-only"]).is_some());
        assert!(warn(&["--sandbox", "danger-full-access"]).is_none());
        assert!(warn(&["exec", "hello"]).is_none());
    }
}
