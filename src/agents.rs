//! Built-in knowledge about the agents this jail is tuned for.
//!
//! Each agent contributes the host state it needs to start logged in
//! (read-write), its self-managed installation (read-only, so an agent
//! cannot replace the binary the host will run next), the API hosts used by
//! filtered egress, and a handful of environment tweaks.

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Codex,
    Cursor,
}

/// Host paths an agent needs, resolved against a home directory and the
/// agent's own environment overrides (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AgentPaths {
    /// Credential/config/session state, mounted read-write.
    pub state: Vec<PathBuf>,
    /// Self-managed installations, readable but never writable.
    pub install: Vec<PathBuf>,
    /// Paths inside `state` that stay write-protected because the host
    /// executes them outside the jail.
    pub write_protected: Vec<PathBuf>,
}

impl Agent {
    pub const ALL: [Agent; 3] = [Agent::Claude, Agent::Codex, Agent::Cursor];

    /// Identify the agent from the program name (basename of argv\[0\]).
    pub fn detect(program: &str) -> Option<Agent> {
        let name = Path::new(program).file_name()?.to_str()?;
        match name {
            "claude" => Some(Agent::Claude),
            "codex" => Some(Agent::Codex),
            "cursor-agent" | "cursor" | "agent" => Some(Agent::Cursor),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
            Agent::Cursor => "cursor",
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
                write_protected: Vec::new(),
            },
            Agent::Codex => AgentPaths {
                state: vec![from_env("CODEX_HOME", ".codex")],
                install: Vec::new(),
                write_protected: Vec::new(),
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
                }
            }
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
            ],
            Agent::Codex => {
                &["OPENAI_API_KEY", "OPENAI_BASE_URL", "CODEX_HOME"]
            }
            Agent::Cursor => &["CURSOR_API_KEY"],
        }
    }

    /// Fixed variables set for the agent inside the jail.
    pub fn env_overrides(self) -> &'static [(&'static str, &'static str)] {
        match self {
            // The installation is read-only inside the jail, so in-jail
            // self-updates can only fail. Update from the host instead.
            Agent::Claude => &[("DISABLE_AUTOUPDATER", "1")],
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
