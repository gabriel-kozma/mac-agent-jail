use std::path::PathBuf;

use crate::config::Settings;

pub const USAGE: &str = "\
mac-agent-jail: run AI coding agents in a macOS Seatbelt sandbox

USAGE:
    mac-agent-jail [OPTIONS] [--] COMMAND [ARGS...]

    mac-agent-jail claude --dangerously-skip-permissions
    mac-agent-jail codex
    mac-agent-jail cursor          (runs the Cursor CLI, cursor-agent)
    mac-agent-jail                 (a sandboxed zsh)

The current directory is the project: readable and writable. The rest of
your home is hidden except for the agent's own state and developer
toolchains.

NETWORK:
    --net MODE              full (default), filtered, or none
    --no-network            same as --net none
    --allow-host HOST       allow HOST and its subdomains (implies filtered);
                            the agent's own API hosts are always included
    --local-port PORT       in full mode, allow connecting to a loopback
                            port (repeatable); loopback is closed otherwise
    --localhost             in full mode, allow all of loopback

FILESYSTEM:
    --ro PATH               extra read-only path (repeatable)
    --rw PATH               extra read-write path (repeatable)
    --deny PATH             deny reads and writes to PATH (repeatable)
    --hide GLOB             hide matching project files (repeatable)
    --no-default-hide       do not hide .env / .env.* in the project
    --git-hooks             allow writing .git/hooks and .git/config, and
                            creating repositories (git clone, git init)
    --project DIR           project directory (default: current directory)

HOST CAPABILITIES:
    --keychain              allow macOS Keychain access
    --no-keychain           block it (default: allowed for claude and
                            cursor, which keep their login there)
    --no-agent-state        do not share ~/.claude, ~/.codex, ~/.cursor
    --ssh-agent             forward $SSH_AUTH_SOCK
    --unix-socket PATH      allow connecting to a Unix socket (repeatable)
    --mach-service NAME     allow an extra Mach service lookup (repeatable)
    --open-urls             let the agent open URLs in the host browser
    --clipboard             allow pasteboard access

ENVIRONMENT:
    --env NAME[=VALUE]      forward or set a variable (repeatable)
    --inherit-env           pass the whole host environment (secrets too)

OTHER:
    --config PATH           config file (default:
                            ~/.config/mac-agent-jail/config.toml)
    --no-pty                do not allocate a pseudo-terminal
    -n, --dry-run           print the Seatbelt profile and command, then exit
    -v, --verbose           print the profile before launching
    --print-config          print an example config file
    -h, --help              show this help
    -V, --version           show the version
";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Cli {
    pub settings: Settings,
    pub command: Vec<String>,
    pub project: Option<PathBuf>,
    pub config: Option<PathBuf>,
    pub dry_run: bool,
    pub verbose: bool,
    pub no_pty: bool,
    pub action: Action,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub enum Action {
    #[default]
    Run,
    Help,
    Version,
    PrintConfig,
}

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Cli, String> {
    let mut cli = Cli::default();
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        if arg == "--" {
            cli.command.extend(args);
            break;
        }
        if !arg.starts_with('-') || arg == "-" {
            cli.command.push(arg);
            cli.command.extend(args);
            break;
        }

        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => {
                (flag.to_string(), Some(value.to_string()))
            }
            _ => (arg.clone(), None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            match inline.clone() {
                Some(value) => Ok(value),
                None => args
                    .next()
                    .ok_or_else(|| format!("{name} requires a value")),
            }
        };
        let s = &mut cli.settings;
        match flag.as_str() {
            "-h" | "--help" => cli.action = Action::Help,
            "-V" | "--version" => cli.action = Action::Version,
            "--print-config" => cli.action = Action::PrintConfig,
            "-n" | "--dry-run" => cli.dry_run = true,
            "-v" | "--verbose" => cli.verbose = true,
            "--no-pty" => cli.no_pty = true,
            "--project" => cli.project = Some(value(&flag)?.into()),
            "--config" => cli.config = Some(value(&flag)?.into()),
            "--net" | "--network" if flag == "--net" || inline.is_some() => {
                let mode = value(&flag)?;
                crate::config::NetworkMode::parse(&mode)?;
                s.network = Some(mode);
            }
            "--network" => s.network = Some("full".into()),
            "--no-network" => s.network = Some("none".into()),
            "--allow-host" => s.allow_hosts.push(value(&flag)?),
            "--local-port" => {
                let port = value(&flag)?;
                s.local_ports.push(
                    port.parse().map_err(|_| {
                        format!("invalid --local-port '{port}'")
                    })?,
                );
            }
            "--localhost" => s.localhost = Some(true),
            "--no-localhost" => s.localhost = Some(false),
            "--ro" => s.ro.push(value(&flag)?),
            "--rw" => s.rw.push(value(&flag)?),
            "--deny" => s.deny.push(value(&flag)?),
            "--hide" => s.hide.push(value(&flag)?),
            "--no-default-hide" => s.default_hide = Some(false),
            "--git-hooks" => s.git_hooks = Some(true),
            "--no-git-hooks" => s.git_hooks = Some(false),
            "--keychain" => s.keychain = Some(true),
            "--no-keychain" => s.keychain = Some(false),
            "--agent-state" => s.agent_state = Some(true),
            "--no-agent-state" => s.agent_state = Some(false),
            "--ssh-agent" => s.ssh_agent = Some(true),
            "--no-ssh-agent" => s.ssh_agent = Some(false),
            "--open-urls" => s.open_urls = Some(true),
            "--no-open-urls" => s.open_urls = Some(false),
            "--clipboard" => s.clipboard = Some(true),
            "--no-clipboard" => s.clipboard = Some(false),
            "--unix-socket" => s.unix_sockets.push(value(&flag)?),
            "--mach-service" => s.mach_services.push(value(&flag)?),
            "--env" => s.env.push(value(&flag)?),
            "--inherit-env" => s.inherit_env = Some(true),
            "--no-inherit-env" => s.inherit_env = Some(false),
            _ => return Err(format!("unknown option '{arg}' (see --help)")),
        }
        if inline.is_some() && !takes_value(&flag) {
            return Err(format!("option '{flag}' does not take a value"));
        }
    }
    Ok(cli)
}

fn takes_value(flag: &str) -> bool {
    matches!(
        flag,
        "--project"
            | "--config"
            | "--net"
            | "--network"
            | "--allow-host"
            | "--local-port"
            | "--ro"
            | "--rw"
            | "--deny"
            | "--hide"
            | "--unix-socket"
            | "--mach-service"
            | "--env"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<Cli, String> {
        parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn command_and_its_flags_are_passed_through() {
        let cli = parse_args(&[
            "--no-keychain",
            "claude",
            "--dangerously-skip-permissions",
            "--ro",
            "x",
        ])
        .unwrap();
        assert_eq!(cli.settings.keychain, Some(false));
        assert_eq!(
            cli.command,
            vec!["claude", "--dangerously-skip-permissions", "--ro", "x"]
        );
        assert!(cli.settings.ro.is_empty());
    }

    #[test]
    fn double_dash_ends_options() {
        let cli = parse_args(&["--", "--weird-binary", "-x"]).unwrap();
        assert_eq!(cli.command, vec!["--weird-binary", "-x"]);
    }

    #[test]
    fn values_inline_and_separate() {
        let cli = parse_args(&[
            "--net=filtered",
            "--allow-host",
            "github.com",
            "--allow-host=pypi.org",
            "--env",
            "FOO=bar",
            "--rw=~/data",
            "codex",
        ])
        .unwrap();
        assert_eq!(cli.settings.network.as_deref(), Some("filtered"));
        assert_eq!(cli.settings.allow_hosts, vec!["github.com", "pypi.org"]);
        assert_eq!(cli.settings.env, vec!["FOO=bar"]);
        assert_eq!(cli.settings.rw, vec!["~/data"]);
        assert_eq!(cli.command, vec!["codex"]);
    }

    #[test]
    fn network_shorthands() {
        assert_eq!(
            parse_args(&["--no-network"]).unwrap().settings.network,
            Some("none".into())
        );
        assert_eq!(
            parse_args(&["--network"]).unwrap().settings.network,
            Some("full".into())
        );
        assert!(parse_args(&["--net", "sometimes"]).is_err());
        let cli =
            parse_args(&["--local-port", "3000", "--local-port=5173"]).unwrap();
        assert_eq!(cli.settings.local_ports, vec![3000, 5173]);
        assert_eq!(cli.settings.localhost, None);
        assert_eq!(
            parse_args(&["--localhost"]).unwrap().settings.localhost,
            Some(true)
        );
        assert!(parse_args(&["--local-port", "http"]).is_err());
    }

    #[test]
    fn errors_are_reported() {
        assert!(parse_args(&["--bogus"]).unwrap_err().contains("--bogus"));
        assert!(parse_args(&["--ro"]).unwrap_err().contains("requires"));
        assert!(
            parse_args(&["--dry-run=yes"])
                .unwrap_err()
                .contains("does not take a value")
        );
    }

    #[test]
    fn actions() {
        assert_eq!(parse_args(&["-h"]).unwrap().action, Action::Help);
        assert_eq!(parse_args(&["-V"]).unwrap().action, Action::Version);
        assert_eq!(
            parse_args(&["--print-config"]).unwrap().action,
            Action::PrintConfig
        );
        let cli = parse_args(&["-n", "-v", "--no-pty"]).unwrap();
        assert!(cli.dry_run && cli.verbose && cli.no_pty);
        assert!(cli.command.is_empty());
    }
}
