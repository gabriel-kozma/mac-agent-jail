# mac-agent-jail

Run AI coding agents — **Claude Code**, **Codex**, and the **Cursor CLI** — in a
macOS Seatbelt (`sandbox-exec`) sandbox, with the **macOS Keychain allowed** so
agents that keep their login there start authenticated.

Based on [akitaonrails/ai-jail](https://github.com/akitaonrails/ai-jail), but
macOS-only and tuned for these three agents. Like ai-jail, it is an
accident-prevention layer for "YOLO mode" agents, not a boundary against
hostile code (use a VM for that).

> Status: the generated profile runs under real `sandbox-exec` on macOS.
> `cargo test` includes live checks for the filesystem policy, Keychain,
> network modes, and the `/usr/bin/git` toolchain shims.

## Usage

```bash
cargo build --release
cp target/release/mac-agent-jail ~/.local/bin/

cd ~/Projects/my-app
mac-agent-jail claude --dangerously-skip-permissions
mac-agent-jail codex
mac-agent-jail cursor            # runs cursor-agent
mac-agent-jail                   # sandboxed zsh
mac-agent-jail --dry-run claude  # print the Seatbelt profile
```

## Default policy

- **Project directory** (cwd): read-write. Refuses to run with `$HOME` or `/`
  as the project.
- **Rest of `$HOME`**: hidden, except:
  - the agent's own state, read-write (`~/.claude` + `~/.claude.json`,
    `~/.codex`, `~/.cursor` + `~/.config/cursor`)
  - toolchains read-only (nvm, mise, rustup, pyenv, `~/.local/bin`, PATH
    entries under home, `.gitconfig`, ...)
  - package caches read-write (`~/.npm`, `~/.cache`, `~/Library/Caches`, ...)
- **Keychain: allowed** — the Security/securityd/CoreAuthentication/ctkd Mach
  services, `~/Library/Keychains` and the MDS databases. Use `--no-keychain` to
  turn it off.
- **Always hidden**: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`,
  `~/.config/gh`, `.netrc`, `.npmrc`, Mail and Messages, and similar stores.
  In the project, `.env` and `.env.*` are hidden (`.env.example` and similar
  stay visible).
- **Write-protected**: `.git/hooks`, `.git/config`, agent installs,
  `~/.cursor/extensions`. These run on the host later, so writing them would
  let the agent act outside the jail.
- **Network**: `full` (any IP), but Unix sockets such as tmux, docker and
  ssh-agent stay closed. Use `--allow-host` / `--net filtered` for an
  allow-list through a local CONNECT proxy, or `--net none`.
- **Terminal**: the agent runs on its own PTY, so `TIOCSTI` cannot inject
  keystrokes into your shell.
- **Environment**: a minimal allowlist plus the agent's own API key variables.
- **Nested sandboxes**: Codex gets `-c sandbox_mode="danger-full-access"`,
  because macOS refuses a nested `sandbox-exec` and the jail is already the
  sandbox.

Opt-ins: `--ssh-agent`, `--open-urls`, `--clipboard`, `--unix-socket`,
`--git-hooks`, `--ro/--rw/--deny`. See `mac-agent-jail --help`.

Config: `~/.config/mac-agent-jail/config.toml` (`--print-config` prints an
example), with `[agents.claude|codex|cursor]` tables. There is no
per-project config, so a repository cannot widen its own sandbox.

## Development

```bash
cargo test && cargo clippy && cargo fmt --check
```

## License

GPL-3.0-only (derived from ai-jail).
