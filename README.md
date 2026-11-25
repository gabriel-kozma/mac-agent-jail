# mac-agent-jail

Run AI coding agents — **Claude Code**, **Codex**, the **Cursor CLI**, and
**opencode** — in a
macOS Seatbelt (`sandbox-exec`) sandbox that confines them to the current
project directory. The **macOS Keychain is opened only for the agents that
keep their login there** (Claude Code, Cursor), so they start authenticated.

Based on [akitaonrails/ai-jail](https://github.com/akitaonrails/ai-jail), but
macOS-only and tuned for these four agents. Like ai-jail, it is an
accident-prevention layer for "YOLO mode" agents, not a boundary against
hostile code (use a VM for that).

> Status: the generated profile runs under real `sandbox-exec` on macOS.
> `cargo test` includes live checks for the filesystem policy, git
> protections, Keychain, network modes, and the `/usr/bin/git` toolchain
> shims.

## Usage

```bash
cargo build --release
cp target/release/mac-agent-jail ~/.local/bin/

cd ~/Projects/my-app
mac-agent-jail claude --dangerously-skip-permissions
mac-agent-jail codex
mac-agent-jail cursor            # runs cursor-agent
mac-agent-jail opencode
mac-agent-jail                   # sandboxed zsh
mac-agent-jail --dry-run claude  # print the Seatbelt profile
```

## Default policy

- **Project directory** (cwd): read-write. Refuses to run with `$HOME` or `/`
  as the project.
- **Rest of `$HOME`**: hidden, except:
  - the agent's own state, read-write (`~/.claude` + `~/.claude.json`,
    `~/.codex`, `~/.cursor` + `~/.config/cursor`, opencode's
    `~/.local/share/opencode`, `~/.config/opencode`,
    `~/.local/state/opencode` and `~/.opencode`)
  - toolchains read-only (nvm, mise, rustup, pyenv, `~/.local/bin`, PATH
    entries under home, `.gitconfig`, ...)
  - package caches read-write (`~/.npm`, `~/.cache`, and the developer
    tools' own directories in `~/Library/Caches`, such as `pip`, `Yarn`,
    `go-build`; add others with `--rw`)
- **Outside `$HOME`**: the system, Homebrew, and the toolchain parts of
  `/Library` (`Developer`, `Frameworks`, `Java`, ...) are read-only. Other
  applications' data in `/Library`, `/Applications`, other users, other
  volumes and `/tmp` are hidden.
- **Keychain**: allowed for `claude` and `cursor`, blocked for `codex` and
  `opencode` (their login is a file in their own directory) and for any
  other command. Seatbelt cannot
  scope the Keychain to one item, so an agent with access can ask for any
  credential saved on this Mac. `--keychain` / `--no-keychain` override the
  default.
- **Always hidden**: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`,
  `.netrc`, `.npmrc`, `~/.config/git/credentials`,
  `~/.gradle/gradle.properties`, Mail and Messages, and similar stores.
  In the project, `.env` and `.env.*` are hidden (`.env.example` and similar
  stay visible).
- **Write-protected**: `.git/hooks` and `.git/config` of every repository
  in the project (also in submodules and, for a linked worktree, in the
  shared git dir), Gradle init scripts,
  agent installs, `~/.cursor/extensions`, the config file in use. These run
  on the host later, so writing them would let the agent act outside the
  jail.
- **No new repositories**: a `.git` cannot be created, replaced, renamed or
  removed anywhere in the project, so `git clone`, `git init`,
  `git worktree add` and `git submodule update` fail inside it. A cloned
  repository's hooks would be the agent's to write. Run those on the host,
  or pass `--git-hooks` to lift all git protections. Commits, branches,
  fetch and push in existing repositories work.
  - Package managers still check out git dependencies: repositories can be
    created under `.build/checkouts` (SwiftPM), `Carthage/Checkouts`,
    `vendor`, `node_modules`, `deps`, `_build`, `_deps`, `subprojects`,
    `.terraform/modules`, `.venv/src`, `venv/src` and `.pio/libdeps`, at
    any depth. Seatbelt matches paths, not programs, so an agent can clone
    into those directories too; treat them as build output.
- **Network**: `full` (any public or LAN IP), but loopback and Unix sockets
  such as tmux, docker and ssh-agent stay closed, because they reach host
  processes outside the jail. `--local-port 3000` opens one loopback port
  (for example a dev server the agent starts and then tests) and
  `--localhost` opens all of it. Servers inside the jail can still listen
  in full mode; in the other modes they can on a listed port.
  Use `--allow-host` / `--net filtered` for an allow-list through a local
  CONNECT proxy, or `--net none`.
- **Terminal**: the agent runs on its own PTY, so `TIOCSTI` cannot inject
  keystrokes into your shell. The last row of your terminal is kept for a
  footer naming the jail and its version, the project and what is open
  (network, Keychain),
  so you can see at a glance that a session is confined. The agent gets a
  terminal one row shorter. Turn it off with `--no-footer` or
  `footer = false`.
- **Environment**: a minimal allowlist plus the agent's own API key variables.
  Cloud credentials are never shared implicitly: with
  `CLAUDE_CODE_USE_BEDROCK` or `CLAUDE_CODE_USE_VERTEX` the jail warns and
  you share them yourself, for example `--env AWS_PROFILE --ro ~/.aws`.
- **opencode**: its client normally talks to a background server shared by
  all your sessions, which would run the agent's tools outside the jail.
  The jail starts a private `opencode serve` on a loopback port it picks,
  with a one-time password, and points the client at it; the server ends
  with the session. The password of your host server
  (`~/.config/opencode/service.json`) is hidden. In filtered mode only
  `opencode.ai` and `models.dev` are allowed by default: add your model
  provider with `--allow-host`.
- **Nested sandboxes**: Codex gets `-c sandbox_mode="danger-full-access"`,
  because macOS refuses a nested `sandbox-exec` and the jail is already the
  sandbox.

The GitHub CLI config (`~/.config/gh`) is shared read-only by default, so
the agent can run `gh` as you: open pull requests, read issues, and anything
else your token allows. gh keeps the token itself in the Keychain, so it
also needs `--keychain` for agents that do not have it by default. `--no-gh`
or `gh = false` hides the config again.

The pasteboard is open by default, so copying from the agent and pasting
text or images into it work. The agent can therefore read whatever you last
copied; `--no-clipboard` or `clipboard = false` closes it.

Opt-ins: `--keychain`, `--local-port`, `--localhost`, `--ssh-agent`,
`--open-urls`, `--unix-socket`, `--git-hooks`, `--ro/--rw/--deny`. See `mac-agent-jail --help`.

Config: `~/.config/mac-agent-jail/config.toml`, then `.mac-agent-jail.toml`
at the root of the project, then the command line. Both files take
`[agents.claude|codex|cursor|opencode]` tables; `--print-config` prints an
example.

The first run in a project creates `.mac-agent-jail.toml` with every
setting commented out. A repository can ship that file, so it cannot widen
its own sandbox: once the file sets anything, the jail refuses to start
until you approve it with `mac-agent-jail --trust-config`, and again after
every change. Approvals are kept under `~/.config/mac-agent-jail/trusted`.
The agent can read the file but not change it.

## Development

```bash
cargo test && cargo clippy && cargo fmt --check
```

## License

GPL-3.0-only (derived from ai-jail).
