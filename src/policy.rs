//! Resolve settings, the agent, and host facts into a Seatbelt [`Profile`].

use std::path::{Path, PathBuf};

use crate::{
    agents::{Agent, expand_home},
    config::{NetworkMode, Settings},
    profile::{
        Loopback, Match, Network, Profile, Rule, Section, ancestors,
        regex_escape,
    },
};

/// System locations needed to exec ordinary programs and load their
/// libraries. `/opt` holds Homebrew on Apple Silicon; `/usr/local` (under
/// `/usr`) holds it on Intel.
///
/// `/private/var/select` has to be readable, not merely `stat`-able.
/// `/usr/bin/git` and `/usr/bin/python3` are shims that `readlink`
/// `developer_dir` there, and Seatbelt treats `readlink` as
/// `file-read-data`. Metadata on the parent denies them with
/// "unable to read data link".
///
/// Only the toolchain parts of `/Library` are listed. The rest holds other
/// applications' data, preferences and logs. The Xcode preferences record
/// the accepted license; without them every `/usr/bin` shim refuses to run.
const SYSTEM_READ: &[&str] = &[
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/private/etc",
    "/Library/Apple",
    "/Library/Developer",
    "/Library/Fonts",
    "/Library/Frameworks",
    "/Library/Java",
    "/Library/Perl",
    "/Library/Preferences/com.apple.dt.Xcode.plist",
    "/Library/Python",
    "/Library/Ruby",
    "/Library/Tcl",
    "/Library/TeX",
    "/opt",
    "/dev",
    "/nix",
    "/private/var/db/timezone",
    "/private/var/select",
    "/private/var/db/xcode_select_link",
];

/// Nodes on the way to allowed paths that are symlinks or roots on macOS
/// (`/etc`, `/var`, `/tmp` all point into `/private`).
const SYSTEM_METADATA: &[&str] = &[
    "/private",
    "/etc",
    "/var",
    "/tmp",
    "/private/tmp",
    "/private/var",
    "/private/var/select",
    "/private/var/run",
];

/// Language toolchains and developer config under `$HOME`, read-only.
const HOME_TOOLCHAINS: &[&str] = &[
    ".local/bin",
    ".local/share/mise",
    ".config/mise",
    ".nvm",
    ".volta",
    ".fnm",
    "Library/Application Support/fnm",
    ".cargo/bin",
    ".rustup",
    ".pyenv",
    ".rbenv",
    ".asdf",
    ".bun/bin",
    ".deno",
    "go/bin",
    ".sdkman",
    ".jenv",
    ".gem",
    "Library/Python",
    ".terminfo",
    ".tool-versions",
    ".gitconfig",
    ".gitignore",
    ".gitignore_global",
    ".gitattributes",
    ".config/git",
    ".editorconfig",
];

/// Package-manager caches under `$HOME`, read-write. `~/Library/Caches` is
/// shared with every application on the Mac (browsers, mail, system
/// agents), so only the developer tools' own directories are listed.
const HOME_CACHES: &[&str] = &[
    ".cache",
    ".npm",
    "Library/Caches/claude-cli-nodejs",
    "Library/Caches/CocoaPods",
    "Library/Caches/Coursier",
    "Library/Caches/Cypress",
    "Library/Caches/deno",
    "Library/Caches/electron",
    "Library/Caches/electron-builder",
    "Library/Caches/go-build",
    "Library/Caches/golangci-lint",
    "Library/Caches/Homebrew",
    "Library/Caches/Mozilla.sccache",
    "Library/Caches/ms-playwright",
    "Library/Caches/node-gyp",
    "Library/Caches/org.swift.swiftpm",
    "Library/Caches/pip",
    "Library/Caches/pnpm",
    "Library/Caches/pypoetry",
    "Library/Caches/ruff",
    "Library/Caches/turbo",
    "Library/Caches/typescript",
    "Library/Caches/uv",
    "Library/Caches/Yarn",
    ".cargo/registry",
    ".cargo/git",
    "go/pkg/mod",
    ".bun/install/cache",
    "Library/pnpm",
    ".local/share/pnpm",
    ".yarn",
    ".gradle",
    ".m2/repository",
    ".node-gyp",
    ".local/state/mise",
];

/// Files under the read-write caches that the host runs outside the jail
/// (Gradle applies init scripts to every build), write-protected.
const HOME_WRITE_PROTECTED: &[&str] = &[
    ".gradle/init.d",
    ".gradle/init.gradle",
    ".gradle/init.gradle.kts",
];

/// Credential stores that stay hidden even when a broader grant (for
/// example `--ro ~`) would otherwise cover them.
const HOME_SECRETS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".azure",
    ".oci",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".config/git/credentials",
    ".gradle/gradle.properties",
    ".cache/huggingface/token",
    ".password-store",
    ".config/gh",
    ".config/gcloud",
    ".config/op",
    ".gem/credentials",
    "Library/Mail",
    "Library/Messages",
    "Library/Safari",
    "Library/Cookies",
    "Library/Application Support/1Password",
];

const BASE_MACH_SERVICES: &[&str] = &[
    "com.apple.cfprefsd.daemon",
    "com.apple.cfprefsd.agent",
    "com.apple.system.logger",
    "com.apple.logd",
    "com.apple.system.notification_center",
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership",
    "com.apple.system.DirectoryService.libinfo_v1",
    "com.apple.SystemConfiguration.configd",
    "com.apple.SystemConfiguration.DNSConfiguration",
    "com.apple.trustd",
    "com.apple.trustd.agent",
    // /usr/bin/curl verifies chains /etc/ssl/cert.pem cannot through it.
    "com.apple.TrustEvaluationAgent",
    "com.apple.ocspd",
    "com.apple.FSEvents",
];

/// Services behind the Security framework's Keychain APIs: the legacy file
/// keychain (SecurityServer), the data-protection keychain (securityd.xpc),
/// Touch ID / password prompts (CoreAuthentication), and smart-card tokens
/// that every item query enumerates (ctkd).
const KEYCHAIN_MACH_SERVICES: &[&str] = &[
    "com.apple.SecurityServer",
    "com.apple.securityd",
    "com.apple.securityd.xpc",
    "com.apple.security.agent",
    "com.apple.CoreAuthentication.daemon",
    "com.apple.CoreAuthentication.agent",
    "com.apple.ctkd.token-client",
    "com.apple.ctkd.slot-client",
];

const OPEN_URL_MACH_SERVICES: &[&str] = &[
    "com.apple.coreservices.launchservicesd",
    "com.apple.lsd.mapdb",
    "com.apple.lsd.modifydb",
    "com.apple.lsd.open",
];

const CLIPBOARD_MACH_SERVICES: &[&str] = &["com.apple.pasteboard.1"];

/// Directories (as regex fragments, at any depth in the project) where
/// package managers check out git dependencies: SwiftPM, Carthage,
/// Composer/Bundler/Go, npm, Mix, rebar3, CMake FetchContent, Meson,
/// Terraform, pip editable installs and PlatformIO. Repositories may be
/// created there. Their content is build input the agent can already
/// rewrite, like `node_modules`, so their hooks are not protected either.
const GIT_DEPENDENCY_DIRS: &[&str] = &[
    "\\.build/checkouts",
    "Carthage/Checkouts",
    "vendor",
    "node_modules",
    "deps",
    "_build",
    "_deps",
    "subprojects",
    "\\.terraform/modules",
    "\\.venv/src",
    "venv/src",
    "\\.pio/libdeps",
];

const DEFAULT_HIDE: &[&str] = &[".env", ".env.*"];
const DEFAULT_HIDE_EXCEPTIONS: &[&str] =
    &["example", "sample", "template", "dist"];

/// Host facts the policy depends on. Collected once in `main.rs` and
/// injected so the resolver is testable.
#[derive(Clone, Debug, Default)]
pub struct Host {
    /// Canonical home directory.
    pub home: PathBuf,
    pub uid: u32,
    /// Darwin's per-user cache directory (`getconf DARWIN_USER_CACHE_DIR`).
    pub user_cache_dir: Option<PathBuf>,
    /// This run's private TMPDIR.
    pub session_dir: Option<PathBuf>,
    /// The canonical path of this executable (Codex `ps` shim target).
    pub exe: Option<PathBuf>,
    /// The config file this run loaded, wherever it lives.
    pub config: Option<PathBuf>,
    /// Host PATH entries.
    pub path: Vec<PathBuf>,
    pub ssh_auth_sock: Option<PathBuf>,
}

#[derive(Clone)]
pub struct Request<'a> {
    pub settings: &'a Settings,
    pub agent: Option<Agent>,
    /// Canonical project directory.
    pub project: &'a Path,
    /// The program as found on PATH (not canonicalized).
    pub program: Option<&'a Path>,
    pub tty: Option<&'a Path>,
    pub proxy_port: Option<u16>,
    pub env: &'a dyn Fn(&str) -> Option<String>,
}

/// Keychain access: an explicit setting, or on for the agents that keep
/// their login there.
pub fn keychain_enabled(settings: &Settings, agent: Option<Agent>) -> bool {
    settings
        .keychain
        .unwrap_or(agent.is_some_and(Agent::uses_keychain))
}

/// Non-fatal problems found while resolving, reported to the user.
pub type Warnings = Vec<String>;

pub fn resolve(
    host: &Host,
    req: &Request,
) -> Result<(Profile, Warnings), String> {
    let mut warnings = Warnings::new();
    let s = req.settings;
    let home = &host.home;
    let keychain = keychain_enabled(s, req.agent);
    let agent_state = s.agent_state.unwrap_or(true);

    let network = match s.network_mode()? {
        NetworkMode::Full => Network::Full,
        NetworkMode::None => Network::None,
        NetworkMode::Filtered => match req.proxy_port {
            Some(port) => Network::Proxy(port),
            None => Network::None,
        },
    };

    let loopback = if s.localhost.unwrap_or(false) {
        Loopback::All
    } else {
        Loopback::Ports(s.local_ports.clone())
    };

    // --- reads -----------------------------------------------------------
    let mut system = Vec::new();
    for path in SYSTEM_READ {
        let path = Path::new(path);
        if exists(path) {
            // A symlink contributes its own node, so readlink works, and
            // the canonical target. rule_for alone would drop the link.
            system.extend(read_rules(path));
        }
    }
    if let Some(bundle) = xcode_bundle() {
        system.push(Rule::subpath(bundle));
    }

    let mut toolchains = Vec::new();
    for rel in HOME_TOOLCHAINS {
        let path = home.join(rel);
        if exists(&path) {
            toolchains.push(rule_for(&path));
        }
    }
    let mut path_entries = Vec::new();
    for entry in &host.path {
        if entry.is_absolute()
            && entry.starts_with(home)
            && canon(entry) != *home
            && entry.is_dir()
            && !is_secret(home, entry)
        {
            path_entries.push(rule_for(entry));
        }
    }
    let mut program = Vec::new();
    if let Some(raw) = req.program {
        // The resolved binary's directory (an npm package, a versioned
        // install) and the PATH entry itself, which may be a symlink node.
        if let Ok(real) = std::fs::canonicalize(raw)
            && let Some(dir) = real.parent()
            && !is_secret(home, dir)
            && dir != home
        {
            program.push(Rule::subpath(dir));
        }
        if let (Some(parent), Some(name)) = (raw.parent(), raw.file_name()) {
            program.push(Rule::literal(canon(parent).join(name)));
        }
    }

    let agent_paths = match req.agent {
        Some(agent) => agent.paths(home, req.env),
        None => Default::default(),
    };
    let mut install = Vec::new();
    for path in &agent_paths.install {
        if exists(path) {
            install.push(rule_for(path));
        }
    }

    let mut extra_ro = Vec::new();
    for raw in &s.ro {
        let path = expand_home(raw, home);
        if exists(&path) {
            extra_ro.push(rule_for(&path));
        } else {
            warnings.push(format!("--ro {raw}: path does not exist, skipped"));
        }
    }

    let mut ssh = Vec::new();
    let mut unix_sockets = Vec::new();
    let mut unix_binds = Vec::new();
    if s.ssh_agent.unwrap_or(false) {
        match &host.ssh_auth_sock {
            Some(sock) if exists(sock) => {
                unix_sockets.push(Rule::literal(canon(sock)));
            }
            _ => warnings.push(
                "--ssh-agent: SSH_AUTH_SOCK is not set or missing".into(),
            ),
        }
        for rel in [".ssh/known_hosts", ".ssh/config"] {
            let path = home.join(rel);
            if path.is_file() {
                ssh.push(Rule::literal(canon(&path)));
            }
        }
    }
    for raw in &s.unix_sockets {
        let path = expand_home(raw, home);
        if exists(&path) {
            unix_sockets.push(Rule::literal(canon(&path)));
        } else {
            warnings.push(format!(
                "--unix-socket {raw}: socket does not exist, skipped"
            ));
        }
    }

    // --- writes ----------------------------------------------------------
    let mut project_rules = vec![Rule::subpath(req.project)];
    let worktree = linked_worktree(req.project);
    if let Some(worktree) = &worktree {
        project_rules.push(Rule::subpath(&worktree.common));
    }

    let mut state = Vec::new();
    if agent_state {
        for path in &agent_paths.state {
            if exists(path) {
                state.push(rule_for(path));
            }
        }
        if req.agent == Some(Agent::Claude) {
            // ~/.claude.json is replaced atomically through siblings such
            // as .claude.json.tmp.<pid>.<ts>, .lock and .backup.
            state.push(Rule::Regex(format!(
                "^{}/\\.claude\\.json(\\.[^/]*)?$",
                regex_escape(&home.to_string_lossy())
            )));
        }
    }

    let mut caches = Vec::new();
    for rel in HOME_CACHES {
        let path = home.join(rel);
        // Tools create their cache on first use, and the parent
        // directories are not writable.
        if exists(&path)
            || matches!(*rel, ".cache" | ".npm")
            || rel.starts_with("Library/Caches/")
        {
            caches.push(Rule::subpath(canon(&path)));
        }
    }

    if let Some(cache) = &host.user_cache_dir {
        // clang and swiftc keep their module cache here, whatever TMPDIR is.
        caches.push(Rule::subpath(cache.join("clang")));
    }

    let mut temp = Vec::new();
    if let Some(dir) = &host.session_dir {
        temp.push(Rule::subpath(dir));
        // /usr/bin/git, clang and python3 go through xcrun, which ignores
        // TMPDIR and creates xcrun_db-* in the per-user temporary directory
        // (confstr DARWIN_USER_TEMP_DIR). The rest of that directory stays
        // hidden: other processes keep files there.
        if let Some(root) = dir.parent().filter(|p| p.parent().is_some()) {
            temp.push(Rule::Regex(format!(
                "^{}/xcrun_db(-[^/]*)?$",
                regex_escape(&root.to_string_lossy())
            )));
        }
    }
    match req.agent {
        Some(Agent::Claude) => {
            // Claude Code ignores TMPDIR for its per-user scratch dir and
            // drops /tmp/claude-<hex>-cwd markers on every Bash call.
            temp.push(Rule::subpath(format!(
                "/private/tmp/claude-{}",
                host.uid
            )));
            temp.push(Rule::Regex(
                "^/private/tmp/claude-[0-9a-f]+-cwd$".into(),
            ));
        }
        Some(Agent::Codex) => {
            let daemon = format!("/private/tmp/codex-daemon-{}", host.uid);
            temp.push(Rule::subpath(&daemon));
            let socket = Rule::Regex(format!("^{daemon}/[0-9a-f]+$"));
            unix_sockets.push(socket.clone());
            unix_binds.push(socket);
            if agent_state && let Some(codex_home) = agent_paths.state.first() {
                let control = codex_home
                    .join("app-server-control/app-server-control.sock");
                unix_sockets.push(Rule::literal(canon(&control)));
            }
        }
        _ => {}
    }

    let mut keychain_rw = Vec::new();
    let mut keychain_ro = Vec::new();
    if keychain {
        keychain_rw.push(Rule::subpath(canon(&home.join("Library/Keychains"))));
        if let Some(cache) = &host.user_cache_dir {
            keychain_rw.push(Rule::subpath(cache.join("mds")));
        }
        keychain_ro.push(Rule::subpath("/private/var/db/mds"));
        // The System keychain is on the default search list.
        keychain_ro.push(Rule::subpath("/Library/Keychains"));
        let prefs = home.join("Library/Preferences/com.apple.security.plist");
        keychain_ro.push(Rule::literal(canon(&prefs)));
    }

    let mut extra_rw = Vec::new();
    for raw in &s.rw {
        let path = expand_home(raw, home);
        if exists(&path) {
            extra_rw.push(rule_for(&path));
        } else {
            warnings.push(format!("--rw {raw}: path does not exist, skipped"));
        }
    }

    // --- denies ----------------------------------------------------------
    let explicit_grants: Vec<PathBuf> = extra_ro
        .iter()
        .chain(&extra_rw)
        .chain(&ssh)
        .filter_map(rule_path)
        .collect();
    let mut secrets = Vec::new();
    for rel in HOME_SECRETS {
        let path = canon(&home.join(rel));
        // An explicit grant of the secret itself (or something inside it)
        // is the user's call; a broader grant such as `--ro ~` is not.
        let granted = explicit_grants.iter().any(|g| g.starts_with(&path));
        if exists(&path) && !granted {
            secrets.push(rule_for(&path));
        }
    }

    for path in &agent_paths.hidden {
        secrets.push(Rule::literal(canon(path)));
    }

    let mut hidden_project = Vec::new();
    let mut reallow = Vec::new();
    let project_re = regex_escape(&req.project.to_string_lossy());
    let mut patterns: Vec<&str> = s.hide.iter().map(String::as_str).collect();
    if s.default_hide.unwrap_or(true) {
        patterns.extend(DEFAULT_HIDE);
        reallow.push(Rule::Regex(format!(
            "^{project_re}/(.*/)?\\.env\\.({})$",
            DEFAULT_HIDE_EXCEPTIONS.join("|")
        )));
    }
    for pattern in patterns {
        hidden_project
            .push(Rule::Regex(project_glob_regex(&project_re, pattern)?));
    }

    let mut denied = Vec::new();
    for raw in &s.deny {
        let path = expand_home(raw, home);
        let path = if path.is_absolute() {
            path
        } else {
            req.project.join(path)
        };
        denied.push(match std::fs::canonicalize(&path) {
            Ok(real) => rule_for(&real),
            Err(_) => Rule::subpath(path),
        });
    }

    let mut protected = Vec::new();
    let mut dependencies = Vec::new();
    for path in &agent_paths.write_protected {
        protected.push(Rule::subpath(canon(path)));
    }
    for path in &agent_paths.install {
        protected.push(Rule::subpath(canon(path)));
    }
    if !s.git_hooks.unwrap_or(false) {
        // Hooks and config (core.hooksPath, core.fsmonitor) run on the host
        // the next time git is used outside the jail. That holds for every
        // repository in the project, not only the top one, and for the git
        // dirs outside it that the project points to: a symlinked `.git`
        // and a linked worktree's shared dir. Submodules and worktrees keep
        // their own hooks and config below those.
        let mut git_dirs = vec![format!("{project_re}/(.*/)?\\.git")];
        let real = canon(&req.project.join(".git"));
        if !real.starts_with(req.project) {
            git_dirs.push(regex_escape(&real.to_string_lossy()));
        }
        if let Some(worktree) = &worktree {
            git_dirs.push(regex_escape(&worktree.common.to_string_lossy()));
            protected.push(Rule::literal(worktree.gitdir.join("commondir")));
        }
        for dir_re in &git_dirs {
            protected.push(Rule::Regex(format!(
                "^{dir_re}/\
                 (hooks(/.*)?|config(\\.worktree)?(\\.lock)?|commondir)$"
            )));
            protected.push(Rule::Regex(format!(
                "^{dir_re}/(modules|worktrees)/.+/\
                 (hooks(/.*)?|config(\\.worktree)?(\\.lock)?)$"
            )));
        }
        // A `.git` node says where hooks and config are read from, so none
        // may be created, replaced, renamed or removed. `git init`,
        // `git clone` and `git worktree add` inside the project belong on
        // the host; a cloned repository's hooks would be the agent's.
        protected.push(Rule::Regex(format!("^{project_re}/(.*/)?\\.git$")));
        // Seatbelt sees paths, not which program runs git, so package
        // managers are told apart by where they put their checkouts.
        dependencies.push(Rule::Regex(format!(
            "^{project_re}/(.*/)?({})/(.*/)?\\.git(/.*)?$",
            GIT_DEPENDENCY_DIRS.join("|")
        )));
    }
    for rel in HOME_WRITE_PROTECTED {
        protected.push(Rule::subpath(canon(&home.join(rel))));
    }
    protected.push(Rule::subpath(canon(&home.join(".config/mac-agent-jail"))));
    if let Some(config) = &host.config {
        protected.push(Rule::literal(config));
    }

    // --- mach, shm -------------------------------------------------------
    let mut mach = vec![Section {
        comment: "System services every program needs",
        items: strings(BASE_MACH_SERVICES),
    }];
    if keychain {
        mach.push(Section {
            comment: "macOS Keychain",
            items: strings(KEYCHAIN_MACH_SERVICES),
        });
    }
    if s.open_urls.unwrap_or(false) {
        mach.push(Section {
            comment: "Open URLs in the host browser (--open-urls)",
            items: strings(OPEN_URL_MACH_SERVICES),
        });
    }
    if s.clipboard.unwrap_or(false) {
        mach.push(Section {
            comment: "Pasteboard (--clipboard)",
            items: strings(CLIPBOARD_MACH_SERVICES),
        });
    }
    if !s.mach_services.is_empty() {
        mach.push(Section {
            comment: "User-listed services (--mach-service)",
            items: s.mach_services.clone(),
        });
    }

    let mut shm = vec![
        (format!("apple.cfprefs.{}v1", host.uid), true),
        ("apple.cfprefs.daemonv1".to_string(), true),
        ("apple.shm.notification_center".to_string(), false),
    ];
    if keychain {
        shm.push(("com.apple.AppleDatabaseChanged".to_string(), true));
    }

    let mut exe = Vec::new();
    if req.agent == Some(Agent::Codex)
        && let Some(path) = &host.exe
    {
        exe.push(Rule::literal(path));
    }

    let read = vec![
        section("System", system),
        section("Developer toolchains (read-only)", toolchains),
        section("PATH entries under $HOME", path_entries),
        section("The command being run", program),
        section("Agent installation (read-only)", install),
        section("Keychain support files", keychain_ro),
        section("SSH client config (--ssh-agent)", ssh),
        section("Codex ps helper", exe),
        section("Extra read-only paths (--ro)", extra_ro),
    ];
    let write = vec![
        section("Project", project_rules),
        section("Agent state", state),
        section("Package caches", caches),
        section("Temporary files", temp),
        section("Keychain databases", keychain_rw),
        section("Extra read-write paths (--rw)", extra_rw),
    ];

    let metadata = {
        let paths: Vec<PathBuf> = read
            .iter()
            .chain(&write)
            .flat_map(|section| section.items.iter())
            .filter_map(rule_path)
            .collect();
        let mut dirs = ancestors(paths.iter().map(PathBuf::as_path));
        let fixed = SYSTEM_METADATA.iter().map(PathBuf::from);
        for path in fixed.chain([home.clone()]) {
            if !dirs.contains(&path) {
                dirs.push(path);
            }
        }
        dirs
    };

    let profile = Profile {
        mach_services: mach,
        shm,
        network,
        loopback,
        unix_sockets,
        unix_binds,
        tty: req.tty.map(Path::to_path_buf),
        metadata,
        read,
        write,
        hidden: vec![
            section("Credential stores", secrets),
            section("Hidden project files (--hide)", hidden_project),
        ],
        reallow,
        denied: vec![section("Denied paths (--deny)", denied)],
        deny_write: vec![section("Write-protected paths", protected)],
        reallow_write: vec![section(
            "Git checkouts made by package managers",
            dependencies,
        )],
    };
    Ok((profile, warnings))
}

/// Translate a hide pattern into a regex anchored at the project. A pattern
/// without '/' matches a basename at any depth; one with '/' is relative to
/// the project root. `*` and `?` do not cross '/'.
fn project_glob_regex(
    project_re: &str,
    pattern: &str,
) -> Result<String, String> {
    let trimmed = pattern.trim_start_matches("./").trim_end_matches('/');
    if trimmed.is_empty() || trimmed.split('/').any(|part| part == "..") {
        return Err(format!("invalid hide pattern '{pattern}'"));
    }
    let mut body = String::new();
    for c in trimmed.chars() {
        match c {
            '*' => body.push_str("[^/]*"),
            '?' => body.push_str("[^/]"),
            other => body.push_str(&regex_escape(&other.to_string())),
        }
    }
    let anchored = trimmed.contains('/') || pattern.starts_with("./");
    let prefix = if anchored { "" } else { "(.*/)?" };
    Ok(format!("^{project_re}/{prefix}{body}(/.*)?$"))
}

/// The git dirs of a linked worktree.
struct Worktree {
    /// The per-worktree git dir (`.git/worktrees/<name>`).
    gitdir: PathBuf,
    /// The shared git dir, two levels up. Commits write its object store.
    common: PathBuf,
}

/// The git dirs behind the project, when its `.git` is a `gitdir:` file.
fn linked_worktree(project: &Path) -> Option<Worktree> {
    let dotgit = project.join(".git");
    if !dotgit.is_file() {
        return None;
    }
    let text = std::fs::read_to_string(&dotgit).ok()?;
    let gitdir = text.lines().find_map(|l| l.strip_prefix("gitdir: "))?;
    let gitdir = project.join(gitdir.trim());
    let gitdir = std::fs::canonicalize(gitdir).ok()?;
    let common = gitdir.parent()?.parent()?.to_path_buf();
    (common.file_name()? == ".git" || common.join("objects").is_dir())
        .then_some(Worktree { gitdir, common })
}

fn xcode_bundle() -> Option<PathBuf> {
    let target =
        std::fs::read_link("/private/var/db/xcode_select_link").ok()?;
    let mut bundle = PathBuf::new();
    for part in target.components() {
        bundle.push(part);
        if part.as_os_str().to_string_lossy().ends_with(".app") {
            return Some(canon(&bundle));
        }
    }
    None
}

fn is_secret(home: &Path, path: &Path) -> bool {
    HOME_SECRETS
        .iter()
        .any(|rel| path.starts_with(home.join(rel)))
}

fn section(comment: &'static str, items: Vec<Rule>) -> Section<Rule> {
    let mut unique: Vec<Rule> = Vec::with_capacity(items.len());
    for item in items {
        if !unique.contains(&item) {
            unique.push(item);
        }
    }
    Section {
        comment,
        items: unique,
    }
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn rule_path(rule: &Rule) -> Option<PathBuf> {
    match rule {
        Rule::Path(path, _) => Some(path.clone()),
        Rule::Regex(_) => None,
    }
}

fn exists(path: &Path) -> bool {
    path.symlink_metadata().is_ok()
}

pub fn canon(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// A canonical rule: files are literals, directories (and paths that do not
/// exist yet) are subpaths. Symlinks are followed; use [`read_rules`] when
/// the link node itself must stay readable.
fn rule_for(path: &Path) -> Rule {
    let real = canon(path);
    let kind = if real.is_file() {
        Match::Literal
    } else {
        Match::Subpath
    };
    Rule::Path(real, kind)
}

/// Read rules for `path`. A symlink contributes its own node (so `readlink`
/// works) and the canonical target.
fn read_rules(path: &Path) -> Vec<Rule> {
    let mut rules = Vec::new();
    if let Some(link) = symlink_node(path) {
        rules.push(Rule::literal(link));
    }
    rules.push(rule_for(path));
    rules
}

/// The symlink itself, with its parent canonicalized, when `path` is a symlink.
fn symlink_node(path: &Path) -> Option<PathBuf> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_symlink() {
        return None;
    }
    let name = path.file_name()?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty())?;
    Some(canon(parent).join(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::render;

    struct Fixture {
        root: PathBuf,
        host: Host,
        project: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Fixture {
            let root = std::env::temp_dir()
                .join(format!("maj-policy-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let home = root.join("home");
            let project = home.join("work/app");
            for dir in [
                "work/app/.git",
                ".claude",
                ".codex",
                ".cursor/extensions",
                ".ssh",
                ".aws",
                ".config/git",
                ".gradle",
                ".local/bin",
                ".local/share/claude/versions",
                ".nvm/versions/node/v22/bin",
                "Library/Keychains",
            ] {
                std::fs::create_dir_all(home.join(dir)).unwrap();
            }
            std::fs::write(home.join(".claude.json"), "{}").unwrap();
            std::fs::write(home.join(".gitconfig"), "").unwrap();
            std::fs::write(home.join(".ssh/id_ed25519"), "key").unwrap();
            std::fs::write(home.join(".ssh/known_hosts"), "").unwrap();
            std::fs::write(home.join(".config/git/credentials"), "").unwrap();
            std::fs::write(home.join(".gradle/gradle.properties"), "").unwrap();
            let home = std::fs::canonicalize(home).unwrap();
            let project = std::fs::canonicalize(project).unwrap();
            let host = Host {
                home: home.clone(),
                uid: 501,
                user_cache_dir: Some(PathBuf::from("/private/var/folders/x/C")),
                session_dir: Some(PathBuf::from("/private/var/folders/x/T/s")),
                exe: Some(PathBuf::from("/opt/maj/bin/mac-agent-jail")),
                config: Some(PathBuf::from("/opt/maj/etc/jail.toml")),
                path: vec![
                    home.join(".nvm/versions/node/v22/bin"),
                    home.join(".ssh"),
                    PathBuf::from("/opt/homebrew/bin"),
                ],
                ssh_auth_sock: None,
            };
            Fixture {
                root,
                host,
                project,
            }
        }

        fn render(&self, settings: &Settings, agent: Option<Agent>) -> String {
            let no_env = |_: &str| None;
            let req = Request {
                settings,
                agent,
                project: &self.project,
                program: None,
                tty: None,
                proxy_port: Some(18080),
                env: &no_env,
            };
            let (profile, _) = resolve(&self.host, &req).unwrap();
            render(&profile)
        }

        fn home(&self) -> String {
            self.host.home.to_string_lossy().into_owned()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn keychain_is_allowed_by_default_only_for_agents_that_log_in_there() {
        let fx = Fixture::new("keychain");
        for agent in [None, Some(Agent::Codex)] {
            let text = fx.render(&Settings::default(), agent);
            assert!(!text.contains("SecurityServer"), "{agent:?}");
            assert!(!text.contains("Library/Keychains"), "{agent:?}");
        }
        let on = Settings {
            keychain: Some(true),
            ..Settings::default()
        };
        for (settings, agent) in [
            (Settings::default(), Some(Agent::Claude)),
            (Settings::default(), Some(Agent::Cursor)),
            (on.clone(), Some(Agent::Codex)),
            (on, None),
        ] {
            let text = fx.render(&settings, agent);
            for service in [
                "com.apple.SecurityServer",
                "com.apple.securityd.xpc",
                "com.apple.CoreAuthentication.daemon",
            ] {
                assert!(
                    text.contains(&format!("(global-name \"{service}\")")),
                    "{agent:?} missing {service}"
                );
            }
            assert!(text.contains(&format!(
                "(allow file-read* file-write* (subpath \"{}/Library/Keychains\"))",
                fx.home()
            )));
            assert!(text.contains("com.apple.AppleDatabaseChanged"));
            assert!(
                text.contains("(subpath \"/private/var/folders/x/C/mds\")")
            );
        }
    }

    #[test]
    fn no_keychain_removes_every_keychain_grant() {
        let fx = Fixture::new("no-keychain");
        let settings = Settings {
            keychain: Some(false),
            ..Settings::default()
        };
        let text = fx.render(&settings, Some(Agent::Claude));
        assert!(!text.contains("SecurityServer"));
        assert!(!text.contains("securityd"));
        assert!(!text.contains("Library/Keychains"));
        assert!(!text.contains("AppleDatabaseChanged"));
        assert!(!text.contains("/mds"));
    }

    #[test]
    fn project_is_writable_and_home_is_not() {
        let fx = Fixture::new("project");
        let text = fx.render(&Settings::default(), None);
        assert!(text.contains(&format!(
            "(allow file-read* file-write* (subpath \"{}\"))",
            fx.project.display()
        )));
        assert!(!text.contains(&format!("(subpath \"{}\")", fx.home())));
        assert!(text.contains(&format!(
            "(allow file-read-metadata (literal \"{}\"))",
            fx.home()
        )));
    }

    #[test]
    fn agent_state_is_per_agent() {
        let fx = Fixture::new("state");
        let home = fx.home();
        let claude = fx.render(&Settings::default(), Some(Agent::Claude));
        assert!(claude.contains(&format!(
            "(allow file-read* file-write* (subpath \"{home}/.claude\"))"
        )));
        assert!(claude.contains("\\.claude\\.json(\\.[^/]*)?$"));
        assert!(claude.contains("/private/tmp/claude-501"));
        assert!(claude.contains(&format!(
            "(allow file-read* (subpath \"{home}/.local/share/claude\"))"
        )));
        assert!(claude.contains(&format!(
            "(deny file-write* (subpath \"{home}/.local/share/claude\"))"
        )));
        assert!(!claude.contains(&format!("{home}/.codex")));

        let codex = fx.render(&Settings::default(), Some(Agent::Codex));
        assert!(codex.contains(&format!(
            "(allow file-read* file-write* (subpath \"{home}/.codex\"))"
        )));
        assert!(codex.contains("codex-daemon-501"));
        assert!(codex.contains("(literal \"/opt/maj/bin/mac-agent-jail\")"));
        assert!(!codex.contains(&format!("{home}/.claude\"")));

        let cursor = fx.render(&Settings::default(), Some(Agent::Cursor));
        assert!(cursor.contains(&format!(
            "(allow file-read* file-write* (subpath \"{home}/.cursor\"))"
        )));
        assert!(cursor.contains(&format!(
            "(deny file-write* (subpath \"{home}/.cursor/extensions\"))"
        )));

        let none = Settings {
            agent_state: Some(false),
            ..Settings::default()
        };
        let text = fx.render(&none, Some(Agent::Claude));
        assert!(!text.contains(&format!("{home}/.claude\"")));
    }

    #[test]
    fn secrets_stay_hidden_and_path_entries_inside_them_are_skipped() {
        let fx = Fixture::new("secrets");
        let home = fx.home();
        let text = fx.render(&Settings::default(), None);
        assert!(text.contains(&format!(
            "(deny file-read* file-write* (subpath \"{home}/.ssh\"))"
        )));
        assert!(!text.contains(&format!(
            "(allow file-read* (subpath \"{home}/.ssh\"))"
        )));
        assert!(text.contains(&format!(
            "(allow file-read* (subpath \"{home}/.nvm/versions/node/v22/bin\"))"
        )));
        assert!(text.contains(&format!(
            "(allow file-read* (literal \"{home}/.gitconfig\"))"
        )));
    }

    #[test]
    fn credentials_inside_granted_directories_stay_hidden() {
        let fx = Fixture::new("nested-secrets");
        let home = fx.home();
        let text = fx.render(&Settings::default(), None);
        for (grant, secret) in [
            (
                format!("(allow file-read* (subpath \"{home}/.config/git\"))"),
                format!("(literal \"{home}/.config/git/credentials\"))"),
            ),
            (
                format!(
                    "(allow file-read* file-write* (subpath \"{home}/.gradle\"))"
                ),
                format!("(literal \"{home}/.gradle/gradle.properties\"))"),
            ),
        ] {
            let allow = text.find(&grant);
            let deny =
                text.find(&format!("(deny file-read* file-write* {secret}"));
            assert!(allow.is_some() && allow < deny, "{secret}\n{text}");
        }
        assert!(text.contains(&format!(
            "(deny file-write* (subpath \"{home}/.gradle/init.d\"))"
        )));
    }

    #[test]
    fn a_path_entry_equal_to_home_is_skipped() {
        let mut fx = Fixture::new("path-home");
        fx.host.path.push(fx.host.home.clone());
        let text = fx.render(&Settings::default(), None);
        assert!(!text.contains(&format!("(subpath \"{}\")", fx.home())));
    }

    #[test]
    fn broad_grants_do_not_expose_secrets_but_explicit_ones_do() {
        let fx = Fixture::new("grants");
        let home = fx.home();
        let broad = Settings {
            ro: vec!["~".into()],
            ..Settings::default()
        };
        let text = fx.render(&broad, None);
        let allow =
            text.find(&format!("(allow file-read* (subpath \"{home}\"))"));
        let deny = text.find(&format!(
            "(deny file-read* file-write* (subpath \"{home}/.aws\"))"
        ));
        assert!(allow.is_some() && deny.is_some() && allow < deny);

        let explicit = Settings {
            ro: vec!["~/.aws".into()],
            ..Settings::default()
        };
        let text = fx.render(&explicit, None);
        assert!(!text.contains(&format!(
            "(deny file-read* file-write* (subpath \"{home}/.aws\"))"
        )));
    }

    #[test]
    fn ssh_agent_exposes_known_hosts_but_not_keys() {
        let mut fx = Fixture::new("ssh");
        let sock = fx.root.join("agent.sock");
        std::fs::write(&sock, "").unwrap();
        fx.host.ssh_auth_sock = Some(sock.clone());
        let settings = Settings {
            ssh_agent: Some(true),
            ..Settings::default()
        };
        let text = fx.render(&settings, None);
        let home = fx.home();
        assert!(text.contains(&format!(
            "(allow file-read* (literal \"{home}/.ssh/known_hosts\"))"
        )));
        assert!(!text.contains(&format!("(subpath \"{home}/.ssh\")")));
        assert!(!text.contains("id_ed25519"));
        assert!(text.contains(&format!(
            "(path-literal \"{}\")",
            canon(&sock).display()
        )));
    }

    #[test]
    fn env_files_are_hidden_with_example_exceptions() {
        let fx = Fixture::new("hide");
        let project = regex_escape(&fx.project.to_string_lossy());
        let text = fx.render(&Settings::default(), None);
        assert!(text.contains(&format!(
            "(deny file-read* file-write* (regex #\"^{project}/(.*/)?\\.env(/.*)?$\"))"
        )));
        assert!(text.contains(&format!(
            "(regex #\"^{project}/(.*/)?\\.env\\.[^/]*(/.*)?$\")"
        )));
        let hidden = text.find("Hidden project files").unwrap();
        let reallow = text
            .find("\\.env\\.(example|sample|template|dist)$")
            .unwrap();
        assert!(hidden < reallow);

        let off = Settings {
            default_hide: Some(false),
            hide: vec!["config/*.pem".into()],
            ..Settings::default()
        };
        let text = fx.render(&off, None);
        assert!(!text.contains("\\.env"));
        assert!(
            text.contains(&format!("^{project}/config/[^/]*\\.pem(/.*)?$"))
        );
    }

    #[test]
    fn user_denies_render_after_env_exceptions() {
        let fx = Fixture::new("deny");
        let settings = Settings {
            deny: vec!["secrets".into()],
            ..Settings::default()
        };
        let text = fx.render(&settings, None);
        let reallow = text.find("Exceptions to the denies").unwrap();
        let deny = text
            .find(&format!(
                "(deny file-read* file-write* (subpath \"{}/secrets\"))",
                fx.project.display()
            ))
            .unwrap();
        assert!(reallow < deny);
    }

    #[test]
    fn git_hooks_are_write_protected_by_default() {
        let fx = Fixture::new("git");
        let project = regex_escape(&fx.project.to_string_lossy());
        let text = fx.render(&Settings::default(), None);
        assert!(text.contains(&format!(
            "(deny file-write* (regex #\"^{project}/(.*/)?\\.git/\
             (hooks(/.*)?|config(\\.worktree)?(\\.lock)?|commondir)$\"))"
        )));
        assert!(text.contains(&format!(
            "^{project}/(.*/)?\\.git/(modules|worktrees)/.+/(hooks(/.*)?|"
        )));
        let allowed = Settings {
            git_hooks: Some(true),
            ..Settings::default()
        };
        assert!(!fx.render(&allowed, None).contains("hooks"));
    }

    #[test]
    fn git_dirs_cannot_be_created_or_replaced_anywhere_in_the_project() {
        let fx = Fixture::new("git-nodes");
        let node = format!(
            "(deny file-write* (regex #\"^{}/(.*/)?\\.git$\"))",
            regex_escape(&fx.project.to_string_lossy())
        );
        let text = fx.render(&Settings::default(), None);
        let deny = text.find(&node);
        let dependencies = text.find(&format!(
            "(allow file-write* (regex #\"^{}/(.*/)?(\\.build/checkouts|",
            regex_escape(&fx.project.to_string_lossy())
        ));
        assert!(deny.is_some() && deny < dependencies, "{text}");
        assert!(text.contains("|vendor|node_modules|"));
        let allowed = Settings {
            git_hooks: Some(true),
            ..Settings::default()
        };
        let text = fx.render(&allowed, None);
        assert!(!text.contains(&node));
        assert!(!text.contains("allow file-write* (regex"));
    }

    #[test]
    fn network_modes() {
        let fx = Fixture::new("net");
        let full = fx.render(&Settings::default(), None);
        assert!(full.contains("(remote ip \"*:*\")"));
        let filtered = Settings {
            allow_hosts: vec!["github.com".into()],
            ..Settings::default()
        };
        let text = fx.render(&filtered, None);
        assert!(text.contains("(remote ip \"localhost:18080\")"));
        assert!(!text.contains("*:*"));
        let none = Settings {
            network: Some("none".into()),
            ..Settings::default()
        };
        let text = fx.render(&none, None);
        assert!(!text.contains("(remote ip"));
    }

    #[test]
    fn loopback_is_closed_in_full_mode_unless_opened() {
        let fx = Fixture::new("loopback");
        let deny = "(deny network-outbound (remote ip \"localhost:*\"))";
        let text = fx.render(&Settings::default(), None);
        assert!(text.contains(deny));
        let ports = Settings {
            local_ports: vec![3000],
            ..Settings::default()
        };
        let text = fx.render(&ports, None);
        assert!(text.contains(deny));
        assert!(text.contains("(remote ip \"localhost:3000\")"));
        let open = Settings {
            localhost: Some(true),
            ..Settings::default()
        };
        assert!(!fx.render(&open, None).contains("localhost"));

        let filtered = Settings {
            allow_hosts: vec!["github.com".into()],
            local_ports: vec![3000],
            ..Settings::default()
        };
        let text = fx.render(&filtered, None);
        assert!(text.contains(
            "(allow network-bind network-inbound (local ip \"localhost:3000\"))"
        ));
    }

    #[test]
    fn opencode_shares_its_state_but_not_the_host_server_password() {
        let fx = Fixture::new("opencode");
        let home = fx.home();
        for dir in
            [".local/share/opencode", ".config/opencode", ".opencode/bin"]
        {
            std::fs::create_dir_all(fx.host.home.join(dir)).unwrap();
        }
        let text = fx.render(&Settings::default(), Some(Agent::Opencode));
        for dir in [".local/share/opencode", ".config/opencode", ".opencode"] {
            assert!(
                text.contains(&format!(
                    "(allow file-read* file-write* (subpath \"{home}/{dir}\"))"
                )),
                "{dir}"
            );
        }
        let allow =
            text.find(&format!("(subpath \"{home}/.config/opencode\")"));
        let deny = text.find(&format!(
            "(deny file-read* file-write* \
             (literal \"{home}/.config/opencode/service.json\"))"
        ));
        assert!(allow.is_some() && allow < deny, "{text}");
        assert!(text.contains(&format!(
            "(deny file-write* (subpath \"{home}/.opencode/bin\"))"
        )));
        assert!(!text.contains("SecurityServer"));
        assert!(!text.contains(&format!("{home}/.claude\"")));
    }

    #[test]
    fn caches_and_system_library_are_narrowed_to_developer_tools() {
        let fx = Fixture::new("narrow");
        let home = fx.home();
        let text = fx.render(&Settings::default(), None);
        assert!(text.contains(&format!(
            "(allow file-read* file-write* (subpath \"{home}/Library/Caches/pip\"))"
        )));
        assert!(
            !text.contains(&format!("(subpath \"{home}/Library/Caches\")"))
        );
        assert!(!text.contains("(subpath \"/Library\")"));
        assert!(!text.contains("/Library/Application Support"));
    }

    #[test]
    fn the_loaded_config_file_is_write_protected() {
        let fx = Fixture::new("config");
        let text = fx.render(&Settings::default(), None);
        assert!(text.contains(
            "(deny file-write* (literal \"/opt/maj/etc/jail.toml\"))"
        ));
    }

    #[test]
    fn optional_capabilities_are_off_by_default() {
        let fx = Fixture::new("caps");
        let text = fx.render(&Settings::default(), None);
        assert!(!text.contains("launchservicesd"));
        assert!(!text.contains("pasteboard"));
        let on = Settings {
            open_urls: Some(true),
            clipboard: Some(true),
            mach_services: vec!["com.example.helper".into()],
            ..Settings::default()
        };
        let text = fx.render(&on, None);
        assert!(text.contains("com.apple.coreservices.launchservicesd"));
        assert!(text.contains("com.apple.pasteboard.1"));
        assert!(text.contains("com.example.helper"));
    }

    #[test]
    fn hide_pattern_validation() {
        assert!(project_glob_regex("/p", "../x").is_err());
        assert!(project_glob_regex("/p", "").is_err());
        assert_eq!(
            project_glob_regex("/p", "*.pem").unwrap(),
            "^/p/(.*/)?[^/]*\\.pem(/.*)?$"
        );
        assert_eq!(
            project_glob_regex("/p", "./secrets/").unwrap(),
            "^/p/secrets(/.*)?$"
        );
    }

    #[test]
    fn xcrun_cache_is_writable_next_to_the_session_dir() {
        let fx = Fixture::new("xcrun");
        let text = fx.render(&Settings::default(), None);
        assert!(text.contains(
            "(allow file-read* file-write* (regex #\"^/private/var/folders/x/T/xcrun_db(-[^/]*)?$\"))"
        ));
        assert!(!text.contains("(subpath \"/private/var/folders/x/T\")"));
    }

    #[test]
    fn read_rules_keep_a_symlink_and_its_target() {
        let root = std::env::temp_dir()
            .join(format!("maj-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("real")).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(root.join("real"), &link).unwrap();
        let rules = read_rules(&link);
        assert!(rules.contains(&Rule::literal(canon(&root).join("link"))));
        assert!(rules.contains(&Rule::subpath(canon(&root.join("real")))));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn linked_worktree_metadata_is_writable() {
        let fx = Fixture::new("worktree");
        let main = fx.root.join("main");
        let gitdir = main.join(".git/worktrees/feature");
        std::fs::create_dir_all(&gitdir).unwrap();
        let wt = fx.root.join("feature");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(
            wt.join(".git"),
            format!("gitdir: {}\n", gitdir.display()),
        )
        .unwrap();
        let worktree = linked_worktree(&wt).unwrap();
        assert_eq!(worktree.common, canon(&main.join(".git")));
        assert_eq!(worktree.gitdir, canon(&gitdir));
        assert!(linked_worktree(&fx.project).is_none());
    }

    #[test]
    fn linked_worktree_protects_the_shared_hooks_and_config() {
        let mut fx = Fixture::new("worktree-hooks");
        let main = fx.root.join("main");
        let gitdir = main.join(".git/worktrees/feature");
        std::fs::create_dir_all(&gitdir).unwrap();
        let wt = fx.root.join("feature");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(
            wt.join(".git"),
            format!("gitdir: {}\n", gitdir.display()),
        )
        .unwrap();
        fx.project = canon(&wt);
        let common = canon(&main.join(".git"));
        let text = fx.render(&Settings::default(), None);
        let allow = text.find(&format!(
            "(allow file-read* file-write* (subpath \"{}\"))",
            common.display()
        ));
        let deny = text.find(&format!(
            "(deny file-write* (regex #\"^{}/(hooks(/.*)?|",
            regex_escape(&common.to_string_lossy())
        ));
        assert!(allow.is_some() && allow < deny, "{text}");
        assert!(text.contains(&format!(
            "(deny file-write* (literal \"{}\"))",
            canon(&gitdir).join("commondir").display()
        )));
    }
}
