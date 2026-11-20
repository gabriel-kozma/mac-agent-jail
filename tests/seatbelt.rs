//! Live Seatbelt checks. Compiled on macOS only; `sandbox-exec` is the
//! thing under test, so these spawn the built binary rather than rendering
//! a profile and reading it back.

#![cfg(target_os = "macos")]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn jail(project: &Path, flags: &[&str], command: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mac-agent-jail"));
    cmd.arg("--no-pty")
        .arg("--project")
        .arg(project)
        .args(flags)
        .args(command);
    cmd.output().expect("run mac-agent-jail")
}

fn show(output: &Output) -> String {
    format!(
        "status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

struct Project {
    path: PathBuf,
}

impl Project {
    fn new(name: &str) -> Project {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir()
            .join(format!("maj-live-{name}-{}-{nanos}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Project { path }
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn user_temp() -> PathBuf {
    let output = Command::new("/usr/bin/getconf")
        .arg("DARWIN_USER_TEMP_DIR")
        .output()
        .expect("getconf");
    assert!(output.status.success(), "{}", show(&output));
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

#[test]
fn filesystem_policy_holds_inside_sandbox_exec() {
    let project = Project::new("fs");
    fs::write(project.path.join(".env"), "SECRET=1\n").unwrap();
    fs::write(project.path.join(".env.example"), "EXAMPLE=1\n").unwrap();
    assert!(
        Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .current_dir(&project.path)
            .status()
            .unwrap()
            .success()
    );

    let home = std::env::var("HOME").unwrap();
    let script = r#"
        set +e
        fail() { print -r -- "FAIL $1"; exit 1; }
        print -n ok > wrote.txt || fail project-write
        [[ "$(<wrote.txt)" == ok ]] || fail project-readback
        [[ -r .env ]] && fail env-hidden
        grep -q EXAMPLE .env.example || fail env-example
        if ls "$HOME" >/dev/null 2>&1; then fail home-list; fi
        if [[ -d "$HOME/.ssh" ]] && ls "$HOME/.ssh" >/dev/null 2>&1; then
            fail ssh
        fi
        if print -n x > "$HOME/maj-jail-should-not-exist" 2>/dev/null; then
            fail home-write
        fi
        if print -n x > .git/hooks/nope 2>/dev/null; then fail hooks; fi
        if mv .git gitreal 2>/dev/null; then fail git-rename; fi
        print -n e > /dev/stderr || fail dev-stderr
        print -n o > /dev/stdout || fail dev-stdout
        if /usr/bin/git config user.email jail@example.com >/dev/null 2>&1
        then
            fail git-config
        fi
        print -n t > "${TMPDIR}/scratch" || fail tmp
    "#;
    let output = jail(&project.path, &[], &["/bin/zsh", "-c", script]);
    let leaked = PathBuf::from(&home).join("maj-jail-should-not-exist");
    let _ = fs::remove_file(&leaked);
    assert!(
        output.status.success(),
        "filesystem policy\n{}",
        show(&output)
    );
    assert!(
        !leaked.exists(),
        "jail created {} in the home directory",
        leaked.display()
    );
}

fn host_git(dir: &Path, args: &[&str]) {
    let output = Command::new("/usr/bin/git")
        .args(["-c", "user.name=maj", "-c", "user.email=maj@example.com"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git");
    assert!(output.status.success(), "git {args:?}\n{}", show(&output));
}

#[test]
fn linked_worktree_cannot_write_the_shared_hooks_or_config() {
    let root = Project::new("worktree");
    let main = root.path.join("main");
    fs::create_dir_all(&main).unwrap();
    host_git(&main, &["init", "-q"]);
    host_git(&main, &["commit", "-q", "--allow-empty", "-m", "init"]);
    host_git(&main, &["worktree", "add", "-q", "../feature"]);
    let main = fs::canonicalize(&main).unwrap();

    let script = r#"
        set +e
        fail() { print -r -- "FAIL $1"; exit 1; }
        git=(/usr/bin/git -c user.name=maj -c user.email=maj@example.com
            -c commit.gpgsign=false)
        print -n x > file.txt || fail project-write
        $git add file.txt || fail add
        $git commit -q -m jailed || fail commit
        if print -n x > "$MAIN/.git/hooks/pre-commit" 2>/dev/null; then
            fail shared-hooks
        fi
        if /usr/bin/git config core.hooksPath /tmp/hooks >/dev/null 2>&1; then
            fail shared-config
        fi
        if print -r -- "gitdir: /tmp/elsewhere" > .git 2>/dev/null; then
            fail gitdir-pointer
        fi
        if mv .git moved 2>/dev/null; then fail gitdir-rename; fi
        exit 0
    "#;
    let main_env = format!("MAIN={}", main.display());
    let output = jail(
        &root.path.join("feature"),
        &["--env", &main_env],
        &["/bin/zsh", "-c", script],
    );
    assert!(
        output.status.success(),
        "worktree policy\n{}",
        show(&output)
    );
    assert!(!main.join(".git/hooks/pre-commit").exists());
}

#[test]
fn credentials_inside_granted_home_directories_stay_hidden() {
    let root = Project::new("home");
    let home = fs::canonicalize(&root.path).unwrap();
    for dir in [".config/git", ".gradle/init.d", "project"] {
        fs::create_dir_all(home.join(dir)).unwrap();
    }
    fs::write(home.join(".config/git/ignore"), "target\n").unwrap();
    fs::write(home.join(".config/git/credentials"), "token\n").unwrap();
    fs::write(home.join(".gradle/gradle.properties"), "password\n").unwrap();
    fs::write(home.join("private.txt"), "private\n").unwrap();

    let script = r#"
        set +e
        fail() { print -r -- "FAIL $1"; exit 1; }
        grep -q target "$HOME/.config/git/ignore" || fail git-config-read
        print -n x > "$HOME/.gradle/scratch" || fail gradle-cache-write
        [[ -r "$HOME/.config/git/credentials" ]] && fail git-credentials
        [[ -r "$HOME/.gradle/gradle.properties" ]] && fail gradle-properties
        if print -n x > "$HOME/.gradle/init.d/evil.gradle" 2>/dev/null; then
            fail gradle-init
        fi
        [[ -r "$HOME/private.txt" ]] && fail home-on-path
        exit 0
    "#;
    // A PATH entry equal to $HOME must not make the home readable.
    let path = format!("{}:/usr/bin:/bin", home.display());
    let output = Command::new(env!("CARGO_BIN_EXE_mac-agent-jail"))
        .env("HOME", &home)
        .env("PATH", path)
        .arg("--no-pty")
        .arg("--project")
        .arg(home.join("project"))
        .args(["/bin/zsh", "-c", script])
        .output()
        .expect("run mac-agent-jail");
    assert!(output.status.success(), "home policy\n{}", show(&output));
}

#[test]
fn apple_toolchain_shims_run_without_xcrun_errors() {
    let project = Project::new("toolchain");
    let cases: &[(&str, &[&str], &str)] = &[
        ("/usr/bin/git", &["--version"], "git version"),
        ("/usr/bin/python3", &["-c", "print(123)"], "123"),
        ("/usr/bin/clang", &["--version"], "clang version"),
        ("/usr/bin/xcode-select", &["-p"], "Developer"),
    ];
    for (bin, args, needle) in cases {
        assert!(
            Path::new(bin).is_file(),
            "{bin} is missing; the macOS toolchain shims are part of this check"
        );
        let mut command = vec![*bin];
        command.extend_from_slice(args);
        let output = jail(&project.path, &[], &command);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{bin} failed\n{}", show(&output));
        assert!(
            stdout.contains(needle),
            "{bin} stdout missing {needle:?}\n{}",
            show(&output)
        );
        assert!(
            !stderr.contains("Operation not permitted")
                && !stderr.contains("xcrun_db"),
            "{bin} still hit a Seatbelt denial\n{}",
            show(&output)
        );
    }
}

#[test]
fn user_temp_allows_only_the_xcrun_cache() {
    let project = Project::new("xcrun");
    let temp = user_temp();
    let allowed = temp.join(format!("xcrun_db-maj-{}", std::process::id()));
    let denied = temp.join(format!("maj-not-xcrun-{}", std::process::id()));
    let script = format!(
        "print -n x > '{}' || exit 1; \
         if print -n y > '{}' 2>/dev/null; then exit 2; fi; \
         rm -f '{}'",
        allowed.display(),
        denied.display(),
        allowed.display()
    );
    let output = jail(&project.path, &[], &["/bin/zsh", "-c", &script]);
    let _ = fs::remove_file(&allowed);
    let leaked = denied.exists();
    let _ = fs::remove_file(&denied);
    assert!(!leaked, "jail wrote {}", denied.display());
    assert!(output.status.success(), "{}", show(&output));
}

#[test]
fn network_none_blocks_and_full_reaches_example() {
    let project = Project::new("net");
    let curl = [
        "/usr/bin/curl",
        "-sS",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--max-time",
        "20",
        "https://example.com",
    ];
    let blocked = jail(&project.path, &["--no-network"], &curl);
    assert!(
        !blocked.status.success(),
        "network none still reached example.com\n{}",
        show(&blocked)
    );

    let open = jail(&project.path, &[], &curl);
    let code = String::from_utf8_lossy(&open.stdout);
    assert!(
        open.status.success() && code.trim() == "200",
        "full network\n{}",
        show(&open)
    );
}

#[test]
fn filtered_network_allows_only_listed_hosts() {
    let project = Project::new("filtered");
    let script = r#"
        code=$(/usr/bin/curl -sS -o /dev/null -w '%{http_code}' --max-time 20 \
            https://example.com) || exit 1
        [[ "$code" == 200 ]] || { print -r -- "example:$code"; exit 1; }
        /usr/bin/curl -sS -o /dev/null --max-time 12 https://cloudflare.com
        exit 0
    "#;
    let output = jail(
        &project.path,
        &["--allow-host", "example.com"],
        &["/bin/zsh", "-c", script],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "listed host was blocked\n{}",
        show(&output)
    );
    assert!(
        stderr.contains("filtered egress blocked: cloudflare.com"),
        "unlisted host was not reported\n{}",
        show(&output)
    );
}

#[test]
fn keychain_is_closed_until_asked_for() {
    let project = Project::new("keychain");
    let list = ["/usr/bin/security", "list-keychains"];
    let on = jail(&project.path, &["--keychain"], &list);
    assert!(on.status.success(), "keychain access failed\n{}", show(&on));
    // A plain command is not an agent that logs in through the Keychain.
    for flags in [&[][..], &["--no-keychain"][..]] {
        let off = jail(&project.path, flags, &list);
        assert!(
            !off.status.success(),
            "{flags:?} still allowed list-keychains\n{}",
            show(&off)
        );
    }
}

#[test]
fn loopback_is_closed_until_a_port_is_listed() {
    let project = Project::new("loopback");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let connect = ["/usr/bin/nc", "-z", "-G", "3", "127.0.0.1", &port];

    let closed = jail(&project.path, &[], &connect);
    assert!(
        !closed.status.success(),
        "loopback reachable by default\n{}",
        show(&closed)
    );
    for flags in [&["--local-port", &port][..], &["--localhost"][..]] {
        let open = jail(&project.path, flags, &connect);
        assert!(open.status.success(), "{flags:?}\n{}", show(&open));
    }
    let other = jail(&project.path, &["--local-port", "9"], &connect);
    assert!(!other.status.success(), "wrong port\n{}", show(&other));
}

#[test]
fn a_listed_loopback_port_can_be_served_inside_a_filtered_jail() {
    let project = Project::new("serve");
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port().to_string()
    };
    // A server and its client, both inside the jail.
    let script = format!(
        "/usr/bin/nc -l 127.0.0.1 {port} >/dev/null & \
         for try in 1 2 3 4 5 6 7 8 9 10; do \
             /usr/bin/nc -z -G 2 127.0.0.1 {port} 2>/dev/null && exit 0; \
             sleep 0.2; \
         done; exit 1"
    );
    let command = ["/bin/zsh", "-c", script.as_str()];
    let open = jail(
        &project.path,
        &["--net", "filtered", "--local-port", &port],
        &command,
    );
    assert!(open.status.success(), "listed port\n{}", show(&open));
    let closed = jail(&project.path, &["--net", "filtered"], &command);
    assert!(!closed.status.success(), "unlisted port\n{}", show(&closed));
}

#[test]
fn a_project_without_a_repository_cannot_grow_a_git_dir() {
    let project = Project::new("nogit");
    let script = r#"
        set +e
        fail() { print -r -- "FAIL $1"; exit 1; }
        mkdir -p staged/hooks || fail project-write
        if print -r -- "gitdir: staged" > .git 2>/dev/null; then
            fail gitdir-file
        fi
        if mv staged .git 2>/dev/null; then fail moved-in; fi
        if /usr/bin/git init -q . 2>/dev/null; then fail git-init; fi
        exit 0
    "#;
    let output = jail(&project.path, &[], &["/bin/zsh", "-c", script]);
    assert!(output.status.success(), "no-repo policy\n{}", show(&output));
    assert!(!project.path.join(".git").exists());
}

#[test]
fn repositories_cannot_be_cloned_or_created_inside_the_project() {
    let project = Project::new("clone");
    let origin = project.path.join("origin");
    fs::create_dir_all(&origin).unwrap();
    host_git(&origin, &["init", "-q"]);
    host_git(&origin, &["commit", "-q", "--allow-empty", "-m", "init"]);

    let script = r#"
        set +e
        fail() { print -r -- "FAIL $1"; exit 1; }
        git=(/usr/bin/git -c user.name=maj -c user.email=maj@example.com
            -c commit.gpgsign=false)
        if $git clone -q origin copy 2>/dev/null; then fail clone; fi
        if $git init -q fresh 2>/dev/null; then fail init; fi
        if $git -C origin worktree add -q ../tree 2>/dev/null; then
            fail worktree-add
        fi
        mkdir -p staged/hooks sub || fail project-write
        if mv staged sub/.git 2>/dev/null; then fail moved-in; fi
        if print -n x > origin/.git/hooks/pre-commit 2>/dev/null; then
            fail nested-hooks
        fi
        if mv origin/.git origin/gitreal 2>/dev/null; then
            fail nested-rename
        fi
        # Package managers check dependencies out into their own directories.
        mkdir -p vendor pkg/.build/checkouts src || fail project-write
        $git clone -q origin vendor/copy || fail vendor-clone
        $git clone -q origin pkg/.build/checkouts/copy || fail swiftpm-clone
        $git -C vendor/copy commit -q --allow-empty -m dep || fail vendor-commit
        if $git clone -q origin src/copy 2>/dev/null; then fail src-clone; fi
        if print -r -- "gitdir: vendor/copy/.git" > .git 2>/dev/null; then
            fail root-pointer
        fi
        # A repository that was already there stays usable.
        print -n x > origin/file.txt || fail nested-write
        $git -C origin add file.txt || fail nested-add
        $git -C origin commit -q -m jailed || fail nested-commit
        exit 0
    "#;
    let output = jail(&project.path, &[], &["/bin/zsh", "-c", script]);
    assert!(output.status.success(), "clone policy\n{}", show(&output));
    for created in ["copy/.git", "fresh/.git", "tree/.git", "sub/.git"] {
        assert!(!project.path.join(created).exists(), "{created} exists");
    }
}

#[test]
fn a_config_file_inside_the_project_cannot_be_rewritten() {
    let project = Project::new("config");
    let config = project.path.join("jail.toml");
    fs::write(&config, "hide = [\"secret.txt\"]\n").unwrap();
    let script = r#"
        if print -r -- 'rw = ["~"]' >> jail.toml 2>/dev/null; then exit 1; fi
        if mv jail.toml old.toml 2>/dev/null; then exit 2; fi
        exit 0
    "#;
    let output = jail(
        &project.path,
        &["--config", config.to_str().unwrap()],
        &["/bin/zsh", "-c", script],
    );
    assert!(output.status.success(), "config policy\n{}", show(&output));
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        "hide = [\"secret.txt\"]\n"
    );
}
