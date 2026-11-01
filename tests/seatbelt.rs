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
fn keychain_lists_until_disabled() {
    let project = Project::new("keychain");
    let list = ["/usr/bin/security", "list-keychains"];
    let on = jail(&project.path, &[], &list);
    assert!(on.status.success(), "keychain access failed\n{}", show(&on));
    let off = jail(&project.path, &["--no-keychain"], &list);
    assert!(
        !off.status.success(),
        "--no-keychain still allowed list-keychains\n{}",
        show(&off)
    );
}
