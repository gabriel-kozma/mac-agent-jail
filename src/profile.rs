//! Seatbelt (SBPL) profile rendering.
//!
//! [`Profile`] is a plain description of what the sandbox may do; resolving
//! it from the host lives in `policy.rs`. Rendering is pure so the output can
//! be tested anywhere. SBPL is last-match-wins, so the render order matters:
//! allows first, then denies, then the narrow exceptions to those denies.

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Match {
    /// The path and everything below it.
    Subpath,
    /// Exactly this path.
    Literal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rule {
    Path(PathBuf, Match),
    /// A raw SBPL regex, already escaped with [`regex_escape`] where needed.
    Regex(String),
}

impl Rule {
    pub fn subpath(path: impl Into<PathBuf>) -> Rule {
        Rule::Path(path.into(), Match::Subpath)
    }

    pub fn literal(path: impl Into<PathBuf>) -> Rule {
        Rule::Path(path.into(), Match::Literal)
    }

    fn render(&self) -> String {
        match self {
            Rule::Path(path, Match::Subpath) => {
                format!("(subpath \"{}\")", escape(&path.to_string_lossy()))
            }
            Rule::Path(path, Match::Literal) => {
                format!("(literal \"{}\")", escape(&path.to_string_lossy()))
            }
            Rule::Regex(regex) => format!("(regex #\"{regex}\")"),
        }
    }
}

/// Loopback destinations reachable in full network mode. Services
/// listening there (dev servers, debug ports, Docker's TCP API) are host
/// processes outside the jail, like the Unix sockets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Loopback {
    All,
    /// Only these ports.
    Ports(Vec<u16>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Network {
    /// Any IP destination, with loopback limited as given.
    Full(Loopback),
    /// Only the filtered-egress proxy on this loopback port.
    Proxy(u16),
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section<T> {
    pub comment: &'static str,
    pub items: Vec<T>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub mach_services: Vec<Section<String>>,
    /// POSIX shared-memory names readable (and writable when `true`).
    pub shm: Vec<(String, bool)>,
    pub network: Network,
    /// Unix-domain sockets the sandbox may connect to.
    pub unix_sockets: Vec<Rule>,
    /// Unix-domain sockets the sandbox may bind (create and listen on).
    pub unix_binds: Vec<Rule>,
    /// The PTY allocated for this run, granted ioctl access.
    pub tty: Option<PathBuf>,
    /// Directories whose own node may be `stat`ed, so allowed paths below
    /// them resolve. Never grants listing or contents.
    pub metadata: Vec<PathBuf>,
    pub read: Vec<Section<Rule>>,
    pub write: Vec<Section<Rule>>,
    /// Denied for reads and writes.
    pub hidden: Vec<Section<Rule>>,
    /// Exceptions to `hidden`, re-allowed for reads and writes.
    pub reallow: Vec<Rule>,
    /// Denied for reads and writes; rendered after `reallow` so an explicit
    /// deny always wins.
    pub denied: Vec<Section<Rule>>,
    pub deny_write: Vec<Section<Rule>>,
    /// Exceptions to `deny_write`, writable again. Rendered before
    /// `denied`, so an explicit deny still wins.
    pub reallow_write: Vec<Section<Rule>>,
}

pub fn render(profile: &Profile) -> String {
    let mut out = String::new();
    out.push_str("(version 1)\n(deny default)\n\n");

    out.push_str("; Processes stay inside the sandbox\n");
    out.push_str("(allow process-exec)\n");
    out.push_str("(allow process-fork)\n");
    out.push_str("(allow process-info* (target same-sandbox))\n");
    out.push_str("(allow signal (target same-sandbox))\n");
    out.push_str("(allow sysctl-read)\n\n");

    for section in &profile.mach_services {
        if section.items.is_empty() {
            continue;
        }
        out.push_str(&format!("; {}\n", section.comment));
        for name in &section.items {
            out.push_str(&format!(
                "(allow mach-lookup (global-name \"{}\"))\n",
                escape(name)
            ));
        }
        out.push('\n');
    }

    if !profile.shm.is_empty() {
        out.push_str("; Shared memory used by preferences and Keychain\n");
        for (name, writable) in &profile.shm {
            let name = escape(name);
            out.push_str(&format!(
                "(allow ipc-posix-shm-read-data ipc-posix-shm-read-metadata \
                 (ipc-posix-name \"{name}\"))\n"
            ));
            if *writable {
                out.push_str(&format!(
                    "(allow ipc-posix-shm-write-data \
                     (ipc-posix-name \"{name}\"))\n"
                ));
            }
        }
        out.push('\n');
    }

    out.push_str("; Terminals and standard devices\n");
    out.push_str("(allow pseudo-tty)\n");
    out.push_str(
        "(allow file-read* file-write* file-ioctl (literal \"/dev/ptmx\"))\n",
    );
    // /dev/tty is the caller's own controlling terminal. ioctl is granted
    // only on the PTY allocated for this run: SBPL cannot filter ioctl
    // requests, and TIOCSTI on a host terminal would inject keystrokes into
    // a shell outside the jail.
    out.push_str("(allow file-read* file-write* (literal \"/dev/tty\"))\n");
    if let Some(tty) = &profile.tty {
        out.push_str(&format!(
            "(allow file-read* file-write* file-ioctl (literal \"{}\"))\n",
            escape(&tty.to_string_lossy())
        ));
    }
    out.push_str(
        "(allow file-write* (literal \"/dev/null\") (literal \"/dev/zero\") \
         (literal \"/dev/random\") (literal \"/dev/urandom\"))\n",
    );
    // Aliases of descriptors the process already holds; scripts redirect
    // to them (`echo oops >/dev/stderr`).
    out.push_str(
        "(allow file-write* (literal \"/dev/stdout\") \
         (literal \"/dev/stderr\") (subpath \"/dev/fd\"))\n",
    );
    out.push_str(
        "(allow file-read* file-write* file-ioctl \
         (literal \"/dev/dtracehelper\"))\n\n",
    );

    render_network(&mut out, profile);

    out.push_str("; Path resolution: stat() of these nodes only\n");
    out.push_str("(allow file-read* (literal \"/\"))\n");
    for dir in &profile.metadata {
        out.push_str(&format!(
            "(allow file-read-metadata (literal \"{}\"))\n",
            escape(&dir.to_string_lossy())
        ));
    }
    out.push('\n');

    render_rules(&mut out, "allow file-read*", &profile.read);
    render_rules(&mut out, "allow file-read* file-write*", &profile.write);
    render_rules(&mut out, "deny file-read* file-write*", &profile.hidden);
    if !profile.reallow.is_empty() {
        out.push_str("; Exceptions to the denies above\n");
        for rule in &profile.reallow {
            out.push_str(&format!(
                "(allow file-read* file-write* {})\n",
                rule.render()
            ));
        }
        out.push('\n');
    }
    render_rules(&mut out, "deny file-write*", &profile.deny_write);
    render_rules(&mut out, "allow file-write*", &profile.reallow_write);
    render_rules(&mut out, "deny file-read* file-write*", &profile.denied);
    out
}

fn render_network(out: &mut String, profile: &Profile) {
    match &profile.network {
        Network::Full(loopback) => {
            out.push_str("; Network: any IP destination\n");
            out.push_str("(allow system-socket)\n");
            out.push_str("(allow network-outbound (remote ip \"*:*\"))\n");
            if let Loopback::Ports(ports) = loopback {
                out.push_str(
                    "(deny network-outbound (remote ip \"localhost:*\"))\n",
                );
                for port in ports {
                    out.push_str(&format!(
                        "(allow network-outbound \
                         (remote ip \"localhost:{port}\"))\n"
                    ));
                }
            }
            out.push_str("(allow network-inbound (local ip \"*:*\"))\n");
            out.push_str("(allow network-bind (local ip \"*:*\"))\n");
            // DNS on macOS goes through mDNSResponder's Unix socket. Other
            // Unix sockets (tmux, docker, ssh-agent) stay closed: they reach
            // host processes that run commands outside the jail.
            out.push_str(
                "(allow network-outbound (remote unix-socket \
                 (path-literal \"/private/var/run/mDNSResponder\")))\n\n",
            );
        }
        Network::Proxy(port) => {
            out.push_str("; Network: filtered egress proxy only\n");
            out.push_str("(allow system-socket)\n");
            out.push_str(&format!(
                "(allow network-outbound (remote ip \"localhost:{port}\"))\n\n"
            ));
        }
        Network::None => {
            out.push_str("; Network: none\n\n");
        }
    }

    if profile.unix_sockets.is_empty() && profile.unix_binds.is_empty() {
        return;
    }
    out.push_str("; Unix sockets\n");
    if profile.network == Network::None {
        out.push_str("(allow system-socket (socket-domain AF_UNIX))\n");
    }
    for rule in &profile.unix_sockets {
        out.push_str(&format!(
            "(allow network-outbound (remote unix-socket {}))\n",
            socket_filter(rule)
        ));
    }
    for rule in &profile.unix_binds {
        out.push_str(&format!(
            "(allow network-bind network-inbound (local unix-socket {}))\n",
            socket_filter(rule)
        ));
    }
    out.push('\n');
}

fn socket_filter(rule: &Rule) -> String {
    match rule {
        Rule::Path(path, Match::Subpath) => {
            format!("(subpath \"{}\")", escape(&path.to_string_lossy()))
        }
        Rule::Path(path, Match::Literal) => {
            format!("(path-literal \"{}\")", escape(&path.to_string_lossy()))
        }
        Rule::Regex(regex) => format!("(path-regex #\"{regex}\")"),
    }
}

fn render_rules(out: &mut String, verb: &str, sections: &[Section<Rule>]) {
    for section in sections {
        if section.items.is_empty() {
            continue;
        }
        out.push_str(&format!("; {}\n", section.comment));
        for rule in &section.items {
            out.push_str(&format!("({verb} {})\n", rule.render()));
        }
        out.push('\n');
    }
}

/// Escape text for an SBPL string literal.
pub fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        push_escaped(c, &mut out);
    }
    out
}

fn push_escaped(c: char, out: &mut String) {
    match c {
        '\\' => out.push_str("\\\\"),
        '"' => out.push_str("\\\""),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        _ => out.push(c),
    }
}

/// Escape a literal path for use inside an SBPL `#"..."` regex.
pub fn regex_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for c in input.chars() {
        if ".*+?()[]{}^$|".contains(c) {
            out.push('\\');
            out.push(c);
        } else {
            push_escaped(c, &mut out);
        }
    }
    out
}

/// Every ancestor directory of the given paths, excluding `/`.
pub fn ancestors<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for path in paths {
        let mut current = path.parent();
        while let Some(dir) = current {
            if dir.parent().is_none() {
                break;
            }
            if !out.iter().any(|seen| seen == dir) {
                out.push(dir.to_path_buf());
            }
            current = dir.parent();
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> Profile {
        Profile {
            mach_services: Vec::new(),
            shm: Vec::new(),
            network: Network::None,
            unix_sockets: Vec::new(),
            unix_binds: Vec::new(),
            tty: None,
            metadata: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            hidden: Vec::new(),
            reallow: Vec::new(),
            denied: Vec::new(),
            deny_write: Vec::new(),
            reallow_write: Vec::new(),
        }
    }

    #[test]
    fn starts_with_deny_default() {
        let text = render(&empty());
        assert!(text.starts_with("(version 1)\n(deny default)\n"));
        assert!(!text.contains("(allow mach-lookup)"));
        assert!(!text.contains("network-outbound"));
    }

    #[test]
    fn denies_render_after_allows() {
        let mut profile = empty();
        profile.write.push(Section {
            comment: "project",
            items: vec![Rule::subpath("/p")],
        });
        profile.hidden.push(Section {
            comment: "hidden",
            items: vec![Rule::Regex("^/p/\\.env$".into())],
        });
        profile.reallow.push(Rule::literal("/p/.env.example"));
        let text = render(&profile);
        let allow =
            text.find("(allow file-read* file-write* (subpath \"/p\"))");
        let deny =
            text.find("(deny file-read* file-write* (regex #\"^/p/\\.env$\"))");
        let reallow = text.find("(literal \"/p/.env.example\")");
        assert!(allow < deny && deny < reallow, "{text}");
    }

    #[test]
    fn full_network_excludes_arbitrary_unix_sockets() {
        let mut profile = empty();
        profile.network = Network::Full(Loopback::All);
        let text = render(&profile);
        assert!(text.contains("(remote ip \"*:*\")"));
        assert!(text.contains("/private/var/run/mDNSResponder"));
        assert!(!text.contains("(allow network-outbound)\n"));
        assert!(!text.contains("localhost"));
    }

    #[test]
    fn full_network_closes_loopback_except_listed_ports() {
        let mut profile = empty();
        profile.network = Network::Full(Loopback::Ports(vec![3000]));
        let text = render(&profile);
        let any = text.find("(allow network-outbound (remote ip \"*:*\"))");
        let deny =
            text.find("(deny network-outbound (remote ip \"localhost:*\"))");
        let port = text
            .find("(allow network-outbound (remote ip \"localhost:3000\"))");
        assert!(any.is_some() && any < deny && deny < port, "{text}");
    }

    #[test]
    fn proxy_network_allows_only_its_port() {
        let mut profile = empty();
        profile.network = Network::Proxy(40123);
        let text = render(&profile);
        assert!(text.contains("(remote ip \"localhost:40123\")"));
        assert!(!text.contains("*:*"));
    }

    #[test]
    fn unix_sockets_without_network_get_a_socket_domain() {
        let mut profile = empty();
        profile.unix_sockets.push(Rule::literal("/tmp/agent.sock"));
        let text = render(&profile);
        assert!(text.contains("(socket-domain AF_UNIX)"));
        assert!(text.contains(
            "(remote unix-socket (path-literal \"/tmp/agent.sock\"))"
        ));
    }

    #[test]
    fn tty_gets_ioctl_only_when_allocated() {
        let mut profile = empty();
        assert!(!render(&profile).contains("/dev/ttys"));
        profile.tty = Some("/dev/ttys042".into());
        assert!(render(&profile).contains(
            "(allow file-read* file-write* file-ioctl (literal \"/dev/ttys042\"))"
        ));
    }

    #[test]
    fn standard_stream_aliases_are_writable() {
        let text = render(&empty());
        assert!(text.contains(
            "(allow file-write* (literal \"/dev/stdout\") \
             (literal \"/dev/stderr\") (subpath \"/dev/fd\"))"
        ));
    }

    #[test]
    fn write_exceptions_render_between_protection_and_explicit_denies() {
        let mut profile = empty();
        let rule = |comment, path: &str| Section {
            comment,
            items: vec![Rule::subpath(path)],
        };
        profile.deny_write.push(rule("protected", "/p/a"));
        profile.reallow_write.push(rule("exception", "/p/a/b"));
        profile.denied.push(rule("denied", "/p/a/b/c"));
        let text = render(&profile);
        let protect = text.find("(deny file-write* (subpath \"/p/a\"))");
        let exception = text.find("(allow file-write* (subpath \"/p/a/b\"))");
        let denied =
            text.find("(deny file-read* file-write* (subpath \"/p/a/b/c\"))");
        assert!(
            protect.is_some() && protect < exception && exception < denied,
            "{text}"
        );
    }

    #[test]
    fn escaping() {
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
        assert_eq!(regex_escape("/a.b/c+d"), "/a\\.b/c\\+d");
        assert_eq!(regex_escape("x\"y"), "x\\\"y");
    }

    #[test]
    fn ancestors_skip_root_and_dedupe() {
        let paths = [Path::new("/Users/me/a/b"), Path::new("/Users/me/c")];
        assert_eq!(
            ancestors(paths),
            vec![
                PathBuf::from("/Users"),
                PathBuf::from("/Users/me"),
                PathBuf::from("/Users/me/a"),
            ]
        );
    }
}
