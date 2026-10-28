//! Filtered egress: a small HTTP proxy that runs outside the sandbox. The
//! Seatbelt profile only lets the jail reach this proxy's loopback port; the
//! proxy dials only allow-listed hosts.
//!
//! Supports `CONNECT host:port` (HTTPS, any TLS client) and absolute-form
//! plain HTTP requests. Allowed names that resolve to loopback, private,
//! link-local, or other non-public addresses are refused, so an allowed
//! name cannot be pointed at services on the host or the LAN.

use std::{
    collections::BTreeSet,
    io::{self, Read, Write},
    net::{
        IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
    },
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

const MAX_HEAD: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug)]
pub struct AllowList {
    entries: Vec<String>,
}

impl AllowList {
    pub fn new<I: IntoIterator<Item = S>, S: AsRef<str>>(
        hosts: I,
    ) -> AllowList {
        let mut entries: Vec<String> = Vec::new();
        for host in hosts {
            let host = normalize(host.as_ref().trim_start_matches("*."));
            if !host.is_empty() && !entries.contains(&host) {
                entries.push(host);
            }
        }
        AllowList { entries }
    }

    /// `host` matches an entry exactly or is a subdomain of it.
    pub fn allows(&self, host: &str) -> bool {
        let host = normalize(host);
        self.entries.iter().any(|entry| {
            host == *entry
                || (host.len() > entry.len()
                    && host.ends_with(entry.as_str())
                    && host.as_bytes()[host.len() - entry.len() - 1] == b'.')
        })
    }

    pub fn entries(&self) -> &[String] {
        &self.entries
    }
}

fn normalize(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

/// Hosts the proxy refused, reported when the session ends.
pub type Blocked = Arc<Mutex<BTreeSet<String>>>;

pub struct Proxy {
    pub port: u16,
    pub blocked: Blocked,
}

pub fn start(allow: AllowList) -> io::Result<Proxy> {
    start_with_resolver(allow, Arc::new(resolve_public))
}

type Resolver = dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync;

fn start_with_resolver(
    allow: AllowList,
    resolver: Arc<Resolver>,
) -> io::Result<Proxy> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let blocked: Blocked = Arc::default();
    let allow = Arc::new(allow);
    let shared = blocked.clone();
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let allow = allow.clone();
            let blocked = shared.clone();
            let resolver = resolver.clone();
            thread::spawn(move || {
                let _ = handle(client, &allow, &blocked, &*resolver);
            });
        }
    });
    Ok(Proxy { port, blocked })
}

fn resolve_public(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    let public: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| is_public(a.ip()))
        .collect();
    if public.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "resolves only to non-public addresses",
        ));
    }
    Ok(public)
}

fn handle(
    mut client: TcpStream,
    allow: &AllowList,
    blocked: &Blocked,
    resolver: &Resolver,
) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    let (head, rest) = read_head(&mut client)?;
    client.set_read_timeout(None)?;
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (method, target, version) =
        match (parts.next(), parts.next(), parts.next()) {
            (Some(m), Some(t), Some(v)) => (m, t, v),
            _ => return respond(&mut client, 400, "malformed request"),
        };

    let (host, port, origin_form) = if method.eq_ignore_ascii_case("CONNECT") {
        match split_host_port(target, 443) {
            Some((host, port)) => (host, port, None),
            None => return respond(&mut client, 400, "bad CONNECT target"),
        }
    } else {
        match parse_absolute(target) {
            Some((host, port, path)) => (host, port, Some(path)),
            None => {
                return respond(
                    &mut client,
                    400,
                    "only absolute http:// URLs are proxied",
                );
            }
        }
    };

    if !allow.allows(&host) {
        blocked.lock().unwrap().insert(host.clone());
        return respond(
            &mut client,
            403,
            &format!("mac-agent-jail: {host} is not in the allow-list"),
        );
    }
    let upstream = match resolver(&host, port).and_then(|addrs| dial(&addrs)) {
        Ok(stream) => stream,
        Err(e) => {
            return respond(&mut client, 502, &format!("{host}: {e}"));
        }
    };

    let mut upstream_w = upstream.try_clone()?;
    match origin_form {
        None => {
            client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        }
        Some(path) => {
            let mut out = format!("{method} {path} {version}\r\n");
            for line in lines.filter(|l| !l.is_empty()) {
                let name = line.split(':').next().unwrap_or("").trim();
                if name.eq_ignore_ascii_case("proxy-connection")
                    || name.eq_ignore_ascii_case("proxy-authorization")
                    || name.eq_ignore_ascii_case("connection")
                {
                    continue;
                }
                out.push_str(line);
                out.push_str("\r\n");
            }
            out.push_str("Connection: close\r\n\r\n");
            upstream_w.write_all(out.as_bytes())?;
        }
    }
    upstream_w.write_all(&rest)?;
    pipe(client, upstream)
}

fn dial(addrs: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no addresses");
    for addr in addrs {
        match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn pipe(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    let mut client_r = client.try_clone()?;
    let mut upstream_w = upstream.try_clone()?;
    let up = thread::spawn(move || {
        let _ = io::copy(&mut client_r, &mut upstream_w);
        let _ = upstream_w.shutdown(Shutdown::Write);
    });
    let mut upstream_r = upstream;
    let mut client_w = client;
    let _ = io::copy(&mut upstream_r, &mut client_w);
    let _ = client_w.shutdown(Shutdown::Write);
    let _ = up.join();
    Ok(())
}

fn read_head(stream: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = find(&buf, b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            buf.truncate(end);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "head too large",
            ));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn respond(stream: &mut TcpStream, code: u16, message: &str) -> io::Result<()> {
    let reason = match code {
        400 => "Bad Request",
        403 => "Forbidden",
        _ => "Bad Gateway",
    };
    let body = format!("{message}\n");
    write!(
        stream,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn split_host_port(target: &str, default_port: u16) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(port) => port.parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };
        (host.to_string(), port)
    } else {
        match target.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), port.parse().ok()?),
            None => (target.to_string(), default_port),
        }
    };
    (!host.is_empty() && !host.contains(['/', '@', ' ']))
        .then_some((host, port))
}

fn parse_absolute(target: &str) -> Option<(String, u16, String)> {
    let rest = target.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_host_port(authority, 80)?;
    Some((host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_matches_host_and_subdomains_only() {
        let allow = AllowList::new(["GitHub.com.", "*.npmjs.org"]);
        assert!(allow.allows("github.com"));
        assert!(allow.allows("api.github.com"));
        assert!(allow.allows("registry.npmjs.org"));
        assert!(allow.allows("npmjs.org"));
        assert!(!allow.allows("evilgithub.com"));
        assert!(!allow.allows("github.com.evil.net"));
        assert!(!allow.allows("com"));
        assert_eq!(allow.entries(), ["github.com", "npmjs.org"]);
    }

    #[test]
    fn non_public_addresses_are_refused() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "140.82.112.3", "2606:4700::1111"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn target_parsing() {
        assert_eq!(
            split_host_port("example.com:8443", 443),
            Some(("example.com".into(), 8443))
        );
        assert_eq!(
            split_host_port("[2606:4700::1]:443", 443),
            Some(("2606:4700::1".into(), 443))
        );
        assert_eq!(split_host_port("a/b:1", 443), None);
        assert_eq!(
            parse_absolute("http://example.com/x?y"),
            Some(("example.com".into(), 80, "/x?y".into()))
        );
        assert_eq!(
            parse_absolute("http://example.com:8080"),
            Some(("example.com".into(), 8080, "/".into()))
        );
        assert_eq!(parse_absolute("https://example.com/"), None);
    }

    fn local_upstream(reply: &'static [u8]) -> SocketAddr {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            for mut conn in server.incoming().flatten() {
                let mut buf = [0u8; 1024];
                let _ = conn.read(&mut buf);
                let _ = conn.write_all(reply);
            }
        });
        addr
    }

    fn proxy_to(addr: SocketAddr, hosts: &[&str]) -> Proxy {
        let resolver: Arc<Resolver> = Arc::new(move |_, _| Ok(vec![addr]));
        start_with_resolver(AllowList::new(hosts), resolver).unwrap()
    }

    fn exchange(port: u16, request: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn connect_tunnels_to_allowed_hosts_only() {
        let addr = local_upstream(b"pong");
        let proxy = proxy_to(addr, &["allowed.test"]);
        let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).unwrap();
        stream
            .write_all(b"CONNECT api.allowed.test:443 HTTP/1.1\r\n\r\nping")
            .unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).unwrap();
        assert_eq!(out, "HTTP/1.1 200 Connection Established\r\n\r\npong");

        let denied = exchange(
            proxy.port,
            "CONNECT other.test:443 HTTP/1.1\r\nHost: other.test\r\n\r\n",
        );
        assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");
        assert!(proxy.blocked.lock().unwrap().contains("other.test"));
    }

    #[test]
    fn plain_http_is_rewritten_to_origin_form() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(String::new()));
        let record = seen.clone();
        thread::spawn(move || {
            let (mut conn, _) = server.accept().unwrap();
            let mut buf = [0u8; 2048];
            let n = conn.read(&mut buf).unwrap();
            *record.lock().unwrap() =
                String::from_utf8_lossy(&buf[..n]).into_owned();
            conn.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        });
        let proxy = proxy_to(addr, &["allowed.test"]);
        let reply = exchange(
            proxy.port,
            "GET http://allowed.test/path?q=1 HTTP/1.1\r\nHost: allowed.test\r\n\
             Proxy-Connection: keep-alive\r\n\r\n",
        );
        assert!(reply.starts_with("HTTP/1.1 204"), "{reply}");
        let request = seen.lock().unwrap().clone();
        assert!(
            request.starts_with("GET /path?q=1 HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(request.contains("Host: allowed.test\r\n"));
        assert!(request.contains("Connection: close\r\n"));
        assert!(!request.to_ascii_lowercase().contains("proxy-connection"));
    }

    #[test]
    fn real_resolver_refuses_loopback() {
        let err = resolve_public("localhost", 80).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
