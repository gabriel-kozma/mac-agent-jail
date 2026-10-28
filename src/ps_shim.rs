//! Minimal `ps` for Codex inside the jail.
//!
//! `/bin/ps` is setuid on macOS and Seatbelt refuses to exec setuid
//! binaries, but Codex validates the PID of its app-server with
//! `ps -p PID -o stat= -o lstart=`. When this executable is invoked as `ps`
//! (through a symlink on the jail's PATH) it answers exactly that query and
//! nothing else. Ported from ai-jail's `codex_ps.rs`.

use std::{ffi::OsString, path::Path};

pub fn is_invoked_as_ps() -> bool {
    std::env::args_os()
        .next()
        .is_some_and(|arg0| Path::new(&arg0).file_name() == Some("ps".as_ref()))
}

pub fn run() -> i32 {
    match pid_query(std::env::args_os().skip(1)) {
        Some(pid) => match process_info(pid) {
            Ok((state, start)) => {
                println!("{state} {start}");
                0
            }
            Err(error) => {
                eprintln!("ps: {error}");
                1
            }
        },
        None => {
            eprintln!(
                "ps: unsupported query (mac-agent-jail only answers Codex PID checks)"
            );
            1
        }
    }
}

fn pid_query(args: impl IntoIterator<Item = OsString>) -> Option<i32> {
    let args: Vec<OsString> = args.into_iter().collect();
    let expected = ["-p", "", "-o", "stat=", "-o", "lstart="];
    if args.len() != expected.len()
        || args
            .iter()
            .zip(expected)
            .enumerate()
            .any(|(i, (arg, want))| i != 1 && arg != want)
    {
        return None;
    }
    args[1].to_str()?.parse().ok().filter(|pid| *pid > 0)
}

#[cfg(target_os = "macos")]
fn process_info(pid: i32) -> Result<(char, String), String> {
    use std::ffi::{c_char, c_int, c_void};

    const PROC_PIDTBSDINFO: c_int = 3;
    const MAXCOMLEN: usize = 16;

    #[repr(C)]
    struct ProcBsdInfo {
        flags: u32,
        status: u32,
        xstatus: u32,
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        ruid: u32,
        rgid: u32,
        svuid: u32,
        svgid: u32,
        reserved: u32,
        comm: [c_char; MAXCOMLEN],
        name: [c_char; MAXCOMLEN * 2],
        nfiles: u32,
        pgid: u32,
        pjobc: u32,
        tdev: u32,
        tpgid: u32,
        nice: i32,
        start_tvsec: u64,
        start_tvusec: u64,
    }

    unsafe extern "C" {
        fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;
    }

    let size = std::mem::size_of::<ProcBsdInfo>() as c_int;
    let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::uninit();
    // SAFETY: the buffer is sized and aligned for PROC_PIDTBSDINFO and is
    // read only when the kernel filled all of it.
    let written = unsafe {
        proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size)
    };
    if written != size {
        return Err(format!("cannot inspect process {pid}"));
    }
    let info = unsafe { info.assume_init() };
    let state = match info.status {
        2 => 'R',
        4 => 'T',
        5 => 'Z',
        _ => 'S',
    };
    Ok((
        state,
        format!("{}.{:06}", info.start_tvsec, info.start_tvusec),
    ))
}

#[cfg(not(target_os = "macos"))]
fn process_info(pid: i32) -> Result<(char, String), String> {
    Err(format!("cannot inspect process {pid} on this platform"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(args: &[&str]) -> Option<i32> {
        pid_query(args.iter().map(OsString::from))
    }

    #[test]
    fn accepts_only_the_codex_query() {
        assert_eq!(
            query(&["-p", "123", "-o", "stat=", "-o", "lstart="]),
            Some(123)
        );
        assert_eq!(query(&["-p", "123", "-o", "args="]), None);
        assert_eq!(query(&["-p", "0", "-o", "stat=", "-o", "lstart="]), None);
        assert_eq!(query(&["-ax"]), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reports_self() {
        let (state, start) = process_info(std::process::id() as i32).unwrap();
        assert!(matches!(state, 'R' | 'S'));
        assert!(start.contains('.'));
    }
}
