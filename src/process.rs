//! Running the sandboxed command, optionally behind a PTY relay.
//!
//! With a PTY, the child gets a fresh terminal of its own and the Seatbelt
//! profile grants ioctl on that device only. The host terminal never enters
//! the sandbox, so `TIOCSTI` cannot push keystrokes into the user's shell.

use std::{
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::process::{CommandExt, ExitStatusExt},
    },
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicBool, AtomicI32, Ordering},
};

static WINCH: AtomicBool = AtomicBool::new(false);
static FORWARD: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_winch(_: libc::c_int) {
    WINCH.store(true, Ordering::SeqCst);
}

extern "C" fn on_terminate(signal: libc::c_int) {
    FORWARD.store(signal, Ordering::SeqCst);
}

fn install(signal: libc::c_int, handler: extern "C" fn(libc::c_int)) {
    // SAFETY: the handlers only store to atomics. No SA_RESTART, so a
    // blocking poll()/waitpid() returns EINTR and the loop sees the flag.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as usize;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(signal, &action, std::ptr::null_mut());
    }
}

/// Keep the supervisor alive on terminal signals so it can clean up, and
/// remember them for forwarding. Handlers (unlike SIG_IGN) reset to the
/// default on exec, so the child is unaffected.
fn install_supervisor_handlers() {
    for signal in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP] {
        install(signal, on_terminate);
    }
}

pub fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1)
}

pub fn is_tty(fd: RawFd) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

pub struct Pty {
    master: OwnedFd,
    slave: OwnedFd,
    pub path: PathBuf,
}

impl Pty {
    pub fn open() -> io::Result<Pty> {
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        let mut size =
            window_size(libc::STDIN_FILENO).unwrap_or(libc::winsize {
                ws_row: 24,
                ws_col: 80,
                ws_xpixel: 0,
                ws_ypixel: 0,
            });
        // SAFETY: valid out-pointers; the terminal settings are inherited.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openpty returned two fresh descriptors we now own.
        let (master, slave) = unsafe {
            (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave))
        };
        set_cloexec(master.as_raw_fd());
        set_cloexec(slave.as_raw_fd());
        // Copy the host terminal's modes so the agent starts with the same
        // line discipline the user had.
        if let Some(attrs) = get_attrs(libc::STDIN_FILENO) {
            unsafe {
                libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &attrs)
            };
        }
        let path = tty_name(slave.as_raw_fd())?;
        Ok(Pty {
            master,
            slave,
            path,
        })
    }

    /// Spawn `cmd` on the PTY and relay it to the host terminal until the
    /// child exits.
    pub fn run(self, mut cmd: Command) -> io::Result<ExitStatus> {
        let slave = self.slave;
        cmd.stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave.try_clone()?));
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn()?;
        drop(cmd);
        drop(slave);

        install_supervisor_handlers();
        install(libc::SIGWINCH, on_winch);
        let _raw = RawMode::enter(libc::STDIN_FILENO);
        relay(self.master.as_raw_fd(), &mut child)
    }
}

/// Run without a PTY, sharing the caller's stdio.
pub fn run_plain(mut cmd: Command) -> io::Result<ExitStatus> {
    let mut child = cmd.spawn()?;
    install_supervisor_handlers();
    loop {
        forward_signal(&child);
        match child.try_wait()? {
            Some(status) => return Ok(status),
            None => {
                let mut status = 0;
                // SAFETY: waits for our own child; EINTR loops.
                let rc =
                    unsafe { libc::waitpid(child.id() as i32, &mut status, 0) };
                if rc == child.id() as i32 {
                    return Ok(ExitStatus::from_raw(status));
                }
            }
        }
    }
}

fn forward_signal(child: &Child) {
    let signal = FORWARD.swap(0, Ordering::SeqCst);
    // Interactive Ctrl-C/Ctrl-\ already reach the child through the
    // terminal; only forward what was sent to the supervisor directly.
    if signal == libc::SIGTERM || signal == libc::SIGHUP {
        unsafe { libc::kill(child.id() as i32, signal) };
    }
}

fn relay(master: RawFd, child: &mut Child) -> io::Result<ExitStatus> {
    let mut buf = [0u8; 16 * 1024];
    let mut stdin_open = true;
    loop {
        if WINCH.swap(false, Ordering::SeqCst)
            && let Some(size) = window_size(libc::STDIN_FILENO)
        {
            unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &size) };
        }
        forward_signal(child);
        if let Some(status) = child.try_wait()? {
            drain(master, &mut buf);
            return Ok(status);
        }

        let mut fds = [
            libc::pollfd {
                fd: if stdin_open { libc::STDIN_FILENO } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: master,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, 200) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        {
            match read_fd(master, &mut buf) {
                Some(n) if n > 0 => write_all(libc::STDOUT_FILENO, &buf[..n]),
                // EOF/EIO: every slave descriptor is closed.
                _ => return child.wait(),
            }
        }
        if stdin_open && fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            match read_fd(libc::STDIN_FILENO, &mut buf) {
                Some(n) if n > 0 => write_all(master, &buf[..n]),
                _ => stdin_open = false,
            }
        }
    }
}

/// Copy whatever output is still buffered on the master after the child
/// exited. Background processes may keep the slave open, so never block.
fn drain(master: RawFd, buf: &mut [u8]) {
    loop {
        let mut fd = libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut fd, 1, 50) } <= 0
            || fd.revents & libc::POLLIN == 0
        {
            return;
        }
        match read_fd(master, buf) {
            Some(n) if n > 0 => write_all(libc::STDOUT_FILENO, &buf[..n]),
            _ => return,
        }
    }
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> Option<usize> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Some(n as usize);
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return None;
        }
    }
}

fn write_all(fd: RawFd, mut data: &[u8]) {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n > 0 {
            data = &data[n as usize..];
        } else if n < 0
            && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
        {
            continue;
        } else {
            return;
        }
    }
}

fn window_size(fd: RawFd) -> Option<libc::winsize> {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    (unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) } == 0
        && size.ws_col > 0)
        .then_some(size)
}

fn get_attrs(fd: RawFd) -> Option<libc::termios> {
    let mut attrs: libc::termios = unsafe { std::mem::zeroed() };
    (unsafe { libc::tcgetattr(fd, &mut attrs) } == 0).then_some(attrs)
}

fn set_cloexec(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
    }
}

fn tty_name(fd: RawFd) -> io::Result<PathBuf> {
    let mut buf = [0 as libc::c_char; 128];
    let rc = unsafe { libc::ttyname_r(fd, buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    Ok(PathBuf::from(name.to_string_lossy().into_owned()))
}

/// Puts the host terminal in raw mode; restores it on drop.
struct RawMode {
    fd: RawFd,
    saved: Option<libc::termios>,
}

impl RawMode {
    fn enter(fd: RawFd) -> RawMode {
        let saved = get_attrs(fd);
        if let Some(mut raw) = saved {
            unsafe {
                libc::cfmakeraw(&mut raw);
                libc::tcsetattr(fd, libc::TCSANOW, &raw);
            }
        }
        RawMode { fd, saved }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if let Some(saved) = &self.saved {
            unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, saved) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code(ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
        assert_eq!(exit_code(ExitStatus::from_raw(libc::SIGKILL)), 137);
    }

    #[test]
    fn pty_runs_a_command_with_a_controlling_terminal() {
        let pty = Pty::open().unwrap();
        let path = pty.path.clone();
        assert!(path.to_string_lossy().starts_with("/dev/"));
        let mut cmd = Command::new("/bin/sh");
        // `tty` prints the controlling terminal: it must be the new PTY.
        cmd.args(["-c", "test \"$(tty)\" = \"$1\" && exit 7", "sh"])
            .arg(&path);
        let status = pty.run(cmd).unwrap();
        assert_eq!(exit_code(status), 7);
    }

    #[test]
    fn plain_run_reports_status() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "exit 5"]);
        assert_eq!(exit_code(run_plain(cmd).unwrap()), 5);
    }
}
