//! fidoparole-bridge — the Firefox native-messaging host of FidoParole.
//!
//! Firefox starts this program when the FidoParole extension asks for logins.
//! It holds no secrets and decides nothing: it forwards each request from the
//! extension (stdin) to the running FidoParole app over a per-user local pipe
//! or socket, and the app's answer back (stdout). The app checks every request
//! and only answers while a vault is unlocked and browser autofill is on.
//!
//! On Linux it is built fully static, because the Flatpak build of Firefox runs
//! it inside its sandbox, against the sandbox's own runtime libraries.

// No console window when Firefox starts it on Windows; stdin / stdout are the
// pipes Firefox hands over either way.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod proto;

use std::io;
use std::time::Duration;

const NOT_RUNNING: &str = r#"{"ok":false,"error":"not_running","message":"FidoParole is not running. Start it and unlock your vault."}"#;
const BAD_REQUEST: &str = r#"{"ok":false,"error":"bad_request","message":"The request could not be read."}"#;

/// How long to wait for the app's answer. It never waits for the key: fills
/// come from the vault already open in memory. (A Windows pipe opened as a
/// file has no read timeout; there the app closes a stalled connection.)
#[cfg_attr(windows, allow(dead_code))]
const REPLY_TIMEOUT: Duration = Duration::from_secs(15);

fn main() {
    // Firefox passes the manifest path and the extension id as arguments;
    // neither is needed. The app decides what to answer.
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    // One request with runtime.sendNativeMessage, several with connectNative:
    // answer until Firefox closes stdin.
    loop {
        let req = match proto::read_frame(&mut input) {
            Ok(Some(r)) => r,
            Ok(None) => return,
            Err(_) => {
                let _ = proto::write_frame(&mut output, BAD_REQUEST.as_bytes());
                return;
            }
        };
        let reply = ask_app(&req).unwrap_or_else(|_| NOT_RUNNING.as_bytes().to_vec());
        if proto::write_frame(&mut output, &reply).is_err() {
            return;
        }
    }
}

/// One request, one answer, one connection.
fn ask_app(req: &[u8]) -> io::Result<Vec<u8>> {
    let mut conn = connect()?;
    proto::write_frame(&mut conn, req)?;
    proto::read_frame(&mut conn)?.ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
}

#[cfg(unix)]
fn connect() -> io::Result<std::os::unix::net::UnixStream> {
    let path = proto::client_socket_path(&proto::Env::current());
    let s = std::os::unix::net::UnixStream::connect(path)?;
    s.set_read_timeout(Some(REPLY_TIMEOUT))?;
    s.set_write_timeout(Some(REPLY_TIMEOUT))?;
    Ok(s)
}

#[cfg(windows)]
fn connect() -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    /// SECURITY_IDENTIFICATION: the app may identify this client, not act as it.
    const SECURITY_IDENTIFICATION: u32 = 1 << 16;
    /// ERROR_PIPE_BUSY: every instance is taken; the app opens a new one at once.
    const ERROR_PIPE_BUSY: i32 = 231;
    let name = proto::pipe_name();
    let start = std::time::Instant::now();
    loop {
        match std::fs::OpenOptions::new().read(true).write(true).security_qos_flags(SECURITY_IDENTIFICATION).open(&name) {
            Ok(f) => return Ok(f),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && start.elapsed() < Duration::from_secs(2) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e),
        }
    }
}
