//! What the relay (`fidoparole-bridge`) and the FidoParole app must agree on:
//! the message framing and where the app listens. The app includes this file
//! with `#[path]`, so there is one copy of these rules.
//!
//! Framing is Firefox's native-messaging format, used on every leg: a 4-byte
//! length in native byte order, then that many bytes of UTF-8 JSON.
//!
//! Where the app listens:
//!
//! ```text
//!   Windows   \\.\pipe\fidoparole-bridge-<session id>
//!   Unix      $XDG_RUNTIME_DIR/fidoparole/bridge.sock
//!             (no XDG_RUNTIME_DIR: $TMPDIR/fidoparole/ on macOS, /tmp/fidoparole-<uid>/ elsewhere)
//!   Flatpak   $XDG_RUNTIME_DIR/app/<flatpak app id>/fidoparole-bridge.sock
//! ```
//!
//! Flatpak shares `$XDG_RUNTIME_DIR/app/<app id>` between the host and the
//! sandbox at the same path, so a relay running inside the Flatpak Firefox
//! sandbox can reach a socket the app creates there.

#![allow(dead_code)] // each side uses a different subset

use std::io::{self, Read, Write};

/// Native-messaging host name (the "name" in Firefox's host manifest).
pub const HOST_NAME: &str = "com.token2.fidoparole";
/// Gecko id of the FidoParole Firefox extension ("allowed_extensions").
pub const EXTENSION_ID: &str = "fidoparole@token2.com";
/// Largest message accepted in either direction.
pub const MAX_FRAME: usize = 64 * 1024;
/// Socket file name inside a Flatpak app's shared runtime directory.
pub const FLATPAK_SOCKET: &str = "fidoparole-bridge.sock";

// ----------------------------------------------------------------- framing --

/// Read one frame. `Ok(None)` when the input ends cleanly before a new frame.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < len.len() {
        match r.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let n = frame_len(len)?;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Length from a frame header, refusing anything above MAX_FRAME.
pub fn frame_len(header: [u8; 4]) -> io::Result<usize> {
    let n = u32::from_ne_bytes(header) as usize;
    if n > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    Ok(n)
}

/// Frame header for a message of `len` bytes.
pub fn frame_header(len: usize) -> io::Result<[u8; 4]> {
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    Ok((len as u32).to_ne_bytes())
}

pub fn write_frame(w: &mut impl Write, msg: &[u8]) -> io::Result<()> {
    w.write_all(&frame_header(msg.len())?)?;
    w.write_all(msg)?;
    w.flush()
}

// --------------------------------------------------------------- endpoints --

/// Windows: the app's named pipe for this logon session. The elevated app
/// and the relay Firefox starts share the session id.
#[cfg(windows)]
pub fn pipe_name() -> String {
    pipe_name_for(session_id())
}

#[cfg(windows)]
pub fn pipe_name_for(session: u32) -> String {
    format!(r"\\.\pipe\fidoparole-bridge-{session}")
}

#[cfg(windows)]
pub fn session_id() -> u32 {
    #[link(name = "kernel32")]
    extern "system" {
        fn ProcessIdToSessionId(pid: u32, session: *mut u32) -> i32;
    }
    let mut s = 0u32;
    if unsafe { ProcessIdToSessionId(std::process::id(), &mut s) } == 0 {
        s = 0;
    }
    s
}

/// The parts of the environment that decide the socket paths (a struct so
/// the rules can be tested).
#[cfg(unix)]
#[derive(Clone, Debug, Default)]
pub struct Env {
    pub runtime_dir: Option<std::path::PathBuf>,
    pub tmpdir: Option<std::path::PathBuf>,
    pub uid: u32,
    pub macos: bool,
    /// Set when this process runs inside a Flatpak sandbox.
    pub flatpak_id: Option<String>,
}

#[cfg(unix)]
impl Env {
    pub fn current() -> Env {
        let nonempty = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(std::path::PathBuf::from);
        Env {
            runtime_dir: nonempty("XDG_RUNTIME_DIR"),
            tmpdir: nonempty("TMPDIR"),
            uid: unsafe { libc::getuid() },
            macos: cfg!(target_os = "macos"),
            flatpak_id: flatpak_app_id(),
        }
    }

    /// `$XDG_RUNTIME_DIR`, or the systemd default for this user.
    fn runtime_dir_or_default(&self) -> std::path::PathBuf {
        self.runtime_dir.clone().unwrap_or_else(|| format!("/run/user/{}", self.uid).into())
    }
}

/// The Flatpak app id when running inside a Flatpak sandbox.
#[cfg(unix)]
pub fn flatpak_app_id() -> Option<String> {
    if let Some(id) = std::env::var("FLATPAK_ID").ok().filter(|s| !s.is_empty()) {
        return Some(id);
    }
    let info = std::fs::read_to_string("/.flatpak-info").ok()?;
    flatpak_info_name(&info)
}

/// `name=` from the `[Application]` group of a `/.flatpak-info` file.
#[cfg(unix)]
pub fn flatpak_info_name(info: &str) -> Option<String> {
    let mut in_app = false;
    for line in info.lines().map(str::trim) {
        if line.starts_with('[') {
            in_app = line == "[Application]";
        } else if in_app {
            if let Some(v) = line.strip_prefix("name=") {
                let v = v.trim();
                if !v.is_empty() { return Some(v.to_string()); }
            }
        }
    }
    None
}

/// Directory holding the app's own (non-Flatpak) socket.
#[cfg(unix)]
pub fn host_socket_dir(env: &Env) -> std::path::PathBuf {
    match (&env.runtime_dir, &env.tmpdir) {
        (Some(rt), _) => rt.join("fidoparole"),
        (None, Some(tmp)) if env.macos => tmp.join("fidoparole"),
        _ => format!("/tmp/fidoparole-{}", env.uid).into(),
    }
}

#[cfg(unix)]
pub fn host_socket_path(env: &Env) -> std::path::PathBuf {
    host_socket_dir(env).join("bridge.sock")
}

/// The socket offered to the Flatpak app `app_id`, as a path that is the same
/// on the host and inside the sandbox.
#[cfg(unix)]
pub fn flatpak_socket_path(env: &Env, app_id: &str) -> std::path::PathBuf {
    env.runtime_dir_or_default().join("app").join(app_id).join(FLATPAK_SOCKET)
}

/// The socket the relay connects to.
#[cfg(unix)]
pub fn client_socket_path(env: &Env) -> std::path::PathBuf {
    match &env.flatpak_id {
        Some(id) => flatpak_socket_path(env, id),
        None => host_socket_path(env),
    }
}

// ------------------------------------------------------------------- tests --

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, br#"{"op":"status"}"#).unwrap();
        write_frame(&mut buf, b"").unwrap();
        assert_eq!(&buf[..4], &15u32.to_ne_bytes());
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), br#"{"op":"status"}"#);
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), b"");
        assert!(read_frame(&mut r).unwrap().is_none(), "clean end of input");
    }

    #[test]
    fn frame_errors() {
        // Too large, both ways.
        let mut r = &((MAX_FRAME as u32) + 1).to_ne_bytes()[..];
        assert!(read_frame(&mut r).is_err());
        assert!(write_frame(&mut Vec::new(), &vec![b'x'; MAX_FRAME + 1]).is_err());
        // Truncated header and truncated body.
        let mut r = &[1u8, 0][..];
        assert!(read_frame(&mut r).is_err());
        let mut b = 10u32.to_ne_bytes().to_vec();
        b.extend_from_slice(b"abc");
        assert!(read_frame(&mut &b[..]).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn pipe_names() {
        assert_eq!(pipe_name_for(3), r"\\.\pipe\fidoparole-bridge-3");
        assert!(pipe_name().starts_with(r"\\.\pipe\fidoparole-bridge-"));
    }

    #[cfg(unix)]
    #[test]
    fn socket_paths() {
        use std::path::Path;
        let linux = Env { runtime_dir: Some("/run/user/1000".into()), uid: 1000, ..Default::default() };
        assert_eq!(host_socket_path(&linux), Path::new("/run/user/1000/fidoparole/bridge.sock"));
        assert_eq!(client_socket_path(&linux), host_socket_path(&linux));
        assert_eq!(flatpak_socket_path(&linux, "org.mozilla.firefox"),
            Path::new("/run/user/1000/app/org.mozilla.firefox/fidoparole-bridge.sock"));

        // Inside the Flatpak sandbox the relay picks the shared directory.
        let sandbox = Env { flatpak_id: Some("org.mozilla.firefox".into()), ..linux.clone() };
        assert_eq!(client_socket_path(&sandbox), flatpak_socket_path(&linux, "org.mozilla.firefox"));
        let sandbox_no_rt = Env { runtime_dir: None, ..sandbox };
        assert_eq!(client_socket_path(&sandbox_no_rt),
            Path::new("/run/user/1000/app/org.mozilla.firefox/fidoparole-bridge.sock"));

        let bare = Env { uid: 1000, ..Default::default() };
        assert_eq!(host_socket_path(&bare), Path::new("/tmp/fidoparole-1000/bridge.sock"));
        let mac = Env { tmpdir: Some("/var/folders/xy/T".into()), macos: true, uid: 501, ..Default::default() };
        assert_eq!(host_socket_path(&mac), Path::new("/var/folders/xy/T/fidoparole/bridge.sock"));
    }

    #[cfg(unix)]
    #[test]
    fn flatpak_info() {
        let info = "[Application]\nname=org.mozilla.firefox\nruntime=runtime/org.freedesktop.Platform/x86_64/24.08\n\n[Instance]\nname=other\n";
        assert_eq!(flatpak_info_name(info).as_deref(), Some("org.mozilla.firefox"));
        assert_eq!(flatpak_info_name("[Instance]\nname=x\n"), None);
    }
}
