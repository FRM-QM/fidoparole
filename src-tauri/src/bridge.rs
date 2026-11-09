//! Browser bridge: lets the FidoParole Firefox extension fill logins from the
//! vault that is open in this app.
//!
//! Firefox starts the relay `fidoparole-bridge` (native messaging). The relay
//! forwards each request over a per-user local pipe / socket to the server
//! here, which answers from the open session:
//!
//! * `status`: disabled / locked / unlocked (+ vault name),
//! * `list`:   the entries whose Website matches the page — no passwords,
//! * `fill`:   one entry's username and password, after checking again that it
//!             matches the page. Every fill is shown in the app.
//!
//! Nothing but `status` is answered unless the user turned on Firefox autofill
//! in the settings and a vault is unlocked. `status` and `list` don't count as
//! activity, so browsing alone never keeps the vault from auto-locking.
//!
//! Framing and endpoints are shared with the relay: `bridge/src/proto.rs`.

#[path = "../../bridge/src/proto.rs"]
mod proto;

use crate::commands::{AppState, Inner, Session};
use crate::urlmatch::{self, Page};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

type R<T> = Result<T, String>;

/// How long a connection may take to send its request or read the answer.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Flatpak builds of Firefox that get a socket and a registration of their own.
#[cfg(unix)]
const FLATPAK_FIREFOX: &[&str] = &["org.mozilla.firefox"];
const RELAY_FILE: &str = if cfg!(windows) { "fidoparole-bridge.exe" } else { "fidoparole-bridge" };

/// Problems starting the listeners, shown in the settings.
#[derive(Default)]
pub struct BridgeInfo(Mutex<BridgeInner>);

#[derive(Default)]
struct BridgeInner {
    errors: Vec<String>,
    /// Flatpak app ids whose listener has been started.
    #[cfg(unix)]
    flatpak: Vec<String>,
}

// ---------------------------------------------------------------- requests --

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    v: u32,
    op: String,
    #[serde(default)]
    origin: String,
    #[serde(default)]
    id: String,
}

type Reply = Zeroizing<Vec<u8>>;

fn reply(v: &impl Serialize) -> Reply {
    let mut out = Zeroizing::new(Vec::with_capacity(512));
    if serde_json::to_writer(&mut *out, v).is_err() {
        return refuse("internal", "could not encode the answer");
    }
    out
}

fn refuse(code: &str, message: &str) -> Reply {
    reply(&serde_json::json!({ "ok": false, "error": code, "message": message }))
}

/// The open session, if Firefox may use it.
fn usable(g: &Inner) -> Result<&Session, Reply> {
    if !g.settings.browser_autofill {
        return Err(refuse("disabled", "Firefox autofill is turned off in FidoParole's settings."));
    }
    g.session.as_ref().ok_or_else(|| refuse("locked", "Unlock your vault in FidoParole."))
}

/// Answer one request (already unframed).
fn handle(app: &AppHandle, req: &[u8]) -> Reply {
    let Ok(r) = serde_json::from_slice::<Request>(req) else {
        return refuse("bad_request", "The request could not be read.");
    };
    if r.v != 1 {
        return refuse("bad_request", "Unsupported request version: update FidoParole and its Firefox extension.");
    }
    let state = app.state::<AppState>();
    match r.op.as_str() {
        "status" => status_reply(&state),
        "list" => list(&state, &r.origin),
        "fill" => fill(app, &state, &r.origin, &r.id),
        _ => refuse("bad_request", "Unknown request."),
    }
}

fn status_reply(state: &AppState) -> Reply {
    // Not AppState::lock(): asking must not count as activity.
    let Ok(g) = state.0.lock() else { return refuse("internal", "internal error") };
    if !g.settings.browser_autofill {
        return reply(&serde_json::json!({ "ok": true, "state": "disabled" }));
    }
    match &g.session {
        Some(s) => reply(&serde_json::json!({ "ok": true, "state": "unlocked", "vault": s.cred.name })),
        None => reply(&serde_json::json!({ "ok": true, "state": "locked" })),
    }
}

#[derive(Serialize)]
struct Listed<'a> {
    id: &'a str,
    title: &'a str,
    username: &'a str,
}

fn list(state: &AppState, origin: &str) -> Reply {
    let Some(page) = Page::parse(origin) else { return refuse("bad_request", "Logins are only offered on http(s) pages.") };
    let Ok(g) = state.0.lock() else { return refuse("internal", "internal error") };
    let s = match usable(&g) { Ok(s) => s, Err(r) => return r };
    let mut entries: Vec<Listed> = s.data.entries.iter()
        .filter(|e| urlmatch::matches(&e.url, &page))
        .map(|e| Listed { id: &e.id, title: &e.title, username: &e.username })
        .collect();
    entries.sort_by_key(|e| e.title.to_lowercase());
    reply(&serde_json::json!({ "ok": true, "host": page.host(), "entries": entries }))
}

#[derive(Serialize)]
struct Filled<'a> {
    ok: bool,
    username: &'a str,
    password: &'a str,
}

fn fill(app: &AppHandle, state: &AppState, origin: &str, id: &str) -> Reply {
    let Some(page) = Page::parse(origin) else { return refuse("bad_request", "Logins are only filled into http(s) pages.") };
    let (out, title) = {
        let Ok(mut g) = state.0.lock() else { return refuse("internal", "internal error") };
        let s = match usable(&g) { Ok(s) => s, Err(r) => return r };
        let Some(e) = s.data.entries.iter().find(|e| e.id == id) else {
            return refuse("no_match", "That login is no longer in the vault.");
        };
        if !urlmatch::matches(&e.url, &page) {
            return refuse("no_match", &if urlmatch::matches(&e.url, &page.as_https()) {
                format!("That login is saved for https://{}; this page is not encrypted (http).", page.host())
            } else {
                format!("That login is not for {}.", page.host())
            });
        }
        let out = reply(&Filled { ok: true, username: &e.username, password: &e.password });
        let title = e.title.clone();
        // A fill is the user at work: it counts as activity, like the app's own UI.
        g.mark_activity();
        (out, title)
    };
    let _ = app.emit("bridge-fill", serde_json::json!({ "title": title, "host": page.host() }));
    out
}

// --------------------------------------------------------------- transport --

async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await?;
    let mut b = Zeroizing::new(vec![0u8; proto::frame_len(h)?]);
    s.read_exact(&mut b).await?;
    Ok(b)
}

async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, msg: &[u8]) -> io::Result<()> {
    s.write_all(&proto::frame_header(msg.len())?).await?;
    s.write_all(msg).await?;
    s.flush().await
}

/// One request and one answer per connection.
async fn serve_conn<S: AsyncRead + AsyncWrite + Unpin>(app: AppHandle, mut s: S) {
    let Ok(Ok(req)) = tokio::time::timeout(IO_TIMEOUT, read_frame(&mut s)).await else { return };
    let out = handle(&app, &req);
    if !matches!(tokio::time::timeout(IO_TIMEOUT, write_frame(&mut s, &out)).await, Ok(Ok(()))) {
        return;
    }
    drop(out);
    // Let the relay read the answer and hang up first, so closing our end
    // can't discard what is still in the pipe.
    let mut b = [0u8; 1];
    let _ = tokio::time::timeout(IO_TIMEOUT, s.read(&mut b)).await;
}

fn record_error(app: &AppHandle, msg: String) {
    eprintln!("browser bridge: {msg}");
    if let Ok(mut g) = app.state::<BridgeInfo>().0.lock() {
        g.errors.push(msg);
    }
}

fn spawn_listener(app: &AppHandle, what: String, fut: impl Future<Output = io::Result<()>> + Send + 'static) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(e) = fut.await {
            record_error(&app, format!("{what}: {e}"));
        }
    });
}

/// Start the listeners (at app start). They run until the app exits.
pub fn start(app: &AppHandle) {
    #[cfg(windows)]
    spawn_listener(app, "Firefox connection".into(), pipe::serve(app.clone()));
    #[cfg(unix)]
    {
        let env = proto::Env::current();
        spawn_listener(app, "Firefox connection".into(), unix::serve(app.clone(), proto::host_socket_path(&env)));
        for id in flatpak_firefoxes() {
            start_flatpak(app, id);
        }
        // Keep the relay copied into a Flatpak sandbox in step with this build.
        for spot in spots().unwrap_or_default() {
            if let (Some(from), true) = (&spot.copy_from, spot.manifest.is_file()) {
                if std::fs::read(from).ok() != std::fs::read(&spot.relay).ok() {
                    let _ = install_relay(from, &spot.relay);
                }
            }
        }
    }
}

#[cfg(unix)]
fn start_flatpak(app: &AppHandle, id: &'static str) {
    {
        let info = app.state::<BridgeInfo>();
        let Ok(mut g) = info.0.lock() else { return };
        if g.flatpak.iter().any(|x| x == id) { return; }
        g.flatpak.push(id.to_string());
    }
    let path = proto::flatpak_socket_path(&proto::Env::current(), id);
    spawn_listener(app, "Firefox (Flatpak) connection".into(), unix::serve(app.clone(), path));
}

#[cfg(windows)]
mod pipe {
    use super::*;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    /// One pipe instance, open to this user (and SYSTEM) only. The explicit
    /// Medium integrity label lets the relay Firefox starts (not elevated)
    /// reach the elevated app. `first`: fail if the name is already taken, so
    /// no other program can sit on the pipe before the app starts.
    fn create(name: &str, first: bool) -> io::Result<NamedPipeServer> {
        let sid = crate::platform::user_sid_string().ok_or_else(|| io::Error::other("cannot read this user's SID"))?;
        let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid})(A;;GA;;;SY)S:(ML;;NW;;;ME)").encode_utf16().chain(Some(0)).collect();
        let mut psd = PSECURITY_DESCRIPTOR::default();
        unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut psd, None) }
            .map_err(io::Error::other)?;
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd.0,
            bInheritHandle: false.into(),
        };
        let r = unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(name, &mut sa as *mut SECURITY_ATTRIBUTES as *mut std::ffi::c_void)
        };
        unsafe { LocalFree(Some(HLOCAL(psd.0))) };
        r
    }

    pub async fn serve(app: AppHandle) -> io::Result<()> {
        let name = proto::pipe_name();
        let mut server = create(&name, true).map_err(|e| {
            if e.raw_os_error() == Some(5) {
                io::Error::other("the pipe name is taken — is FidoParole already running?")
            } else { e }
        })?;
        loop {
            let connected = server.connect().await;
            // Always keep a listening instance, so the name is never free.
            let next = create(&name, false)?;
            let conn = std::mem::replace(&mut server, next);
            if connected.is_ok() {
                tauri::async_runtime::spawn(serve_conn(app.clone(), conn));
            }
        }
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    /// Bind `path` in a private (0700) directory owned by this user. A stale
    /// socket left by a crash is replaced; a live one means another FidoParole
    /// is serving already.
    fn bind(path: &Path) -> io::Result<tokio::net::UnixListener> {
        let uid = unsafe { libc::getuid() };
        let dir = path.parent().ok_or_else(|| io::Error::other("bad socket path"))?;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let md = std::fs::symlink_metadata(dir)?;
        if !md.is_dir() || md.uid() != uid {
            return Err(io::Error::other(format!("{} is not a directory of this user", dir.display())));
        }
        if md.mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        if std::fs::symlink_metadata(path).is_ok() {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(io::ErrorKind::AddrInUse, "another FidoParole is already serving Firefox"));
            }
            std::fs::remove_file(path)?;
        }
        let l = tokio::net::UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(l)
    }

    pub async fn serve(app: AppHandle, path: PathBuf) -> io::Result<()> {
        let listener = bind(&path)?;
        let uid = unsafe { libc::getuid() };
        loop {
            let s = match listener.accept().await {
                Ok((s, _)) => s,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            // Only this user's processes (a Flatpak sandbox keeps the uid).
            if !matches!(s.peer_cred(), Ok(c) if c.uid() == uid) {
                continue;
            }
            tauri::async_runtime::spawn(serve_conn(app.clone(), s));
        }
    }
}

// ------------------------------------------------------------ registration --

/// One place Firefox looks for our native-messaging host.
struct Spot {
    label: String,
    /// The host manifest file.
    manifest: PathBuf,
    /// The relay path written into the manifest.
    relay: PathBuf,
    /// Flatpak: the relay is copied from here into the sandbox's data folder.
    copy_from: Option<PathBuf>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    label: String,
    registered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStatus {
    enabled: bool,
    extension_id: &'static str,
    targets: Vec<Target>,
    errors: Vec<String>,
}

/// The relay next to this program's executable.
fn relay_source() -> R<PathBuf> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let p = exe.with_file_name(RELAY_FILE);
    if p.is_file() {
        Ok(p)
    } else {
        Err(format!("{RELAY_FILE} is missing next to {}. Build FidoParole with build.ps1 / build.sh, which puts it there.", exe.display()))
    }
}

fn manifest_json(relay: &Path) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "name": proto::HOST_NAME,
        "description": "FidoParole: fill logins from the vault on your FIDO2 key",
        "path": relay,
        "type": "stdio",
        "allowed_extensions": [proto::EXTENSION_ID],
    }))
    .unwrap_or_default()
}

#[cfg(unix)]
fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from)
}

/// Flatpak Firefox builds installed for this user (they have a data folder).
#[cfg(unix)]
fn flatpak_firefoxes() -> Vec<&'static str> {
    let Some(h) = home() else { return vec![] };
    FLATPAK_FIREFOX.iter().copied().filter(|id| h.join(".var/app").join(id).is_dir()).collect()
}

fn spots() -> R<Vec<Spot>> {
    let relay = relay_source()?;
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        let dir = std::env::var_os("APPDATA").map(PathBuf::from).ok_or("APPDATA is not set")?.join("com.token2.fidoparole");
        out.push(Spot { label: "Firefox".into(), manifest: dir.join("firefox-native-host.json"), relay, copy_from: None });
    }
    #[cfg(unix)]
    {
        let h = home().ok_or("HOME is not set")?;
        let dir = if cfg!(target_os = "macos") {
            h.join("Library/Application Support/Mozilla/NativeMessagingHosts")
        } else {
            // Deb / tarball Firefox; the snap's portal reads this file too.
            h.join(".mozilla/native-messaging-hosts")
        };
        out.push(Spot { label: "Firefox".into(), manifest: dir.join(format!("{}.json", proto::HOST_NAME)), relay: relay.clone(), copy_from: None });
        // Flatpak Firefox runs the host inside its sandbox: it reads the
        // manifest from its own ~/.mozilla and can't see this folder, so the
        // relay is copied into the app's data folder (same path in and out).
        for id in flatpak_firefoxes() {
            let base = h.join(".var/app").join(id);
            out.push(Spot {
                label: if id == "org.mozilla.firefox" { "Firefox (Flatpak)".into() } else { format!("Flatpak {id}") },
                manifest: base.join(".mozilla/native-messaging-hosts").join(format!("{}.json", proto::HOST_NAME)),
                relay: base.join("data/fidoparole").join(RELAY_FILE),
                copy_from: Some(relay.clone()),
            });
        }
    }
    Ok(out)
}

/// Does `spot` point Firefox at our relay?
fn is_registered(spot: &Spot) -> bool {
    let Ok(text) = std::fs::read_to_string(&spot.manifest) else { return false };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { return false };
    let points_here = v.get("path").and_then(|p| p.as_str()).map(Path::new) == Some(spot.relay.as_path());
    let ours = v.get("allowed_extensions").and_then(|a| a.as_array())
        .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(proto::EXTENSION_ID)));
    #[cfg(windows)]
    let points_here = points_here && registry::get().as_deref().map(Path::new) == Some(spot.manifest.as_path());
    points_here && ours && spot.relay.is_file()
}

/// Copy the relay (atomically, executable) to `to`.
fn install_relay(from: &Path, to: &Path) -> R<()> {
    let dir = to.parent().ok_or("bad relay path")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = to.with_extension("new");
    std::fs::copy(from, &tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, to).map_err(|e| format!("{}: {e}", to.display()))
}

/// Linux: a relay that needs a dynamic loader may not run inside the Flatpak
/// sandbox (different libc). Some(true) = dynamically linked ELF.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn elf_is_dynamic(b: &[u8]) -> Option<bool> {
    if b.len() < 64 || &b[..4] != b"\x7fELF" { return None; }
    let le = b[5] == 1;
    let u16_at = |o: usize| b.get(o..o + 2).map(|x| if le { u16::from_le_bytes([x[0], x[1]]) } else { u16::from_be_bytes([x[0], x[1]]) });
    let u32_at = |o: usize| b.get(o..o + 4).map(|x| { let a = [x[0], x[1], x[2], x[3]]; if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) } });
    let u64_at = |o: usize| b.get(o..o + 8).map(|x| { let a: [u8; 8] = x.try_into().unwrap(); if le { u64::from_le_bytes(a) } else { u64::from_be_bytes(a) } });
    let (phoff, phentsize, phnum) = match b[4] {
        1 => (u32_at(0x1c)? as usize, u16_at(0x2a)? as usize, u16_at(0x2c)? as usize),
        2 => (u64_at(0x20)? as usize, u16_at(0x36)? as usize, u16_at(0x38)? as usize),
        _ => return None,
    };
    const PT_INTERP: u32 = 3;
    for i in 0..phnum {
        if u32_at(phoff.checked_add(i.checked_mul(phentsize)?)?)? == PT_INTERP {
            return Some(true);
        }
    }
    Some(false)
}

fn spot_warning(spot: &Spot) -> Option<String> {
    let from = spot.copy_from.as_ref()?;
    match std::fs::read(from).ok().as_deref().and_then(elf_is_dynamic) {
        Some(true) => Some(format!(
            "{RELAY_FILE} is dynamically linked, so it may not start inside the Flatpak sandbox. \
             Build it static: rustup target add x86_64-unknown-linux-musl, then run build.sh again."
        )),
        _ => None,
    }
}

pub fn status(app: &AppHandle, enabled: bool) -> BrowserStatus {
    let mut errors = app.state::<BridgeInfo>().0.lock().map(|g| g.errors.clone()).unwrap_or_default();
    let targets = match spots() {
        Ok(spots) => spots.iter().map(|s| Target { label: s.label.clone(), registered: is_registered(s), warning: spot_warning(s) }).collect(),
        Err(e) => {
            errors.push(e);
            vec![]
        }
    };
    BrowserStatus { enabled, extension_id: proto::EXTENSION_ID, targets, errors }
}

/// Tell every Firefox found where the relay is. Returns the labels registered.
pub fn register(app: &AppHandle) -> R<Vec<String>> {
    let mut done = Vec::new();
    for spot in spots()? {
        if let Some(from) = &spot.copy_from {
            install_relay(from, &spot.relay)?;
        }
        let dir = spot.manifest.parent().ok_or("bad manifest path")?;
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        std::fs::write(&spot.manifest, manifest_json(&spot.relay)).map_err(|e| format!("{}: {e}", spot.manifest.display()))?;
        #[cfg(windows)]
        registry::set(&spot.manifest)?;
        done.push(spot.label);
    }
    #[cfg(unix)]
    for id in flatpak_firefoxes() {
        start_flatpak(app, id);
    }
    let _ = app;
    Ok(done)
}

#[cfg(windows)]
mod registry {
    use super::R;
    use std::path::Path;
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegGetValueW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE,
        REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
    };

    const KEY: &str = r"Software\Mozilla\NativeMessagingHosts\com.token2.fidoparole";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// HKCU\…\NativeMessagingHosts\<host> (default value) = manifest path.
    pub fn set(manifest: &Path) -> R<()> {
        let key = wide(KEY);
        let val = wide(&manifest.to_string_lossy());
        let mut hk = HKEY::default();
        unsafe {
            RegCreateKeyExW(HKEY_CURRENT_USER, PCWSTR(key.as_ptr()), None, PCWSTR::null(), REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, None, &mut hk, None)
                .ok()
                .map_err(|e| format!("registry: {e}"))?;
            let bytes = std::slice::from_raw_parts(val.as_ptr() as *const u8, val.len() * 2);
            let r = RegSetValueExW(hk, PCWSTR::null(), None, REG_SZ, Some(bytes));
            let _ = RegCloseKey(hk);
            r.ok().map_err(|e| format!("registry: {e}"))
        }
    }

    pub fn get() -> Option<String> {
        let key = wide(KEY);
        let mut buf = vec![0u16; 1024];
        let mut len = (buf.len() * 2) as u32;
        unsafe {
            RegGetValueW(HKEY_CURRENT_USER, PCWSTR(key.as_ptr()), PCWSTR::null(), RRF_RT_REG_SZ, None, Some(buf.as_mut_ptr() as *mut _), Some(&mut len))
                .ok()
                .ok()?;
        }
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..n]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_points_at_relay() {
        let p = if cfg!(windows) { PathBuf::from(r"C:\Apps\FidoParole\fidoparole-bridge.exe") } else { PathBuf::from("/opt/fidoparole/fidoparole-bridge") };
        let v: serde_json::Value = serde_json::from_str(&manifest_json(&p)).unwrap();
        assert_eq!(v["name"], "com.token2.fidoparole");
        assert_eq!(v["type"], "stdio");
        assert_eq!(v["path"].as_str().map(Path::new), Some(p.as_path()));
        assert_eq!(v["allowed_extensions"][0], "fidoparole@token2.com");
    }

    #[test]
    fn elf_detection() {
        // Minimal 64-bit little-endian ELF header with one program header.
        let mut b = vec![0u8; 0x40 + 0x38];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&0x38u16.to_le_bytes());
        b[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
        b[0x40..0x44].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        assert_eq!(elf_is_dynamic(&b), Some(false));
        b[0x40..0x44].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        assert_eq!(elf_is_dynamic(&b), Some(true));
        assert_eq!(elf_is_dynamic(b"MZ not an elf file at all, padding padding padding padding pad"), None);
        // Program headers pointing past the end: not trusted.
        b[0x20..0x28].copy_from_slice(&0xffffu64.to_le_bytes());
        assert_eq!(elf_is_dynamic(&b), None);
    }
}
