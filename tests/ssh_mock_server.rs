//! In-process mock SSH server for integration tests.
//!
//! This file is intentionally NOT a test runner — it only exposes helper
//! types used by `ssh_client_mock.rs` and `sftp_mock.rs`. The single
//! `#[test]` at the bottom is just a smoke check so cargo doesn't warn
//! that this binary contains zero tests.
//!
//! The server is built on `russh::server::Server` + `russh_sftp::server::run`
//! and binds on `127.0.0.1:0` (ephemeral port) so concurrent tests do not
//! collide. A fresh ed25519 host key is generated per server from a
//! deterministic seed (no on-disk PEM, no rand dep).
//!
//! # Helpers
//!
//! - [`MockSshServer::start`] — build + spawn, returns ([`SocketAddr`],
//!   [`MockServerHandle`])
//! - [`MockServerHandle::shutdown`] — graceful stop via `CancellationToken`
//! - [`mock_host_config`] — `HostConfig` pointing at `127.0.0.1:<port>`
//!   with `HostKeyVerification::Off`
//! - [`mock_limits`] — short-timeout `LimitsConfig` for fast tests
//!
//! # SFTP backend
//!
//! The mock SFTP handler is filesystem-backed — it routes requests to a
//! `tempfile::TempDir` so `upload_file` / `download_file` / `read_dir` /
//! `mkdir_recursive` actually round-trip real bytes.

#![allow(dead_code)] // Helpers may be unused depending on which test binary links them.
#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::ignored_unit_patterns,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::return_self_not_must_use
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bridge_mcp::config::{
    AuthConfig, HostConfig, HostKeyVerification, LimitsConfig, OsType, Protocol, RedactedSecret,
};
use russh::keys::PrivateKey;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::server::{Auth, Config as ServerConfig, Handler as ServerHandler, Msg, Server, Session};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{
    Attrs, Data, File as SftpFile, FileAttributes, Handle as SftpHandle, Name, OpenFlags, Status,
    StatusCode, Version,
};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

// ============================================================================
// Behaviour configuration: what `exec_request` should return.
// ============================================================================

/// Stdout/exit_code returned for an `exec_request`.
///
/// Tests configure this via [`MockSshServerBuilder::exec_response`]. The
/// built-in default is `("", 0)` — an empty stdout and exit code 0.
#[derive(Clone, Debug)]
pub struct ExecResponse {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: u32,
}

impl ExecResponse {
    pub fn ok(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: Vec::new(),
            exit_code: 0,
        }
    }
}

/// Either accept a password (`user`, `password`) or reject everything.
#[derive(Clone, Debug)]
pub struct AuthCreds {
    pub user: String,
    pub password: String,
}

// ============================================================================
// Public handle returned to tests.
// ============================================================================

/// Owns the cancellation token that stops the spawned server task.
///
/// Drop or call [`Self::shutdown`] explicitly to stop the listener.
pub struct MockServerHandle {
    cancel: CancellationToken,
}

impl MockServerHandle {
    /// Trigger a graceful shutdown of the server. Idempotent.
    ///
    /// Cancels the accept loop and signals the per-connection drivers to send
    /// an SSH `Disconnect` to the client before tearing down the transport.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

impl Drop for MockServerHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Shared list of live per-connection handles, used by the accept loop to
/// send a graceful disconnect on shutdown.
type SessionHandles = Arc<Mutex<Vec<russh::server::Handle>>>;

// ============================================================================
// Builder + start.
// ============================================================================

pub struct MockSshServerBuilder {
    creds: AuthCreds,
    exec_response: ExecResponse,
    sftp_root: Option<Arc<TempDir>>,
}

impl MockSshServerBuilder {
    pub fn new() -> Self {
        Self {
            creds: AuthCreds {
                user: "tester".into(),
                password: "testpass".into(),
            },
            exec_response: ExecResponse::ok("ok\n"),
            sftp_root: None,
        }
    }

    pub fn creds(mut self, user: &str, password: &str) -> Self {
        self.creds = AuthCreds {
            user: user.into(),
            password: password.into(),
        };
        self
    }

    pub fn exec_response(mut self, resp: ExecResponse) -> Self {
        self.exec_response = resp;
        self
    }

    /// Use the supplied `TempDir` as the SFTP root. If unset, a fresh
    /// `TempDir` is created on `start()`.
    pub fn sftp_root(mut self, root: Arc<TempDir>) -> Self {
        self.sftp_root = Some(root);
        self
    }

    /// Bind on `127.0.0.1:0` and spawn the listener.
    ///
    /// Returns `(addr, handle, sftp_root)` — `sftp_root` is the temp dir
    /// the SFTP handler uses as its filesystem; tests can poke at it
    /// directly to assert post-conditions.
    pub async fn start(self) -> (SocketAddr, MockServerHandle, Arc<TempDir>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind 127.0.0.1:0");
        let addr = listener.local_addr().expect("local_addr");

        let cancel = CancellationToken::new();
        let cancel_inner = cancel.clone();

        let sftp_root = self
            .sftp_root
            .unwrap_or_else(|| Arc::new(tempfile::tempdir().expect("tempdir")));

        let creds = self.creds.clone();
        let exec_response = self.exec_response.clone();
        let sftp_root_for_task = sftp_root.clone();

        // russh's Server trait works on `&TcpListener` and runs forever;
        // we wrap it in a `select!` against the cancel token so tests can
        // tear down deterministically.
        tokio::spawn(async move {
            let host_key = generate_ed25519_host_key();
            let config = Arc::new(ServerConfig {
                inactivity_timeout: Some(Duration::from_secs(30)),
                auth_rejection_time: Duration::from_millis(50),
                auth_rejection_time_initial: Some(Duration::from_millis(0)),
                keys: vec![host_key],
                ..Default::default()
            });

            let mut server = MockServer {
                creds,
                exec_response,
                sftp_root: sftp_root_for_task,
            };

            // Manual accept loop — gives us a clean shutdown path without
            // depending on `RunningServerHandle`. Per-connection drivers are
            // tracked in a `JoinSet` and their session `Handle`s are kept
            // in a shared `Vec` so `shutdown()` can send an SSH disconnect
            // to each live client, not just stop accepting new ones.
            //
            // `russh::server::run_stream` spawns the actual session loop in
            // an internal `tokio::task` and returns a `RunningSession` whose
            // `JoinHandle` *detaches* on drop. Aborting the wrapper here is
            // therefore insufficient to kill an established session — we
            // must talk to the session via its `Handle::disconnect`.
            let session_handles: SessionHandles = Arc::new(Mutex::new(Vec::new()));
            let mut conns: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = cancel_inner.cancelled() => {
                        // Drain live session handles and tell each peer to
                        // disconnect. After that, abort the connection drivers
                        // and break out of the accept loop.
                        let handles = {
                            let mut guard = session_handles.lock().await;
                            std::mem::take(&mut *guard)
                        };
                        for h in handles {
                            let _ = h
                                .disconnect(
                                    russh::Disconnect::ByApplication,
                                    String::new(),
                                    String::new(),
                                )
                                .await;
                        }
                        conns.abort_all();
                        break;
                    }
                    accept = listener.accept() => {
                        let Ok((sock, peer)) = accept else { break };
                        let cfg = config.clone();
                        let handler = server.new_client(Some(peer));
                        let session_handles = session_handles.clone();
                        conns.spawn(async move {
                            // Best-effort: ignore connection-level errors;
                            // tests assert from the client side.
                            if let Ok(running) =
                                russh::server::run_stream(cfg, sock, handler).await
                            {
                                session_handles.lock().await.push(running.handle());
                                let _ = running.await;
                            }
                        });
                    }
                }
            }
        });

        (addr, MockServerHandle { cancel }, sftp_root)
    }
}

impl Default for MockSshServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience: same as `MockSshServerBuilder::new().start()`.
pub async fn start_default_server() -> (SocketAddr, MockServerHandle, Arc<TempDir>) {
    MockSshServerBuilder::new().start().await
}

// ============================================================================
// HostConfig / LimitsConfig builders.
// ============================================================================

pub fn mock_host_config(addr: SocketAddr, user: &str, password: &str) -> HostConfig {
    HostConfig {
        hostname: addr.ip().to_string(),
        port: addr.port(),
        user: user.to_string(),
        auth: AuthConfig::Password {
            password: RedactedSecret::from(password),
        },
        description: Some("mock SSH server".into()),
        // `Off` so we don't touch ~/.ssh/known_hosts during tests.
        host_key_verification: HostKeyVerification::Off,
        proxy_jump: None,
        socks_proxy: None,
        sudo_password: None,
        tags: Vec::new(),
        os_type: OsType::Linux,
        shell: None,
        retry: None,
        protocol: Protocol::default(),

        #[cfg(feature = "winrm")]
        winrm_use_tls: None,
        #[cfg(feature = "winrm")]
        winrm_accept_invalid_certs: None,
        #[cfg(feature = "winrm")]
        winrm_operation_timeout_secs: None,
        #[cfg(feature = "winrm")]
        winrm_max_envelope_size: None,
    }
}

pub fn mock_limits() -> LimitsConfig {
    LimitsConfig {
        command_timeout_seconds: 10,
        connection_timeout_seconds: 10,
        keepalive_interval_seconds: 30,
        max_output_bytes: 1024 * 1024,
        max_concurrent_commands: 5,
        retry_attempts: 0,
        retry_initial_delay_ms: 50,
        rate_limit_per_second: 0,
        ..LimitsConfig::default()
    }
}

// ============================================================================
// Internal: deterministic ed25519 host key (no rand dep).
// ============================================================================

/// Generate a fresh ed25519 host key from a static seed. Different test
/// binaries (and the bundled smoke test below) call this; the seed is the
/// same so the resulting key is identical, but every server allocates its
/// own `PrivateKey` so there's no shared mutable state.
fn generate_ed25519_host_key() -> PrivateKey {
    // Static seed — keys are throwaway; we only care that they parse.
    let seed = [0xA5u8; 32];
    let keypair = Ed25519Keypair::from_seed(&seed);
    PrivateKey::new(KeypairData::from(keypair), "mock-host-key")
        .expect("build PrivateKey from Ed25519Keypair")
}

// ============================================================================
// russh server impl.
// ============================================================================

#[derive(Clone)]
struct MockServer {
    creds: AuthCreds,
    exec_response: ExecResponse,
    sftp_root: Arc<TempDir>,
}

impl Server for MockServer {
    type Handler = MockSession;

    fn new_client(&mut self, _peer: Option<SocketAddr>) -> Self::Handler {
        MockSession {
            creds: self.creds.clone(),
            exec_response: self.exec_response.clone(),
            sftp_root: self.sftp_root.clone(),
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

struct MockSession {
    creds: AuthCreds,
    exec_response: ExecResponse,
    sftp_root: Arc<TempDir>,
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl ServerHandler for MockSession {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == self.creds.user && password == self.creds.password {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let mut chans = self.channels.lock().await;
        chans.insert(channel.id(), channel);
        Ok(true)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let resp = self.exec_response.clone();
        let handle = session.handle();
        // Inform the client that the exec request succeeded.
        session.channel_success(channel)?;

        // Spawn so we don't block the read loop while sending output.
        tokio::spawn(async move {
            // Stdout. `Handle::data` takes `impl Into<bytes::Bytes>` but
            // russh also impls `From<Vec<u8>>` for its own `CryptoVec`,
            // so a bare `.into()` is ambiguous. Force the conversion via
            // the `tokio_util::bytes::Bytes` reexport (no extra dev-dep).
            if !resp.stdout.is_empty() {
                let bytes: tokio_util::bytes::Bytes = resp.stdout.into();
                let _ = handle.data(channel, bytes).await;
            }
            // Stderr (extended data, code 1)
            if !resp.stderr.is_empty() {
                let bytes: tokio_util::bytes::Bytes = resp.stderr.into();
                let _ = handle.extended_data(channel, 1, bytes).await;
            }
            // Exit status THEN EOF THEN close, matching how a real sshd
            // closes a one-shot exec channel. The client (`SshClient::exec`)
            // loops until `wait()` returns `None`.
            let _ = handle.exit_status_request(channel, resp.exit_code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            session.channel_failure(channel)?;
            return Ok(());
        }

        // Take ownership of the channel and run the SFTP server on its stream.
        let chan = {
            let mut chans = self.channels.lock().await;
            chans.remove(&channel)
        };
        let Some(chan) = chan else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        session.channel_success(channel)?;
        let sftp = MockSftpSession::new(self.sftp_root.clone());
        russh_sftp::server::run(chan.into_stream(), sftp).await;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.close(channel)?;
        Ok(())
    }
}

// ============================================================================
// Filesystem-backed SFTP handler.
//
// All paths are resolved relative to `sftp_root` to keep tests sandboxed.
// The russh-sftp client speaks absolute paths (e.g. "/foo/bar"); we strip
// the leading slash and join under `sftp_root`.
// ============================================================================

struct MockSftpSession {
    root: Arc<TempDir>,
    /// handle -> (path, kind, is_dir_done)
    handles: HashMap<String, FileHandle>,
    next_handle_id: u64,
}

#[derive(Clone)]
struct FileHandle {
    path: PathBuf,
    kind: HandleKind,
    /// For directory handles: have we already returned the listing?
    dir_done: bool,
}

#[derive(Clone, PartialEq, Eq)]
enum HandleKind {
    File,
    Dir,
}

impl MockSftpSession {
    fn new(root: Arc<TempDir>) -> Self {
        Self {
            root,
            handles: HashMap::new(),
            next_handle_id: 0,
        }
    }

    fn allocate_handle(&mut self, path: PathBuf, kind: HandleKind) -> String {
        self.next_handle_id += 1;
        let h = format!("h{}", self.next_handle_id);
        self.handles.insert(
            h.clone(),
            FileHandle {
                path,
                kind,
                dir_done: false,
            },
        );
        h
    }

    /// Resolve a client path under `sftp_root`. Strips a leading `/` so
    /// that `/tmp/a` maps to `<root>/tmp/a` — keeping all I/O sandboxed.
    fn resolve(&self, client_path: &str) -> PathBuf {
        let trimmed = client_path.trim_start_matches('/');
        if trimmed.is_empty() {
            self.root.path().to_path_buf()
        } else {
            self.root.path().join(trimmed)
        }
    }
}

fn fs_attrs(path: &Path) -> FileAttributes {
    let mut attrs = FileAttributes::default();
    if let Ok(meta) = std::fs::metadata(path) {
        attrs.size = Some(meta.len());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            attrs.permissions = Some(meta.permissions().mode());
        }
        attrs.set_dir(meta.is_dir());
    }
    attrs
}

impl russh_sftp::server::Handler for MockSftpSession {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        // Return the path verbatim — russh-sftp's client uses this to
        // canonicalize paths but our paths are already canonical.
        let canonical = if path.is_empty() || path == "." {
            "/".to_string()
        } else {
            path
        };
        Ok(Name {
            id,
            files: vec![SftpFile::dummy(canonical)],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let resolved = self.resolve(&path);
        if !resolved.exists() {
            return Err(StatusCode::NoSuchFile);
        }
        Ok(Attrs {
            id,
            attrs: fs_attrs(&resolved),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let h = self.handles.get(&handle).ok_or(StatusCode::Failure)?;
        Ok(Attrs {
            id,
            attrs: fs_attrs(&h.path),
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<SftpHandle, Self::Error> {
        let path = self.resolve(&filename);

        let mut opts = std::fs::OpenOptions::new();
        let read = pflags.contains(OpenFlags::READ);
        let write = pflags.contains(OpenFlags::WRITE);
        let create = pflags.contains(OpenFlags::CREATE);
        let truncate = pflags.contains(OpenFlags::TRUNCATE);
        let append = pflags.contains(OpenFlags::APPEND);
        let exclude = pflags.contains(OpenFlags::EXCLUDE);

        opts.read(read)
            .write(write)
            .create(create)
            .truncate(truncate)
            .append(append);
        if exclude {
            opts.create_new(true);
        }

        // Open just to validate access — we don't keep the FD because
        // each `read` / `write` reopens to support arbitrary offsets.
        match opts.open(&path) {
            Ok(_) => {}
            Err(e) => return Err(io_error_to_status(&e)),
        }

        let handle = self.allocate_handle(path, HandleKind::File);
        Ok(SftpHandle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".into(),
            language_tag: "en-US".into(),
        })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let h = self
            .handles
            .get(&handle)
            .ok_or(StatusCode::Failure)?
            .clone();
        if h.kind != HandleKind::File {
            return Err(StatusCode::Failure);
        }
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&h.path).map_err(|e| io_error_to_status(&e))?;
        f.seek(SeekFrom::Start(offset))
            .map_err(|e| io_error_to_status(&e))?;
        let mut buf = vec![0u8; len as usize];
        let n = f.read(&mut buf).map_err(|e| io_error_to_status(&e))?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let h = self
            .handles
            .get(&handle)
            .ok_or(StatusCode::Failure)?
            .clone();
        if h.kind != HandleKind::File {
            return Err(StatusCode::Failure);
        }
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&h.path)
            .map_err(|e| io_error_to_status(&e))?;
        f.seek(SeekFrom::Start(offset))
            .map_err(|e| io_error_to_status(&e))?;
        f.write_all(&data).map_err(|e| io_error_to_status(&e))?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".into(),
            language_tag: "en-US".into(),
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<SftpHandle, Self::Error> {
        let resolved = self.resolve(&path);
        if !resolved.is_dir() {
            return Err(StatusCode::NoSuchFile);
        }
        let handle = self.allocate_handle(resolved, HandleKind::Dir);
        Ok(SftpHandle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let h = self.handles.get_mut(&handle).ok_or(StatusCode::Failure)?;
        if h.kind != HandleKind::Dir {
            return Err(StatusCode::Failure);
        }
        if h.dir_done {
            return Err(StatusCode::Eof);
        }
        h.dir_done = true;

        let dir = std::fs::read_dir(&h.path).map_err(|e| io_error_to_status(&e))?;
        let mut files = Vec::new();
        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            files.push(SftpFile::new(name, fs_attrs(&entry.path())));
        }
        Ok(Name { id, files })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let resolved = self.resolve(&path);
        match std::fs::create_dir(&resolved) {
            Ok(()) => Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".into(),
                language_tag: "en-US".into(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".into(),
                language_tag: "en-US".into(),
            }),
            Err(e) => Err(io_error_to_status(&e)),
        }
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let resolved = self.resolve(&path);
        std::fs::remove_dir(&resolved).map_err(|e| io_error_to_status(&e))?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".into(),
            language_tag: "en-US".into(),
        })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let resolved = self.resolve(&filename);
        std::fs::remove_file(&resolved).map_err(|e| io_error_to_status(&e))?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".into(),
            language_tag: "en-US".into(),
        })
    }
}

fn io_error_to_status(e: &std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        std::io::ErrorKind::AlreadyExists => StatusCode::Failure,
        _ => StatusCode::Failure,
    }
}

// ============================================================================
// Smoke test so this binary contains at least one #[test] entry — keeps
// `cargo test --test ssh_mock_server` happy.
// ============================================================================

#[tokio::test]
async fn mock_server_starts_and_shuts_down() {
    let (addr, handle, _root) = MockSshServerBuilder::new().start().await;
    assert!(addr.port() > 0);
    handle.shutdown();
}
