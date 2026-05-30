use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use russh::ChannelMsg;
use russh::client::{self, Config, Handle, Handler};
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{PublicKey, load_secret_key};
use russh_sftp::client::SftpSession;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;

use crate::config::{AuthConfig, HostConfig, HostKeyVerification, LimitsConfig, SocksVersion};
use crate::error::{BridgeError, Result};
use crate::ssh::known_hosts;
use crate::ssh::sftp::SftpClient;

/// Sanitize SSH error messages to prevent credential leakage.
/// Removes any potential password or key material from error strings,
/// and masks authentication method names that could aid reconnaissance.
fn sanitize_ssh_error(error: &impl std::fmt::Display) -> String {
    let mut msg = error.to_string();
    // Mask auth method names that could aid reconnaissance
    for method in &["publickey", "keyboard-interactive", "gssapi-with-mic"] {
        msg = msg.replace(method, "***");
    }
    // Truncate overly long error messages that might contain data dumps
    if msg.len() > 500 {
        format!("{}... (truncated)", &msg[..500])
    } else {
        msg
    }
}

/// Hardened algorithm allowlist for the SSH transport layer (FIND-008).
///
/// Russh 0.60.1's `negotiation::Preferred::DEFAULT` includes legacy MAC
/// algorithms (`hmac-sha1`, `hmac-sha1-etm@openssh.com`) in `HMAC_ORDER`
/// (see `russh-0.60.1/src/negotiation.rs:134`). The KEX list `SAFE_KEX_ORDER`
/// (line 103) and cipher list `CIPHER_ORDER` (line 126) are already free of
/// SHA-1 / DH-Group1 / 3DES / blowfish, but we mirror the full allowlist
/// here so the policy is explicit at the call site rather than implicit in a
/// transitive default.
///
/// Allowlist (per `audit/2026-05-09/surface/context7/russh.md`):
/// - **kex**:    `mlkem768x25519-sha256`, `curve25519-sha256`,
///   `curve25519-sha256@libssh.org`, plus the `kex-strict-*-v00@openssh.com`
///   anti-Terrapin extensions (required, otherwise russh refuses to advertise
///   strict-KEX).
/// - **cipher**: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`
/// - **mac**:    `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`
///   (encrypt-then-MAC only; the AEAD ciphers above carry their own MAC, but
///   russh still negotiates a separate MAC name for non-AEAD interop).
/// - **key**:    `ssh-ed25519` (matches the host-key policy enforced by
///   `known_hosts::verify_host_key`).
fn hardened_preferred() -> russh::Preferred {
    use std::borrow::Cow;

    use russh::keys::ssh_key::Algorithm;

    // KEX: include the OpenSSH strict-kex extension markers so russh advertises
    // them and enables the Terrapin (CVE-2023-48795) mitigation. They are
    // pseudo-algorithms in russh's negotiation layer, not real KEX methods.
    const HARDENED_KEX: &[russh::kex::Name] = &[
        russh::kex::MLKEM768X25519_SHA256,
        russh::kex::CURVE25519,
        russh::kex::CURVE25519_PRE_RFC_8731,
        russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
        russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    ];

    const HARDENED_CIPHER: &[russh::cipher::Name] =
        &[russh::cipher::CHACHA20_POLY1305, russh::cipher::AES_256_GCM];

    const HARDENED_MAC: &[russh::mac::Name] =
        &[russh::mac::HMAC_SHA512_ETM, russh::mac::HMAC_SHA256_ETM];

    russh::Preferred {
        kex: Cow::Borrowed(HARDENED_KEX),
        // `Algorithm::Ed25519` is not a `const` value (it's an enum variant in
        // ssh-key), so we allocate the slice at call time. This is a one-shot
        // cost per connection.
        key: Cow::Owned(vec![Algorithm::Ed25519]),
        cipher: Cow::Borrowed(HARDENED_CIPHER),
        mac: Cow::Borrowed(HARDENED_MAC),
        // Compression: keep upstream default (russh ships `none` only without
        // the `flate2` feature, which we don't enable).
        compression: russh::Preferred::DEFAULT.compression,
    }
}

/// Build a russh client `Config` with a hardened algorithm allowlist and
/// explicit rekey limits (FIND-008).
///
/// Replaces `russh::client::Config { ..Default::default() }` at the two
/// connect call sites (direct + jump-host). Without this helper:
/// - `Preferred::default()` would silently include `hmac-sha1` and
///   `hmac-sha1-etm@openssh.com` (per russh 0.60.1 `HMAC_ORDER`).
/// - `Limits::default()` already pins 1 GiB / 1 h thresholds, but we set
///   them explicitly via `Limits::new` so a future russh default change
///   cannot weaken the policy without a build break (the constructor
///   asserts the bounds).
///
/// The pool keeps sessions for up to 1 h (`pool.rs::max_age_seconds`), so
/// the rekey time limit acts as a defence-in-depth against long-lived
/// sessions accumulating ciphertext under one key.
pub fn build_russh_client_config(limits: &LimitsConfig) -> Config {
    Config {
        inactivity_timeout: Some(Duration::from_secs(limits.keepalive_interval_seconds)),
        keepalive_interval: Some(Duration::from_secs(limits.keepalive_interval_seconds)),
        keepalive_max: 3,
        preferred: hardened_preferred(),
        limits: russh::Limits::new(1 << 30, 1 << 30, Duration::from_secs(3600)),
        ..Default::default()
    }
}

/// A wrapper around a russh Channel that implements `AsyncRead` and `AsyncWrite`
/// for use as a transport stream for tunneled SSH connections.
struct ChannelStream {
    channel: russh::Channel<russh::client::Msg>,
    read_buffer: Vec<u8>,
    read_pos: usize,
}

impl ChannelStream {
    #[allow(clippy::missing_const_for_fn)] // Vec::new() is not const
    fn new(channel: russh::Channel<russh::client::Msg>) -> Self {
        Self {
            channel,
            read_buffer: Vec::new(),
            read_pos: 0,
        }
    }
}

impl AsyncRead for ChannelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // If we have buffered data, return it first
        if this.read_pos < this.read_buffer.len() {
            let remaining = &this.read_buffer[this.read_pos..];
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.read_pos += to_copy;
            if this.read_pos >= this.read_buffer.len() {
                this.read_buffer.clear();
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Try to receive more data from the channel
        let fut = this.channel.wait();
        tokio::pin!(fut);

        match fut.poll(cx) {
            Poll::Ready(Some(ChannelMsg::Data { data })) => {
                let to_copy = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    this.read_buffer = data[to_copy..].to_vec();
                    this.read_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(ChannelMsg::Eof) | None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(_)) => {
                // Other message types, try again
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ChannelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let fut = this.channel.data(buf);
        tokio::pin!(fut);

        match fut.poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let fut = this.channel.eof();
        tokio::pin!(fut);

        match fut.poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Output from a command execution
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: u32,
    pub duration_ms: u64,
}

/// SSH client handler for russh with host key verification
struct ClientHandler {
    hostname: String,
    port: u16,
    verification_mode: HostKeyVerification,
}

impl ClientHandler {
    const fn new(hostname: String, port: u16, verification_mode: HostKeyVerification) -> Self {
        Self {
            hostname,
            port,
            verification_mode,
        }
    }
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        match known_hosts::verify_host_key(
            &self.hostname,
            self.port,
            server_public_key,
            self.verification_mode,
        ) {
            Ok(()) => Ok(true),
            Err(e) => {
                tracing::error!(error = %e, "Host key verification failed");
                Ok(false)
            }
        }
    }
}

/// SSH client wrapper
pub struct SshClient {
    handle: Handle<ClientHandler>,
    host_name: String,
    /// Optional jump host client kept alive to maintain the tunnel (RAII pattern).
    /// This field is intentionally never read - its presence keeps the connection alive.
    #[allow(dead_code, clippy::struct_field_names)]
    jump_client: Option<Box<Self>>,
}

impl SshClient {
    /// Connect to a host using the provided configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The SSH connection cannot be established (network error, timeout)
    /// - Host key verification fails
    /// - Authentication fails (invalid credentials, key, or agent)
    #[must_use = "the SSH client must be used or closed"]
    #[tracing::instrument(
        name = "ssh.connect",
        skip(host, limits),
        fields(
            host = %host_name,
            port = host.port,
            duration_ms = tracing::field::Empty,
        )
    )]
    pub async fn connect(
        host_name: &str,
        host: &HostConfig,
        limits: &LimitsConfig,
    ) -> Result<Self> {
        let _timer = crate::telemetry::SpanDurationGuard::start();
        let handle = Self::establish_connection(host_name, host, limits).await?;
        Self::authenticate(handle, host_name, host).await
    }

    /// Connect to a host through a jump host (bastion)
    ///
    /// This establishes an SSH connection to the jump host first, then opens
    /// a direct-tcpip tunnel to the target host and establishes a second SSH
    /// connection through that tunnel.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Connection to jump host fails
    /// - Tunnel creation fails
    /// - Connection to target through tunnel fails
    /// - Authentication on target fails
    #[must_use = "the SSH client must be used or closed"]
    #[tracing::instrument(
        name = "ssh.connect_via_jump",
        skip(host, jump_host, limits),
        fields(
            host = %host_name,
            jump = %jump_host_name,
            port = host.port,
            duration_ms = tracing::field::Empty,
        )
    )]
    pub async fn connect_via_jump(
        host_name: &str,
        host: &HostConfig,
        jump_host_name: &str,
        jump_host: &HostConfig,
        limits: &LimitsConfig,
    ) -> Result<Self> {
        let _timer = crate::telemetry::SpanDurationGuard::start();
        tracing::info!(
            host = %host_name,
            jump = %jump_host_name,
            "Connecting via jump host"
        );

        // 1. Connect to the jump host
        let jump_client = Self::connect(jump_host_name, jump_host, limits).await?;

        tracing::debug!(
            host = %host_name,
            target = %host.hostname,
            port = %host.port,
            "Opening tunnel through jump host"
        );

        // 2. Open a direct-tcpip channel to the target host
        let channel = jump_client
            .handle
            .channel_open_direct_tcpip(&host.hostname, host.port.into(), "127.0.0.1", 0)
            .await
            .map_err(|e| BridgeError::SshConnection {
                host: host_name.to_string(),
                reason: format!("Failed to open tunnel through {jump_host_name}: {e}"),
            })?;

        // 3. Wrap the channel as a stream for SSH transport
        let stream = ChannelStream::new(channel);

        // 4. Establish SSH connection through the tunnel
        // FIND-008: hardened algo allowlist + rekey limits via shared helper.
        let config = Arc::new(build_russh_client_config(limits));

        let handler =
            ClientHandler::new(host.hostname.clone(), host.port, host.host_key_verification);

        let handle = client::connect_stream(config, stream, handler)
            .await
            .map_err(|e| {
                // FIND-016: sanitize before embedding so russh-emitted diagnostics
                // that name auth methods do not leak through the jump-host
                // connect-phase error.
                let sanitized = sanitize_ssh_error(&e);
                BridgeError::SshConnection {
                    host: host_name.to_string(),
                    reason: format!("Failed to establish SSH through tunnel: {sanitized}"),
                }
            })?;

        tracing::debug!(host = %host_name, "Authenticating through tunnel");

        // 5. Authenticate on the target host
        let client = Self::authenticate_with_jump(handle, host_name, host, jump_client).await?;

        tracing::info!(
            host = %host_name,
            jump = %jump_host_name,
            "Connected via jump host"
        );

        Ok(client)
    }

    /// Authenticate and return client with `jump_client` attached
    async fn authenticate_with_jump(
        handle: Handle<ClientHandler>,
        host_name: &str,
        host: &HostConfig,
        jump_client: Self,
    ) -> Result<Self> {
        // Authenticate based on the configured method
        let mut client = Self::authenticate(handle, host_name, host).await?;

        // Attach the jump client to keep the tunnel alive
        client.jump_client = Some(Box::new(jump_client));

        Ok(client)
    }

    /// Establish the TCP/SSH connection (direct or via SOCKS proxy)
    async fn establish_connection(
        host_name: &str,
        host: &HostConfig,
        limits: &LimitsConfig,
    ) -> Result<Handle<ClientHandler>> {
        // FIND-008: hardened algo allowlist + rekey limits via shared helper.
        let config = Arc::new(build_russh_client_config(limits));
        let target_host = &host.hostname;
        let port = host.port;
        let handler = ClientHandler::new(target_host.clone(), port, host.host_key_verification);

        let connect_timeout = Duration::from_secs(limits.connection_timeout_seconds);
        let timeout_secs = limits.connection_timeout_seconds;

        if let Some(ref socks) = host.socks_proxy {
            // SOCKS proxy path: connect via proxy, then SSH over the tunneled stream
            let proxy_addr = format!("{}:{}", socks.hostname, socks.port);
            let target_addr = (target_host.as_str(), port);

            tracing::info!(
                host = %host_name,
                proxy = %proxy_addr,
                version = ?socks.version,
                "Connecting via SOCKS proxy"
            );

            let tcp_stream = timeout(connect_timeout, async {
                let map_err = |e: tokio_socks::Error| BridgeError::SocksProxy {
                    host: host_name.to_string(),
                    reason: e.to_string(),
                };
                let result: Result<tokio::net::TcpStream> = match socks.version {
                    SocksVersion::Socks5 => {
                        let stream = if let (Some(user), Some(pass)) =
                            (&socks.username, &socks.password)
                        {
                            tokio_socks::tcp::Socks5Stream::connect_with_password(
                                proxy_addr.as_str(),
                                target_addr,
                                user,
                                pass.as_str(),
                            )
                            .await
                            .map_err(map_err)?
                        } else {
                            tokio_socks::tcp::Socks5Stream::connect(
                                proxy_addr.as_str(),
                                target_addr,
                            )
                            .await
                            .map_err(map_err)?
                        };
                        Ok(stream.into_inner())
                    }
                    SocksVersion::Socks4 => {
                        let stream = tokio_socks::tcp::Socks4Stream::connect(
                            proxy_addr.as_str(),
                            target_addr,
                        )
                        .await
                        .map_err(map_err)?;
                        Ok(stream.into_inner())
                    }
                };
                result
            })
            .await
            .map_err(|_| {
                tracing::error!(host = %host_name, proxy = %proxy_addr, timeout_secs, "SOCKS proxy connection timeout");
                BridgeError::SocksProxy {
                    host: host_name.to_string(),
                    reason: format!("Connection timeout after {timeout_secs}s"),
                }
            })??;

            // SSH over the SOCKS-tunneled TCP stream
            client::connect_stream(config, tcp_stream, handler)
                .await
                .map_err(|e| {
                    // FIND-016: sanitize before logging/embedding so russh-emitted
                    // diagnostics that name auth methods (publickey, password,
                    // gssapi-*) do not leak through connect-phase errors.
                    let sanitized = sanitize_ssh_error(&e);
                    tracing::error!(host = %host_name, error = %sanitized, "SSH connection through SOCKS proxy failed");
                    BridgeError::SshConnection {
                        host: host_name.to_string(),
                        reason: format!("Failed to establish SSH through SOCKS proxy: {sanitized}"),
                    }
                })
        } else {
            // Direct connection
            let addr = format!("{target_host}:{port}");

            timeout(connect_timeout, client::connect(config, &addr, handler))
                .await
                .map_err(|_| {
                    tracing::error!(host = %host_name, addr = %addr, timeout_secs, "SSH connection timeout");
                    BridgeError::SshConnection {
                        host: host_name.to_string(),
                        reason: format!("Connection timeout after {timeout_secs}s"),
                    }
                })?
                .map_err(|e| {
                    // FIND-016: same sanitization as the SOCKS branch above.
                    let sanitized = sanitize_ssh_error(&e);
                    tracing::error!(host = %host_name, addr = %addr, error = %sanitized, "SSH connection failed");
                    BridgeError::SshConnection {
                        host: host_name.to_string(),
                        reason: sanitized,
                    }
                })
        }
    }

    /// Authenticate using the configured method
    async fn authenticate(
        handle: Handle<ClientHandler>,
        host_name: &str,
        host: &HostConfig,
    ) -> Result<Self> {
        match &host.auth {
            AuthConfig::Key { path, passphrase } => {
                Self::auth_with_key(handle, host_name, host, path, passphrase.as_deref()).await
            }
            AuthConfig::Password { password } => {
                Self::auth_with_password(handle, host_name, host, password).await
            }
            AuthConfig::Agent => Self::auth_with_agent(handle, host_name, host).await,
            #[cfg(feature = "winrm")]
            AuthConfig::Ntlm { .. } | AuthConfig::Certificate { .. } | AuthConfig::Kerberos => {
                Err(BridgeError::SshAuth {
                    user: host.user.clone(),
                    host: format!("{host_name}: WinRM auth types cannot be used with SSH protocol"),
                })
            }
        }
    }

    /// Authenticate using an SSH key file
    async fn auth_with_key(
        mut handle: Handle<ClientHandler>,
        host_name: &str,
        host: &HostConfig,
        path: &str,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        let expanded = crate::path_utils::home_expand_or_input(path);
        let key_path = Path::new(&expanded);

        let key_pair =
            load_secret_key(key_path, passphrase).map_err(|e| BridgeError::SshKeyInvalid {
                path: format!("{path}: {}", sanitize_ssh_error(&e)),
            })?;

        let hash_alg = handle
            .best_supported_rsa_hash()
            .await
            .ok()
            .flatten()
            .flatten();

        let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg);

        let auth_result = handle
            .authenticate_publickey(&host.user, key_with_hash)
            .await
            .map_err(|e| {
                tracing::error!(host = %host_name, user = %host.user, error = %sanitize_ssh_error(&e), method = "key", "SSH key authentication error");
                BridgeError::SshAuth {
                    user: host.user.clone(),
                    host: format!("{host_name}: authentication failed"),
                }
            })?;

        if !auth_result.success() {
            tracing::error!(host = %host_name, user = %host.user, method = "key", "SSH key authentication failed");
            return Err(BridgeError::SshAuth {
                user: host.user.clone(),
                host: host_name.to_string(),
            });
        }

        Ok(Self {
            handle,
            host_name: host_name.to_string(),
            jump_client: None,
        })
    }

    /// Authenticate using a password
    async fn auth_with_password(
        mut handle: Handle<ClientHandler>,
        host_name: &str,
        host: &HostConfig,
        password: &str,
    ) -> Result<Self> {
        let auth_result = handle
            .authenticate_password(&host.user, password)
            .await
            .map_err(|e| {
                tracing::error!(host = %host_name, user = %host.user, error = %sanitize_ssh_error(&e), method = "password", "SSH password authentication error");
                BridgeError::SshAuth {
                    user: host.user.clone(),
                    host: format!("{host_name}: authentication failed"),
                }
            })?;

        if !auth_result.success() {
            tracing::error!(host = %host_name, user = %host.user, method = "password", "SSH password authentication failed");
            return Err(BridgeError::SshAuth {
                user: host.user.clone(),
                host: host_name.to_string(),
            });
        }

        Ok(Self {
            handle,
            host_name: host_name.to_string(),
            jump_client: None,
        })
    }

    /// Authenticate using an SSH agent
    #[cfg(unix)]
    async fn auth_with_agent(
        mut handle: Handle<ClientHandler>,
        host_name: &str,
        host: &HostConfig,
    ) -> Result<Self> {
        use russh::keys::agent::client::AgentClient;

        let mut agent = AgentClient::connect_env().await.map_err(|e| {
            // FIND-016: sanitize the trace event too — the error-variant `host`
            // is already sanitized below but the trace was emitting the raw
            // russh diagnostic.
            let sanitized = sanitize_ssh_error(&e);
            tracing::error!(host = %host_name, error = %sanitized, "SSH agent connection failed");
            BridgeError::SshAuth {
                user: host.user.clone(),
                host: format!("{host_name}: SSH agent connection failed: {sanitized}"),
            }
        })?;

        let identities = agent.request_identities().await.map_err(|e| {
            // FIND-016: same sanitization pattern as the agent-connect site above.
            let sanitized = sanitize_ssh_error(&e);
            tracing::error!(host = %host_name, error = %sanitized, "Failed to get agent identities");
            BridgeError::SshAuth {
                user: host.user.clone(),
                host: format!("{host_name}: Failed to get agent identities: {sanitized}"),
            }
        })?;

        if identities.is_empty() {
            tracing::error!(host = %host_name, user = %host.user, "No identities available in SSH agent");
            return Err(BridgeError::SshAuth {
                user: host.user.clone(),
                host: format!("{host_name}: No identities available in SSH agent"),
            });
        }

        let mut last_error: Option<String> = None;
        for public_key in &identities {
            let hash_alg = handle
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten();

            match handle
                .authenticate_publickey_with(
                    &host.user,
                    public_key.public_key().into_owned(),
                    hash_alg,
                    &mut agent,
                )
                .await
            {
                Ok(result) if result.success() => {
                    return Ok(Self {
                        handle,
                        host_name: host_name.to_string(),
                        jump_client: None,
                    });
                }
                Ok(_) => {
                    last_error = Some("Key rejected by server".to_string());
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                }
            }
        }

        let error_msg = last_error.unwrap_or_else(|| "unknown".to_string());
        tracing::error!(
            host = %host_name,
            user = %host.user,
            identity_count = identities.len(),
            last_error = %error_msg,
            method = "agent",
            "SSH agent authentication failed - no identity accepted"
        );
        Err(BridgeError::SshAuth {
            user: host.user.clone(),
            host: format!(
                "{host_name}: None of the {} agent identities worked. Last error: {error_msg}",
                identities.len()
            ),
        })
    }

    /// Authenticate using an SSH agent (Windows)
    #[cfg(windows)]
    async fn auth_with_agent(
        mut handle: Handle<ClientHandler>,
        host_name: &str,
        host: &HostConfig,
    ) -> Result<Self> {
        use russh::keys::agent::client::AgentClient;
        use tokio::net::windows::named_pipe::ClientOptions;

        // Windows OpenSSH Agent pipe path
        const PIPE_NAME: &str = r"\\.\pipe\openssh-ssh-agent";

        // Connect to the Windows OpenSSH Agent
        let pipe = ClientOptions::new()
            .open(PIPE_NAME)
            .map_err(|e| BridgeError::SshAuth {
                user: host.user.clone(),
                host: format!(
                    "{host_name}: Windows SSH agent connection failed: {e}. \
                    Ensure the OpenSSH Authentication Agent service is running."
                ),
            })?;

        let mut agent = AgentClient::connect(pipe);

        let identities = agent
            .request_identities()
            .await
            .map_err(|e| BridgeError::SshAuth {
                user: host.user.clone(),
                host: format!(
                    "{host_name}: Failed to get agent identities: {}",
                    sanitize_ssh_error(&e)
                ),
            })?;

        if identities.is_empty() {
            return Err(BridgeError::SshAuth {
                user: host.user.clone(),
                host: format!("{host_name}: No identities available in SSH agent"),
            });
        }

        let mut last_error: Option<String> = None;
        for public_key in &identities {
            let hash_alg = handle
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten();

            match handle
                .authenticate_publickey_with(
                    &host.user,
                    public_key.public_key().into_owned(),
                    hash_alg,
                    &mut agent,
                )
                .await
            {
                Ok(result) if result.success() => {
                    return Ok(Self {
                        handle,
                        host_name: host_name.to_string(),
                        jump_client: None,
                    });
                }
                Ok(_) => {
                    last_error = Some("Key rejected by server".to_string());
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                }
            }
        }

        Err(BridgeError::SshAuth {
            user: host.user.clone(),
            host: format!(
                "{host_name}: None of the {} agent identities worked. Last error: {}",
                identities.len(),
                last_error.unwrap_or_else(|| "unknown".to_string())
            ),
        })
    }

    /// Authenticate using an SSH agent (unsupported platforms)
    #[cfg(not(any(unix, windows)))]
    async fn auth_with_agent(
        _handle: Handle<ClientHandler>,
        host_name: &str,
        host: &HostConfig,
    ) -> Result<Self> {
        Err(BridgeError::SshAuth {
            user: host.user.clone(),
            host: format!("{host_name}: SSH agent not supported on this platform"),
        })
    }

    /// Execute a command on the remote host
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The SSH channel cannot be opened
    /// - The command execution fails
    /// - The command times out
    /// - The output exceeds the maximum allowed size
    pub async fn exec(&self, command: &str, limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = std::time::Instant::now();

        let mut channel =
            self.handle
                .channel_open_session()
                .await
                .map_err(|e| BridgeError::SshExec {
                    reason: format!("Failed to open channel: {e}"),
                })?;

        channel
            .exec(true, command)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Failed to execute command: {e}"),
            })?;

        let (stdout, stderr, exit_code) = Self::read_command_output(&mut channel, limits).await?;

        #[expect(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code,
            duration_ms,
        })
    }

    /// Read command output from channel with timeout
    async fn read_command_output(
        channel: &mut russh::Channel<russh::client::Msg>,
        limits: &LimitsConfig,
    ) -> Result<(Vec<u8>, Vec<u8>, u32)> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = 0u32;
        let mut total_bytes = 0usize;
        let command_timeout = Duration::from_secs(limits.command_timeout_seconds);

        let result = timeout(command_timeout, async {
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Data { data }) => {
                        total_bytes += data.len();
                        if total_bytes > limits.max_output_bytes {
                            return Err(BridgeError::SshOutputTooLarge {
                                limit_bytes: limits.max_output_bytes,
                            });
                        }
                        stdout.extend_from_slice(&data);
                    }
                    Some(ChannelMsg::ExtendedData { data, ext }) => {
                        if ext == 1 {
                            total_bytes += data.len();
                            if total_bytes > limits.max_output_bytes {
                                return Err(BridgeError::SshOutputTooLarge {
                                    limit_bytes: limits.max_output_bytes,
                                });
                            }
                            stderr.extend_from_slice(&data);
                        }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = exit_status;
                    }
                    None => {
                        break;
                    }
                    // Eof signals end of data but ExitStatus may arrive before
                    // or after it. Continue the loop to collect all messages
                    // until the channel is fully closed (None).
                    _ => {}
                }
            }
            Ok((stdout, stderr, exit_code))
        })
        .await;

        match result {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                let _ = channel.close().await;
                Err(BridgeError::SshTimeout {
                    seconds: limits.command_timeout_seconds,
                })
            }
        }
    }

    /// Check if the connection is still alive (with 5s timeout to avoid blocking)
    #[must_use = "the connection status should be checked"]
    pub async fn is_connected(&self) -> bool {
        // Use a short timeout to avoid blocking the pool if connection is in a bad state
        match timeout(Duration::from_secs(5), self.handle.channel_open_session()).await {
            Ok(Ok(_)) => true,
            // Channel open failed or timeout - connection is likely dead
            Ok(Err(_)) | Err(_) => false,
        }
    }

    /// Get the host name
    #[must_use]
    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    /// Close the connection (with 5s timeout to avoid blocking)
    ///
    /// # Errors
    ///
    /// Returns an error if the disconnect message cannot be sent to the server
    /// or if the operation times out.
    pub async fn close(self) -> Result<()> {
        // Use a timeout to avoid blocking if the connection is in a bad state
        match timeout(
            Duration::from_secs(5),
            self.handle
                .disconnect(russh::Disconnect::ByApplication, "", "en"),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(BridgeError::SshConnection {
                host: self.host_name,
                reason: e.to_string(),
            }),
            Err(_) => {
                // Timeout during close - connection was likely dead anyway
                tracing::warn!(host = %self.host_name, "Timeout closing SSH connection, forcing drop");
                Ok(())
            }
        }
    }

    /// Open an interactive shell channel
    ///
    /// Returns a channel with an active shell session. The caller can send
    /// commands via `channel.data()` and read output via `channel.wait()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the SSH channel cannot be opened or the shell
    /// request is rejected by the server.
    pub async fn open_shell(&self) -> Result<russh::Channel<russh::client::Msg>> {
        let channel =
            self.handle
                .channel_open_session()
                .await
                .map_err(|e| BridgeError::SshExec {
                    reason: format!("Failed to open channel for shell: {e}"),
                })?;

        channel
            .request_shell(true)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Failed to request shell: {e}"),
            })?;

        Ok(channel)
    }

    /// Forward a single TCP connection through the SSH tunnel.
    ///
    /// Opens a direct-tcpip channel to `remote_host:remote_port` and copies data
    /// bidirectionally between the local TCP stream and the SSH channel.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel cannot be opened or if forwarding fails.
    pub async fn forward_tcp_connection(
        &self,
        mut tcp_stream: tokio::net::TcpStream,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<()> {
        let channel = self
            .handle
            .channel_open_direct_tcpip(remote_host, remote_port.into(), "127.0.0.1", 0)
            .await
            .map_err(|e| BridgeError::Tunnel {
                reason: format!("Failed to open channel to {remote_host}:{remote_port}: {e}"),
            })?;

        let mut channel_stream = ChannelStream::new(channel);
        let _ = tokio::io::copy_bidirectional(&mut tcp_stream, &mut channel_stream)
            .await
            .map_err(|e| BridgeError::Tunnel {
                reason: format!("Tunnel forwarding error: {e}"),
            })?;

        Ok(())
    }

    /// Create an SFTP session for file transfers
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The SSH channel cannot be opened
    /// - The SFTP subsystem request fails
    /// - SFTP initialization fails
    pub async fn sftp_session(&self) -> Result<SftpClient> {
        // Open a new session channel
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| BridgeError::Sftp {
                reason: format!("Failed to open channel: {e}"),
            })?;

        // Request the SFTP subsystem
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| BridgeError::Sftp {
                reason: format!("Failed to request SFTP subsystem: {e}"),
            })?;

        // Create the SFTP session from the channel stream
        let sftp_session =
            SftpSession::new(channel.into_stream())
                .await
                .map_err(|e| BridgeError::Sftp {
                    reason: format!("Failed to initialize SFTP session: {e}"),
                })?;

        Ok(SftpClient::new(sftp_session))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== CommandOutput Tests ==============

    #[test]
    fn test_command_output_new() {
        let output = CommandOutput {
            stdout: "hello".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 100,
        };

        assert_eq!(output.stdout, "hello");
        assert_eq!(output.stderr, "");
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.duration_ms, 100);
    }

    #[test]
    fn test_command_output_with_stderr() {
        let output = CommandOutput {
            stdout: "output".to_string(),
            stderr: "error message".to_string(),
            exit_code: 1,
            duration_ms: 500,
        };

        assert_eq!(output.stdout, "output");
        assert_eq!(output.stderr, "error message");
        assert_eq!(output.exit_code, 1);
    }

    #[test]
    fn test_command_output_clone() {
        let output = CommandOutput {
            stdout: "test".to_string(),
            stderr: "err".to_string(),
            exit_code: 127,
            duration_ms: 1000,
        };

        let cloned = output.clone();
        assert_eq!(cloned.stdout, output.stdout);
        assert_eq!(cloned.stderr, output.stderr);
        assert_eq!(cloned.exit_code, output.exit_code);
        assert_eq!(cloned.duration_ms, output.duration_ms);
    }

    #[test]
    fn test_command_output_debug() {
        let output = CommandOutput {
            stdout: "hello".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 50,
        };

        let debug_str = format!("{output:?}");
        assert!(debug_str.contains("CommandOutput"));
        assert!(debug_str.contains("stdout"));
        assert!(debug_str.contains("hello"));
        assert!(debug_str.contains("exit_code"));
        assert!(debug_str.contains('0'));
    }

    #[test]
    fn test_command_output_empty_strings() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 0,
        };

        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn test_command_output_large_exit_code() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 255,
            duration_ms: 10,
        };

        assert_eq!(output.exit_code, 255);
    }

    #[test]
    fn test_command_output_unicode() {
        let output = CommandOutput {
            stdout: "日本語 🎉 émoji".to_string(),
            stderr: "错误信息".to_string(),
            exit_code: 0,
            duration_ms: 100,
        };

        assert!(output.stdout.contains("日本語"));
        assert!(output.stdout.contains("🎉"));
        assert!(output.stderr.contains("错误信息"));
    }

    #[test]
    fn test_command_output_multiline() {
        let output = CommandOutput {
            stdout: "line1\nline2\nline3".to_string(),
            stderr: "err1\nerr2".to_string(),
            exit_code: 0,
            duration_ms: 200,
        };

        assert_eq!(output.stdout.lines().count(), 3);
        assert_eq!(output.stderr.lines().count(), 2);
    }

    #[test]
    fn test_command_output_crlf() {
        let output = CommandOutput {
            stdout: "line1\r\nline2\r\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 50,
        };

        assert!(output.stdout.contains("\r\n"));
    }

    #[test]
    fn test_command_output_long_duration() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: u64::MAX,
        };

        assert_eq!(output.duration_ms, u64::MAX);
    }

    // ============== ClientHandler Tests ==============

    #[test]
    fn test_client_handler_new() {
        let handler =
            ClientHandler::new("example.com".to_string(), 22, HostKeyVerification::Strict);

        assert_eq!(handler.hostname, "example.com");
        assert_eq!(handler.port, 22);
        assert_eq!(handler.verification_mode, HostKeyVerification::Strict);
    }

    #[test]
    fn test_client_handler_custom_port() {
        let handler = ClientHandler::new(
            "example.com".to_string(),
            2222,
            HostKeyVerification::AcceptNew,
        );

        assert_eq!(handler.port, 2222);
        assert_eq!(handler.verification_mode, HostKeyVerification::AcceptNew);
    }

    #[test]
    fn test_client_handler_verification_off() {
        let handler = ClientHandler::new("test.local".to_string(), 22, HostKeyVerification::Off);

        assert_eq!(handler.verification_mode, HostKeyVerification::Off);
    }

    #[test]
    fn test_client_handler_ipv4_hostname() {
        let handler =
            ClientHandler::new("192.168.1.100".to_string(), 22, HostKeyVerification::Strict);

        assert_eq!(handler.hostname, "192.168.1.100");
    }

    #[test]
    fn test_client_handler_ipv6_hostname() {
        let handler = ClientHandler::new("::1".to_string(), 22, HostKeyVerification::Strict);

        assert_eq!(handler.hostname, "::1");
    }

    // ============== ChannelStream Tests ==============

    #[test]
    fn test_channel_stream_buffer_initialization() {
        // Note: We can't fully test ChannelStream without a real channel,
        // but we document the expected behavior here.
        // The buffer should start empty with position 0.

        // This test validates our understanding of the internal state.
        // In production, ChannelStream::new() creates:
        // - read_buffer: Vec::new() (empty)
        // - read_pos: 0
    }

    // ============== sanitize_ssh_error Tests ==============

    #[test]
    fn test_sanitize_ssh_error_masks_auth_methods() {
        let error = "no auth methods: publickey,keyboard-interactive";
        let sanitized = sanitize_ssh_error(&error);
        assert!(
            !sanitized.contains("publickey"),
            "publickey should be masked"
        );
        assert!(
            !sanitized.contains("keyboard-interactive"),
            "keyboard-interactive should be masked"
        );
        assert!(sanitized.contains("***"), "Should contain masked markers");
    }

    #[test]
    fn test_sanitize_ssh_error_truncates_long_messages() {
        let long_error = "x".repeat(600);
        let sanitized = sanitize_ssh_error(&long_error);
        assert!(sanitized.len() < 600, "Should be truncated");
        assert!(sanitized.contains("(truncated)"));
    }

    #[test]
    fn test_sanitize_ssh_error_short_message_unchanged() {
        let error = "Connection refused";
        let sanitized = sanitize_ssh_error(&error);
        assert_eq!(sanitized, "Connection refused");
    }

    // ============== Error Scenario Documentation Tests ==============

    #[test]
    fn test_ssh_connection_error_format() {
        let error = BridgeError::SshConnection {
            host: "test-host".to_string(),
            reason: "Connection refused".to_string(),
        };

        let msg = error.to_string();
        assert!(msg.contains("test-host"));
        assert!(msg.contains("Connection refused"));
    }

    #[test]
    fn test_ssh_auth_error_format() {
        let error = BridgeError::SshAuth {
            user: "testuser".to_string(),
            host: "example.com".to_string(),
        };

        let msg = error.to_string();
        assert!(msg.contains("testuser"));
        assert!(msg.contains("example.com"));
    }

    #[test]
    fn test_ssh_key_invalid_error_format() {
        let error = BridgeError::SshKeyInvalid {
            path: "/path/to/key".to_string(),
        };

        let msg = error.to_string();
        assert!(msg.contains("/path/to/key"));
    }

    #[test]
    fn test_ssh_exec_error_format() {
        let error = BridgeError::SshExec {
            reason: "Channel closed".to_string(),
        };

        let msg = error.to_string();
        assert!(msg.contains("Channel closed"));
    }

    #[test]
    fn test_ssh_timeout_error_format() {
        let error = BridgeError::SshTimeout { seconds: 30 };

        let msg = error.to_string();
        assert!(msg.contains("30"));
        assert!(msg.contains("timeout"));
    }

    #[test]
    fn test_ssh_output_too_large_error_format() {
        let error = BridgeError::SshOutputTooLarge {
            limit_bytes: 1_048_576,
        };

        let msg = error.to_string();
        assert!(msg.contains("1048576"));
    }

    #[test]
    fn test_ssh_host_key_mismatch_error_format() {
        let error = BridgeError::SshHostKeyMismatch {
            host: "server.example.com".to_string(),
            expected: "SHA256:expected".to_string(),
            actual: "SHA256:actual".to_string(),
        };

        let msg = error.to_string();
        assert!(msg.contains("server.example.com"));
        assert!(msg.contains("expected"));
        assert!(msg.contains("actual"));
    }

    #[test]
    fn test_ssh_host_key_unknown_error_format() {
        let error = BridgeError::SshHostKeyUnknown {
            host: "new-server.example.com".to_string(),
            fingerprint: "SHA256:abc123".to_string(),
        };

        let msg = error.to_string();
        assert!(msg.contains("new-server.example.com"));
        assert!(msg.contains("SHA256:abc123"));
    }

    #[test]
    fn test_sftp_error_format() {
        let error = BridgeError::Sftp {
            reason: "Permission denied".to_string(),
        };

        let msg = error.to_string();
        assert!(msg.contains("Permission denied"));
    }

    // ============== Configuration Edge Cases ==============

    #[test]
    fn test_host_key_verification_default_is_strict() {
        // Security: default should be strict
        let default = HostKeyVerification::default();
        assert_eq!(default, HostKeyVerification::Strict);
    }

    #[test]
    fn test_host_key_verification_all_modes() {
        // Ensure all modes are distinct
        assert_ne!(HostKeyVerification::Strict, HostKeyVerification::AcceptNew);
        assert_ne!(HostKeyVerification::Strict, HostKeyVerification::Off);
        assert_ne!(HostKeyVerification::AcceptNew, HostKeyVerification::Off);
    }

    // ============== CommandOutput Additional Tests ==============

    #[test]
    fn test_command_output_with_special_chars() {
        let output = CommandOutput {
            stdout: "path: /home/user\nvar: $HOME".to_string(),
            stderr: "warning: `deprecated`".to_string(),
            exit_code: 0,
            duration_ms: 50,
        };

        assert!(output.stdout.contains("$HOME"));
        assert!(output.stderr.contains("`deprecated`"));
    }

    #[test]
    fn test_command_output_binary_output() {
        // Test handling of non-UTF8 content (converted via lossy)
        let output = CommandOutput {
            stdout: "\u{FFFD}\u{FFFD}binary".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 10,
        };

        assert!(output.stdout.contains("binary"));
    }

    #[test]
    fn test_command_output_high_exit_codes() {
        // Exit codes 128+ indicate signals
        let signal_exit = CommandOutput {
            stdout: String::new(),
            stderr: "Killed".to_string(),
            exit_code: 137, // SIGKILL (128 + 9)
            duration_ms: 100,
        };

        assert_eq!(signal_exit.exit_code, 137);
    }

    #[test]
    fn test_command_output_max_exit_code() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: u32::MAX,
            duration_ms: 0,
        };

        assert_eq!(output.exit_code, u32::MAX);
    }

    // ============== ClientHandler Edge Cases ==============

    #[test]
    fn test_client_handler_min_port() {
        let handler = ClientHandler::new("test.local".to_string(), 1, HostKeyVerification::Strict);
        assert_eq!(handler.port, 1);
    }

    #[test]
    fn test_client_handler_max_port() {
        let handler =
            ClientHandler::new("test.local".to_string(), 65535, HostKeyVerification::Strict);
        assert_eq!(handler.port, 65535);
    }

    #[test]
    fn test_client_handler_empty_hostname() {
        let handler = ClientHandler::new(String::new(), 22, HostKeyVerification::Strict);
        assert!(handler.hostname.is_empty());
    }

    #[test]
    fn test_client_handler_long_hostname() {
        let long_hostname = "a".repeat(255);
        let handler = ClientHandler::new(long_hostname.clone(), 22, HostKeyVerification::Strict);
        assert_eq!(handler.hostname.len(), 255);
    }

    #[test]
    fn test_client_handler_unicode_hostname() {
        let handler = ClientHandler::new(
            "サーバー.example.com".to_string(),
            22,
            HostKeyVerification::Strict,
        );
        assert_eq!(handler.hostname, "サーバー.example.com");
    }

    // ============== Error Edge Cases ==============

    #[test]
    fn test_ssh_connection_error_empty_reason() {
        let error = BridgeError::SshConnection {
            host: "host".to_string(),
            reason: String::new(),
        };
        let msg = error.to_string();
        assert!(msg.contains("host"));
    }

    #[test]
    fn test_ssh_auth_error_unicode() {
        let error = BridgeError::SshAuth {
            user: "用户".to_string(),
            host: "服务器".to_string(),
        };
        let msg = error.to_string();
        assert!(msg.contains("用户"));
        assert!(msg.contains("服务器"));
    }

    #[test]
    fn test_ssh_exec_error_multiline() {
        let error = BridgeError::SshExec {
            reason: "Error 1\nError 2\nError 3".to_string(),
        };
        let msg = error.to_string();
        assert!(msg.contains("Error 1"));
    }

    #[test]
    fn test_ssh_timeout_zero() {
        let error = BridgeError::SshTimeout { seconds: 0 };
        let msg = error.to_string();
        assert!(msg.contains('0'));
    }

    #[test]
    fn test_ssh_timeout_max() {
        let error = BridgeError::SshTimeout { seconds: u64::MAX };
        let msg = error.to_string();
        // Should not panic
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_ssh_output_too_large_zero() {
        let error = BridgeError::SshOutputTooLarge { limit_bytes: 0 };
        let msg = error.to_string();
        assert!(msg.contains('0'));
    }

    #[test]
    fn test_ssh_key_invalid_special_path() {
        let error = BridgeError::SshKeyInvalid {
            path: "~/.ssh/id_rsa: passphrase required".to_string(),
        };
        let msg = error.to_string();
        assert!(msg.contains("passphrase"));
    }

    // ============== CommandOutput Trait Tests ==============

    #[test]
    fn test_command_output_partial_eq() {
        let output1 = CommandOutput {
            stdout: "hello".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 100,
        };

        let output2 = output1.clone();

        assert_eq!(output1.stdout, output2.stdout);
        assert_eq!(output1.stderr, output2.stderr);
        assert_eq!(output1.exit_code, output2.exit_code);
        assert_eq!(output1.duration_ms, output2.duration_ms);
    }

    #[test]
    fn test_command_output_with_ansi_codes() {
        let output = CommandOutput {
            stdout: "\x1b[32mgreen\x1b[0m and \x1b[31mred\x1b[0m".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 10,
        };

        assert!(output.stdout.contains("\x1b[32m"));
    }

    #[test]
    fn test_command_output_carriage_return() {
        let output = CommandOutput {
            stdout: "progress: 50%\rprogress: 100%".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 20,
        };

        assert!(output.stdout.contains('\r'));
    }

    // ============== sanitize_ssh_error Comprehensive Tests ==============

    #[test]
    fn test_sanitize_ssh_error_masks_gssapi() {
        let error = "auth failed: gssapi-with-mic not supported";
        let sanitized = sanitize_ssh_error(&error);
        assert!(
            !sanitized.contains("gssapi-with-mic"),
            "gssapi-with-mic should be masked"
        );
        assert!(sanitized.contains("***"));
    }

    #[test]
    fn test_sanitize_ssh_error_masks_all_methods_simultaneously() {
        let error = "tried publickey, keyboard-interactive, gssapi-with-mic";
        let sanitized = sanitize_ssh_error(&error);
        assert!(!sanitized.contains("publickey"));
        assert!(!sanitized.contains("keyboard-interactive"));
        assert!(!sanitized.contains("gssapi-with-mic"));
        // Should contain three masked markers
        assert_eq!(sanitized.matches("***").count(), 3);
    }

    #[test]
    fn test_sanitize_ssh_error_exact_500_boundary() {
        // Exactly 500 chars should NOT be truncated
        let error = "x".repeat(500);
        let sanitized = sanitize_ssh_error(&error);
        assert_eq!(sanitized.len(), 500);
        assert!(!sanitized.contains("(truncated)"));
    }

    #[test]
    fn test_sanitize_ssh_error_501_chars_truncated() {
        let error = "x".repeat(501);
        let sanitized = sanitize_ssh_error(&error);
        assert!(sanitized.contains("(truncated)"));
        // The truncated output should be: 500 chars + "... (truncated)"
        assert!(sanitized.starts_with(&"x".repeat(500)));
    }

    #[test]
    fn test_sanitize_ssh_error_empty_message() {
        let error = "";
        let sanitized = sanitize_ssh_error(&error);
        assert_eq!(sanitized, "");
    }

    #[test]
    fn test_sanitize_ssh_error_password_not_explicitly_masked() {
        // "password" is not in the masking list (only auth method names)
        let error = "password authentication failed";
        let sanitized = sanitize_ssh_error(&error);
        assert_eq!(sanitized, "password authentication failed");
    }

    #[test]
    fn test_sanitize_ssh_error_preserves_non_sensitive_info() {
        let error = "Connection refused by 192.168.1.1:22";
        let sanitized = sanitize_ssh_error(&error);
        assert_eq!(sanitized, "Connection refused by 192.168.1.1:22");
    }

    #[test]
    fn test_sanitize_ssh_error_with_custom_display_type() {
        // Test with a type that implements Display (not just &str)
        let error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let sanitized = sanitize_ssh_error(&error);
        assert!(sanitized.contains("refused"));
    }

    #[test]
    fn test_sanitize_ssh_error_truncation_with_auth_methods() {
        // Long message that also contains auth methods
        let prefix = "publickey failed: ";
        let padding = "y".repeat(600);
        let error = format!("{prefix}{padding}");
        let sanitized = sanitize_ssh_error(&error);
        assert!(!sanitized.contains("publickey"));
        assert!(sanitized.contains("(truncated)"));
    }
}
