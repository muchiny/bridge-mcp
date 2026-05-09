use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub hosts: HashMap<String, HostConfig>,

    #[serde(default)]
    pub security: SecurityConfig,

    #[serde(default)]
    pub limits: LimitsConfig,

    #[serde(default)]
    pub audit: AuditConfig,

    #[serde(default)]
    pub sessions: SessionConfig,

    #[serde(default)]
    pub tool_groups: ToolGroupsConfig,

    #[serde(default)]
    pub ssh_config: SshConfigDiscovery,

    /// HTTP transport configuration (used with `--http` flag).
    #[serde(default)]
    pub http: HttpTransportConfig,

    /// Role-based access control configuration
    #[serde(default)]
    pub rbac: crate::security::rbac::RbacConfig,

    /// AWX REST API configuration for air-gapped relay via SSH.
    #[serde(default)]
    pub awx: Option<AwxConfig>,
}

/// AWX REST API configuration.
///
/// AWX API calls are relayed through SSH: the MCP server connects to
/// `ssh_host` via SSH and runs `curl` commands against the AWX URL.
/// This enables air-gapped environments where AWX is not directly
/// reachable from the MCP server host.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AwxConfig {
    /// SSH host alias (from `hosts` section) used to relay API calls.
    pub ssh_host: String,

    /// Base URL of the AWX instance (e.g., `https://awx.internal`).
    pub url: String,

    /// `OAuth2` Bearer token for AWX API authentication.
    pub token: String,

    /// Request timeout in seconds (default: 30).
    #[serde(default = "default_awx_timeout")]
    pub api_timeout: u32,

    /// Whether to verify SSL certificates (default: true).
    /// Set to false for self-signed certs in air-gapped environments.
    #[serde(default = "default_true")]
    pub verify_ssl: bool,
}

fn default_awx_timeout() -> u32 {
    30
}

fn default_true() -> bool {
    true
}

/// HTTP transport configuration for the YAML config.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTransportConfig {
    /// Bind address (default: `"127.0.0.1:3000"` — loopback only).
    #[serde(default = "default_http_bind")]
    pub bind: String,

    /// Maximum request body size in bytes (default: 1MB).
    #[serde(default = "default_http_max_body_size")]
    pub max_body_size: usize,

    /// Session timeout in seconds (default: 1800 = 30 minutes).
    #[serde(default = "default_http_session_timeout")]
    pub session_timeout_seconds: u64,

    /// Maximum concurrent sessions (default: 100).
    #[serde(default = "default_http_max_sessions")]
    pub max_sessions: usize,

    /// OAuth 2.0 configuration.
    #[serde(default)]
    pub oauth: HttpOAuthConfig,

    /// Allowlist of `Origin` headers (anti-DNS-rebinding, MCP 2025-11-25).
    /// Default: localhost variants only. Production servers MUST list
    /// their public origin (e.g. `https://app.example.com`).
    #[serde(default = "default_http_allowed_origins")]
    pub allowed_origins: Vec<String>,

    /// SECURITY: bypass the loopback-or-OAuth check enforced by `serve`.
    /// Required only when intentionally exposing the bridge on a public
    /// interface without OAuth (e.g. behind a separate auth proxy).
    /// Defaults to `false`.
    #[serde(default)]
    pub allow_unsafe_bind: bool,
}

impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self {
            bind: default_http_bind(),
            max_body_size: default_http_max_body_size(),
            session_timeout_seconds: default_http_session_timeout(),
            max_sessions: default_http_max_sessions(),
            oauth: HttpOAuthConfig::default(),
            allowed_origins: default_http_allowed_origins(),
            allow_unsafe_bind: false,
        }
    }
}

fn default_http_bind() -> String {
    "127.0.0.1:3000".to_string()
}

fn default_http_allowed_origins() -> Vec<String> {
    vec![
        "http://localhost".to_string(),
        "https://localhost".to_string(),
        "http://127.0.0.1".to_string(),
        "https://127.0.0.1".to_string(),
        "http://[::1]".to_string(),
        "https://[::1]".to_string(),
    ]
}

const fn default_http_max_body_size() -> usize {
    1_048_576
}

const fn default_http_session_timeout() -> u64 {
    1800
}

const fn default_http_max_sessions() -> usize {
    100
}

/// OAuth configuration for the HTTP transport (YAML-serializable).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpOAuthConfig {
    /// Enable OAuth authentication (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// Expected issuer (e.g., `"https://auth.example.com"`).
    #[serde(default)]
    pub issuer: String,

    /// Expected audience.
    #[serde(default)]
    pub audience: String,

    /// JWKS endpoint for key validation.
    ///
    /// NOTE: JWKS HTTP fetching is not yet wired in this build —
    /// configure [`Self::static_keys`] for now. The follow-up will pipe
    /// `reqwest`/`hyper` through extensions and fetch this document at
    /// boot.
    #[serde(default)]
    pub jwks_uri: Option<String>,

    /// OAuth client ID for this server.
    #[serde(default)]
    pub client_id: String,

    /// Required scopes for access.
    #[serde(default)]
    pub required_scopes: Vec<String>,

    /// Static signing keys for token validation, keyed by `kid`.
    ///
    /// Each entry is `(key_id, pem_encoded_public_key)`. Either
    /// `static_keys` or `jwks_uri` MUST be configured when
    /// `enabled = true`; otherwise the server fails closed at boot
    /// rather than rejecting every token at request time.
    #[serde(default)]
    pub static_keys: Vec<HttpOAuthStaticKey>,
}

/// A single OAuth signing key entry for static-key validation.
///
/// Used by [`HttpOAuthConfig::static_keys`] to populate the validator's
/// in-memory key map at boot. Keys are addressed by their JWT `kid`
/// header.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpOAuthStaticKey {
    /// JWT `kid` header value this key matches.
    pub kid: String,
    /// PEM-encoded RSA public key (PKCS#1 or `SubjectPublicKeyInfo`).
    pub public_key_pem: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub hostname: String,

    #[serde(default = "default_port")]
    pub port: u16,

    pub user: String,

    pub auth: AuthConfig,

    /// Optional description for this host
    #[serde(default)]
    pub description: Option<String>,

    /// Host key verification mode for this host
    #[serde(default)]
    pub host_key_verification: HostKeyVerification,

    /// Optional jump host (bastion) alias to connect through
    ///
    /// When set, the connection to this host will be tunneled through
    /// the specified jump host using SSH port forwarding.
    #[serde(default)]
    pub proxy_jump: Option<String>,

    /// Optional SOCKS proxy to connect through (alternative to `proxy_jump`).
    ///
    /// When set, the SSH connection will be tunneled through the specified
    /// SOCKS proxy. Mutually exclusive with `proxy_jump`.
    #[serde(default)]
    pub socks_proxy: Option<SocksProxyConfig>,

    /// Optional sudo password for this host (used with sudo commands).
    ///
    /// Wrapped in [`Zeroizing<String>`] so the byte buffer is overwritten when
    /// the value is dropped (FIND-028). Hot-reload via `config/watcher.rs`
    /// drops the old `HostConfig`, which now wipes the prior password
    /// instead of leaving it resident on the heap for the process lifetime.
    #[serde(default)]
    pub sudo_password: Option<Zeroizing<String>>,

    /// Tags for grouping hosts (e.g., "production", "staging", "database")
    #[serde(default)]
    pub tags: Vec<String>,

    /// Remote operating system type (default: linux).
    ///
    /// Affects shell escaping, session initialization, and available tool groups.
    #[serde(default)]
    pub os_type: OsType,

    /// Shell type used on the remote host.
    ///
    /// If not set, inferred from `os_type`: Linux -> posix, Windows -> cmd.
    /// Override to `powershell` if the Windows host has `PowerShell` as default shell.
    #[serde(default)]
    pub shell: Option<ShellType>,

    /// Per-host retry configuration override
    #[serde(default)]
    pub retry: Option<HostRetryConfig>,

    /// Remote execution protocol (default: ssh).
    ///
    /// Determines which adapter is used to connect and execute commands.
    /// When omitted, defaults to SSH for full backward compatibility.
    #[serde(default)]
    pub protocol: Protocol,

    /// Override TLS auto-detection for `WinRM`/PSRP (ignored for other protocols).
    ///
    /// By default, TLS is auto-detected from the port: 5986 = HTTPS, 5985 = HTTP.
    #[cfg(feature = "winrm")]
    #[serde(default)]
    pub winrm_use_tls: Option<bool>,

    /// Accept invalid TLS certificates for `WinRM`/PSRP endpoints.
    ///
    /// Set to `true` for self-signed certificates in test environments.
    /// Default: `false`.
    #[cfg(feature = "winrm")]
    #[serde(default)]
    pub winrm_accept_invalid_certs: Option<bool>,

    /// Operation timeout in seconds for `WinRM`/PSRP commands.
    ///
    /// Default: 60 seconds (matches `winrm-rs` default).
    #[cfg(feature = "winrm")]
    #[serde(default)]
    pub winrm_operation_timeout_secs: Option<u64>,

    /// Maximum SOAP envelope size in bytes for `WinRM`/PSRP.
    ///
    /// Default: 153600 (150 KB, matches `winrm-rs` default).
    #[cfg(feature = "winrm")]
    #[serde(default)]
    pub winrm_max_envelope_size: Option<u32>,
}

/// Per-host retry configuration override
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostRetryConfig {
    /// Maximum retry attempts (overrides global `limits.retry_attempts`)
    #[serde(default)]
    pub max_attempts: Option<u32>,

    /// Initial retry delay in milliseconds (overrides global `limits.retry_initial_delay_ms`)
    #[serde(default)]
    pub initial_delay_ms: Option<u64>,

    /// Maximum delay cap in milliseconds (default: 30000)
    #[serde(default)]
    pub max_delay_ms: Option<u64>,
}

impl HostConfig {
    /// Resolve the effective shell type for this host.
    ///
    /// If `shell` is explicitly set, use that. Otherwise, infer from `os_type`.
    #[must_use]
    pub fn effective_shell(&self) -> ShellType {
        self.shell.unwrap_or(match self.os_type {
            OsType::Linux => ShellType::Posix,
            OsType::Windows => ShellType::Cmd,
        })
    }

    /// Check if this host has a specific tag
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
    }
}

/// Host key verification mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HostKeyVerification {
    /// Strict: reject unknown hosts, reject mismatched keys (most secure, default)
    #[default]
    Strict,
    /// Accept new: add unknown hosts to `known_hosts`, reject mismatched keys
    AcceptNew,
    /// Off: accept all keys (insecure, for testing only)
    Off,
}

/// Remote operating system type.
///
/// Determines shell escaping rules, session initialization, and which
/// tool groups are available. Defaults to `Linux` for backward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    /// Linux/Unix host (default)
    #[default]
    Linux,
    /// Windows host via `OpenSSH` for Windows
    Windows,
}

/// Shell type used on the remote host.
///
/// Controls argument escaping and session initialization.
/// Inferred from `OsType` if not explicitly set:
/// `Linux` -> `Posix`, `Windows` -> `Cmd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ShellType {
    /// POSIX shell (bash, sh, zsh) -- single-quote escaping
    Posix,
    /// Windows `cmd.exe` -- caret escaping, double-quote wrapping
    Cmd,
    /// `PowerShell` (`pwsh` / `powershell.exe`) -- single-quote with doubling
    #[serde(alias = "pwsh")]
    PowerShell,
}

/// Remote execution protocol for a host.
///
/// Determines which adapter is used to execute commands on the host.
/// Defaults to `Ssh` for full backward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// SSH (default) — works for Linux, Windows (via `OpenSSH`), and modern network equipment
    #[default]
    Ssh,
    /// `WinRM` — Windows Remote Management (SOAP/WS-Man over HTTP/HTTPS)
    #[cfg(feature = "winrm")]
    #[serde(alias = "WinRM")]
    WinRm,
    /// PSRP — `PowerShell` Remoting Protocol (native PS over `WinRM` transport)
    #[cfg(feature = "psrp")]
    #[serde(alias = "PSRP")]
    Psrp,
    /// Telnet — legacy network equipment (Cisco IOS, switches, PLCs)
    #[cfg(feature = "telnet")]
    Telnet,
    /// Kubernetes Exec — direct pod command execution via K8s API
    #[cfg(feature = "k8s-exec")]
    #[serde(alias = "kubernetes", alias = "k8s")]
    K8sExec,
    /// Serial — RS-232/USB serial port communication (PLCs, embedded, console)
    #[cfg(feature = "serial")]
    Serial,
    /// AWS SSM — Systems Manager `SendCommand` for EC2 instances
    #[cfg(feature = "ssm")]
    Ssm,
    /// Azure Run Command — execute commands on Azure VMs via REST API
    #[cfg(feature = "azure")]
    Azure,
    /// GCP OS Command — execute commands on GCP VMs via `gcloud` CLI
    #[cfg(feature = "gcp")]
    Gcp,
}

const fn default_port() -> u16 {
    22
}

/// SOCKS proxy configuration for tunneling SSH connections
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocksProxyConfig {
    /// Proxy hostname or IP
    pub hostname: String,

    /// Proxy port (default: 1080)
    #[serde(default = "default_socks_port")]
    pub port: u16,

    /// SOCKS version: `socks5` (default) or `socks4`
    #[serde(default)]
    pub version: SocksVersion,

    /// Optional username for SOCKS5 authentication
    #[serde(default)]
    pub username: Option<String>,

    /// Optional password for SOCKS5 authentication.
    ///
    /// Wrapped in `Zeroizing<String>` so the byte buffer is overwritten
    /// when the value is dropped (FIND-014). `SocksProxyConfig` lives for
    /// the entire process; without `Zeroizing` the password sits in heap
    /// from start to exit.
    #[serde(default)]
    pub password: Option<Zeroizing<String>>,
}

/// SOCKS protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SocksVersion {
    /// SOCKS5 (default) - supports authentication and UDP
    #[default]
    Socks5,
    /// SOCKS4 - simpler, no authentication support
    Socks4,
}

const fn default_socks_port() -> u16 {
    1080
}

/// Authentication configuration.
///
/// SSH variants (`Key`, `Agent`, `Password`) are always available.
/// `WinRM` variants (`Ntlm`, `Certificate`, `Kerberos`) are feature-gated.
///
/// Sensitive fields (`password`, `passphrase`) are wrapped in [`Zeroizing`]
/// so they are securely erased from memory when the config is dropped
/// (e.g. on hot-reload or process exit).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    Key {
        path: String,
        #[serde(default)]
        passphrase: Option<Zeroizing<String>>,
    },
    Agent,
    Password {
        password: Zeroizing<String>,
    },
    /// `NTLMv2` authentication for `WinRM` (default `WinRM` auth method).
    #[cfg(feature = "winrm")]
    Ntlm {
        password: Zeroizing<String>,
        /// Windows domain (e.g., "CORP"). Optional — omit for local accounts.
        #[serde(default)]
        domain: Option<String>,
    },
    /// TLS client certificate authentication for `WinRM`.
    #[cfg(feature = "winrm")]
    Certificate {
        /// Path to the client certificate PEM file.
        cert_path: String,
        /// Path to the client private key PEM file.
        key_path: String,
    },
    /// Kerberos (SPNEGO) authentication for `WinRM`.
    ///
    /// Requires a valid TGT from `kinit` at runtime. The `kerberos`
    /// feature must be enabled in the `winrm-rs` dependency.
    #[cfg(feature = "winrm")]
    Kerberos,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default = "default_security_mode")]
    pub mode: SecurityMode,

    #[serde(default)]
    pub whitelist: Vec<String>,

    #[serde(default = "default_blacklist")]
    pub blacklist: Vec<String>,

    /// Legacy field for backward compatibility (use `sanitize` instead)
    #[serde(default)]
    pub sanitize_patterns: Vec<String>,

    /// Advanced sanitizer configuration
    #[serde(default)]
    pub sanitize: SanitizeConfig,

    /// Require MCP `elicitation/create` confirmation before executing tools
    /// annotated `destructive_hint: true`. When the client advertises the
    /// `elicitation` capability, the server asks the user to confirm; on
    /// decline/cancel the tool call returns an error without executing.
    /// When the client does not support elicitation, the call is rejected.
    ///
    /// Defaults to `true` (security-first); set to `false` to opt out
    /// (NOT RECOMMENDED in production — a compromised MCP client can
    /// mass-execute destructive tools without surfacing to a human).
    #[serde(default = "default_require_elicitation_on_destructive")]
    pub require_elicitation_on_destructive: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            mode: default_security_mode(),
            whitelist: Vec::new(),
            blacklist: default_blacklist(),
            sanitize_patterns: Vec::new(),
            sanitize: SanitizeConfig::default(),
            require_elicitation_on_destructive: default_require_elicitation_on_destructive(),
        }
    }
}

/// Default for `SecurityConfig::require_elicitation_on_destructive`.
///
/// FIND-022: defaults to `true` (security-first). Operators who want the
/// legacy permissive behaviour must opt out explicitly via
/// `security.require_elicitation_on_destructive: false`.
fn default_require_elicitation_on_destructive() -> bool {
    true
}

/// Advanced sanitizer configuration
///
/// Allows fine-grained control over output sanitization:
/// - Enable/disable sanitization
/// - Disable specific builtin pattern categories
/// - Add custom patterns with custom replacement text
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizeConfig {
    /// Enable/disable sanitization entirely (default: true)
    #[serde(default = "default_sanitize_enabled")]
    pub enabled: bool,

    /// Builtin pattern categories to disable.
    ///
    /// Available categories:
    /// - `"github"` - GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
    /// - `"gitlab"` - GitLab tokens (glpat-)
    /// - `"slack"` - Slack tokens and webhooks
    /// - `"discord"` - Discord webhooks
    /// - `"openai"` - `OpenAI` API keys (sk-)
    /// - `"aws"` - AWS credentials (AKIA, access keys, session tokens)
    /// - `"k3s"` - K3s/Kubernetes tokens
    /// - `"jwt"` - JWT tokens (eyJ...)
    /// - `"certificates"` - Private keys (RSA, OpenSSH, EC, PGP)
    /// - `"kubeconfig"` - Kubeconfig credentials
    /// - `"docker"` - Docker registry auth and login
    /// - `"database"` - Database connection strings and passwords
    /// - `"ansible"` - Ansible vault and become passwords
    /// - `"azure"` - Azure credentials
    /// - `"gcp"` - Google Cloud credentials
    /// - `"hashicorp"` - Vault and Consul tokens
    /// - `"generic"` - Generic password/secret/token patterns
    #[serde(default)]
    pub disable_builtin: Vec<String>,

    /// Custom patterns with custom replacements
    #[serde(default)]
    pub custom_patterns: Vec<CustomSanitizePattern>,

    /// Enable entropy-based secret detection (default: true)
    ///
    /// Detects high-entropy strings that may be secrets even when
    /// they don't match any known pattern (e.g., random API keys).
    #[serde(default = "default_sanitize_enabled")]
    pub entropy_detection: bool,

    /// Shannon entropy threshold in bits per character (default: 4.5)
    ///
    /// Tokens with entropy above this value are considered potential secrets.
    /// - English text: ~3.5-4.5 bits
    /// - Hex secrets: ~3.7-4.0 bits
    /// - Base64 secrets: ~5.0-6.0 bits
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,

    /// Minimum token length for entropy analysis (default: 16)
    #[serde(default = "default_entropy_min_length")]
    pub entropy_min_length: usize,

    /// Known safe strings to exclude from entropy detection
    #[serde(default)]
    pub entropy_whitelist: Vec<String>,
}

const fn default_entropy_threshold() -> f64 {
    4.5
}

const fn default_entropy_min_length() -> usize {
    16
}

impl Default for SanitizeConfig {
    fn default() -> Self {
        Self {
            enabled: default_sanitize_enabled(),
            disable_builtin: Vec::new(),
            custom_patterns: Vec::new(),
            entropy_detection: true,
            entropy_threshold: default_entropy_threshold(),
            entropy_min_length: default_entropy_min_length(),
            entropy_whitelist: Vec::new(),
        }
    }
}

const fn default_sanitize_enabled() -> bool {
    true
}

/// Custom sanitization pattern with configurable replacement
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomSanitizePattern {
    /// Regex pattern to match sensitive data
    pub pattern: String,

    /// Replacement text (default: `[REDACTED]`)
    /// Supports capture groups: $1, $2, etc.
    #[serde(default = "default_replacement")]
    pub replacement: String,

    /// Optional description for documentation/debugging
    #[serde(default)]
    pub description: Option<String>,
}

fn default_replacement() -> String {
    "[REDACTED]".to_string()
}

const fn default_security_mode() -> SecurityMode {
    SecurityMode::Standard
}

fn default_blacklist() -> Vec<String> {
    vec![
        r"(?i)rm\s+-rf\s+/".to_string(),
        r"(?i)mkfs\.".to_string(),
        r"(?i)dd\s+if=".to_string(),
        r"(?i)>\s*/dev/".to_string(),
        r"(?i)chmod\s+777".to_string(),
        r"(?i)curl.*\|.*sh".to_string(),
        r"(?i)wget.*\|.*sh".to_string(),
        r"(?i)\breboot\b".to_string(),
        r"(?i)\bpoweroff\b".to_string(),
        r"(?i)\bhalt\b".to_string(),
        r"(?i)\bshutdown\b".to_string(),
        r"(?i)\biptables\s+-F\b".to_string(),
        // Redis destructive commands
        r"(?i)\bredis-cli\b.*\b(FLUSHALL|FLUSHDB|SHUTDOWN)\b".to_string(),
        // Terraform destructive commands
        r"(?i)\bterraform\s+destroy\b".to_string(),
        r"(?i)\bterraform\s+state\s+rm\b".to_string(),
        // Vault destructive commands
        r"(?i)\bvault\s+(delete|kv\s+delete)\b".to_string(),
        // Systemd service disruption
        r"(?i)\bsystemctl\s+(stop|disable|isolate)\b".to_string(),
        // Cron wipe
        r"(?i)\bcrontab\s+-r\b".to_string(),
        // Firewall disable
        r"(?i)\bufw\s+disable\b".to_string(),
        // Nginx stop
        r"(?i)\bnginx\s+-s\s+stop\b".to_string(),
        // === Windows dangerous commands ===
        // Recursive deletion (rd /s, Remove-Item -Recurse)
        r"(?i)\brd\s+/s".to_string(),
        r"(?i)\bRemove-Item\b.*-Recurse".to_string(),
        // Disk formatting
        r"(?i)\bformat\s+[a-z]:".to_string(),
        r"(?i)\bdiskpart\b".to_string(),
        // System shutdown/restart
        r"(?i)\bRestart-Computer\b".to_string(),
        r"(?i)\bStop-Computer\b".to_string(),
        // Dangerous code execution via PowerShell
        r"(?i)\bInvoke-Expression\b".to_string(),
        r"(?i)\biex\b".to_string(),
        r"(?i)Invoke-WebRequest.*\|.*Invoke-Expression".to_string(),
        // Firewall disable
        r"(?i)\bnetsh\s+advfirewall\s+set\b.*\boff\b".to_string(),
        r"(?i)\bSet-NetFirewallProfile\b.*\bFalse\b".to_string(),
        // Service deletion
        r"(?i)\bsc\s+delete\b".to_string(),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityMode {
    Strict,
    #[serde(alias = "normal")]
    Standard,
    Permissive,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_command_timeout")]
    pub command_timeout_seconds: u64,

    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: usize,

    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_commands: usize,

    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_seconds: u64,

    #[serde(default = "default_keepalive")]
    pub keepalive_interval_seconds: u64,

    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,

    #[serde(default = "default_retry_initial_delay_ms")]
    pub retry_initial_delay_ms: u64,

    /// Rate limit: maximum requests per second per host (0 = disabled, default: 10)
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_second: u32,

    /// Maximum output characters returned by tool calls (default: 20000).
    /// Individual tool calls can override this with their `max_output` parameter.
    /// At ~3-4 chars/token, 40000 chars ≈ 10-13K tokens — a safe default that
    /// works with all AI models. Use `client_overrides` to raise for larger-context models.
    /// Set to 0 to disable truncation.
    #[serde(default = "default_max_output_chars")]
    pub max_output_chars: usize,

    /// Per-client overrides for `max_output_chars`, matched by MCP client name.
    /// Detected automatically during MCP `initialize` handshake.
    /// Built-in defaults for known clients (Claude, Cursor, etc.) are applied
    /// when this field is absent from YAML config.
    #[serde(default = "default_client_overrides")]
    pub client_overrides: Vec<ClientOverride>,

    /// TTL in seconds for cached full outputs used by `ssh_output_fetch` pagination
    /// (default: 300 = 5 minutes)
    #[serde(default = "default_output_cache_ttl")]
    pub output_cache_ttl_seconds: u64,

    /// Maximum number of cached output entries kept in memory (default: 100)
    #[serde(default = "default_output_cache_max_entries")]
    pub output_cache_max_entries: usize,

    /// Maximum number of concurrent async tasks (default: 50).
    /// When the limit is reached, new task-augmented requests are rejected.
    #[serde(default = "default_max_tasks")]
    pub max_tasks: usize,

    /// Maximum TTL for async tasks in milliseconds (default: 3600000 = 1 hour).
    /// Client-requested TTLs are capped to this value.
    #[serde(default = "default_max_task_ttl_ms")]
    pub max_task_ttl_ms: u64,

    /// Default poll interval hint for async tasks in milliseconds (default: 2000).
    /// Clients use this to determine how often to poll `tasks/get`.
    #[serde(default = "default_task_poll_interval_ms")]
    pub task_poll_interval_ms: u64,

    /// Timeout in seconds for server-to-client requests (elicitation, sampling).
    /// Default: 120 seconds.
    #[serde(default = "default_client_request_timeout")]
    pub client_request_timeout_seconds: u64,

    /// Maximum tokens for sampling `createMessage` requests (default: 4096).
    #[serde(default = "default_sampling_max_tokens")]
    pub sampling_max_tokens: u32,

    /// Content size threshold in bytes above which `ssh_file_write` uses SFTP
    /// streaming instead of shell commands (default: 65536 = 64 KB).
    /// Set to 0 to always use SFTP.
    #[serde(default = "default_sftp_write_threshold")]
    pub sftp_write_threshold_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            command_timeout_seconds: default_command_timeout(),
            max_output_bytes: default_max_output_bytes(),
            max_concurrent_commands: default_max_concurrent(),
            connection_timeout_seconds: default_connection_timeout(),
            keepalive_interval_seconds: default_keepalive(),
            retry_attempts: default_retry_attempts(),
            retry_initial_delay_ms: default_retry_initial_delay_ms(),
            rate_limit_per_second: default_rate_limit(),
            max_output_chars: default_max_output_chars(),
            client_overrides: default_client_overrides(),
            output_cache_ttl_seconds: default_output_cache_ttl(),
            output_cache_max_entries: default_output_cache_max_entries(),
            max_tasks: default_max_tasks(),
            max_task_ttl_ms: default_max_task_ttl_ms(),
            task_poll_interval_ms: default_task_poll_interval_ms(),
            client_request_timeout_seconds: default_client_request_timeout(),
            sampling_max_tokens: default_sampling_max_tokens(),
            sftp_write_threshold_bytes: default_sftp_write_threshold(),
        }
    }
}

impl LimitsConfig {
    /// Create a `RetryConfig` from these limits settings
    #[must_use]
    pub fn retry_config(&self) -> crate::ssh::RetryConfig {
        crate::ssh::RetryConfig {
            max_attempts: self.retry_attempts,
            initial_delay_ms: self.retry_initial_delay_ms,
            ..Default::default()
        }
    }

    /// Resolve the effective `max_output_chars` for a given MCP client.
    ///
    /// Resolution order:
    /// 1. First matching `client_overrides` entry (case-insensitive, using `match_mode`)
    /// 2. `self.max_output_chars` (YAML config or default)
    #[must_use]
    pub fn effective_max_output_chars(&self, client_name: Option<&str>) -> usize {
        if let Some(name) = client_name {
            let name_lower = name.to_lowercase();
            for ov in &self.client_overrides {
                let pattern = ov.name_contains.to_lowercase();
                let matched = match ov.match_mode {
                    MatchMode::Exact => name_lower == pattern,
                    MatchMode::Prefix => name_lower.starts_with(&pattern),
                    MatchMode::Contains => name_lower.contains(&pattern),
                };
                if matched && let Some(max) = ov.max_output_chars {
                    return max;
                }
            }
        }
        self.max_output_chars
    }
}

/// How to match the `name_contains` pattern against the MCP client name.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    /// Exact match (case-insensitive): `"claude-code"` matches `"Claude-Code"`
    Exact,
    /// Prefix match (case-insensitive): `"claude"` matches `"claude-code"` but not `"not-claude"`
    #[default]
    Prefix,
    /// Substring match (case-insensitive): `"claude"` matches `"not-claude"` (legacy behavior)
    Contains,
}

/// Per-client override for output limits, matched by MCP client name.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientOverride {
    /// Pattern to match against the MCP client name (case-insensitive)
    pub name_contains: String,

    /// How to match the pattern against the client name (default: prefix)
    #[serde(default)]
    pub match_mode: MatchMode,

    /// Override for `max_output_chars` when this client is detected
    #[serde(default)]
    pub max_output_chars: Option<usize>,
}

const fn default_command_timeout() -> u64 {
    1800 // 30 minutes - supports long-running tasks like Molecule tests
}

const fn default_max_output_bytes() -> usize {
    10 * 1024 * 1024 // 10MB
}

const fn default_max_concurrent() -> usize {
    5
}

const fn default_connection_timeout() -> u64 {
    10
}

const fn default_keepalive() -> u64 {
    30
}

const fn default_retry_attempts() -> u32 {
    3
}

const fn default_retry_initial_delay_ms() -> u64 {
    100
}

const fn default_rate_limit() -> u32 {
    10 // 10 requests/second per host
}

const fn default_max_output_chars() -> usize {
    40_000 // ~10-13K tokens, safe for 128K+ context models
}

/// Built-in client overrides for known MCP clients.
///
/// These are applied automatically when no `client_overrides` are configured
/// in the YAML config. If the user provides any `client_overrides` in YAML,
/// serde replaces this entire Vec with the user's list.
fn default_client_overrides() -> Vec<ClientOverride> {
    vec![
        // Tier 1: Claude-based clients (200K context) → 80K chars (~20K tokens, ~10%)
        ClientOverride {
            name_contains: "claude".into(),
            match_mode: MatchMode::Prefix,
            max_output_chars: Some(80_000),
        },
        ClientOverride {
            name_contains: "cline".into(),
            match_mode: MatchMode::Prefix,
            max_output_chars: Some(80_000),
        },
        // Tier 2: Multi-model clients (128-200K context) → 50K chars (~13K tokens)
        ClientOverride {
            name_contains: "cursor".into(),
            match_mode: MatchMode::Prefix,
            max_output_chars: Some(50_000),
        },
        ClientOverride {
            name_contains: "windsurf".into(),
            match_mode: MatchMode::Prefix,
            max_output_chars: Some(50_000),
        },
        ClientOverride {
            name_contains: "copilot".into(),
            match_mode: MatchMode::Prefix,
            max_output_chars: Some(50_000),
        },
        ClientOverride {
            name_contains: "zed".into(),
            match_mode: MatchMode::Prefix,
            max_output_chars: Some(50_000),
        },
        // Tier 3: Model-agnostic clients (unknown context) → 30K chars (~8K tokens)
        ClientOverride {
            name_contains: "continue".into(),
            match_mode: MatchMode::Prefix,
            max_output_chars: Some(30_000),
        },
    ]
}

const fn default_output_cache_ttl() -> u64 {
    300 // 5 minutes
}

const fn default_output_cache_max_entries() -> usize {
    100
}

const fn default_max_tasks() -> usize {
    50
}

const fn default_max_task_ttl_ms() -> u64 {
    3_600_000 // 1 hour
}

const fn default_task_poll_interval_ms() -> u64 {
    2_000 // 2 seconds
}

const fn default_client_request_timeout() -> u64 {
    120
}

const fn default_sampling_max_tokens() -> u32 {
    4096
}

const fn default_sftp_write_threshold() -> usize {
    65_536 // 64 KB — well below ARG_MAX on all platforms
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(default = "default_audit_enabled")]
    pub enabled: bool,

    #[serde(default = "default_audit_path")]
    pub path: PathBuf,

    #[serde(default = "default_audit_max_size")]
    pub max_size_mb: u64,

    #[serde(default = "default_audit_retain")]
    pub retain_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: default_audit_enabled(),
            path: default_audit_path(),
            max_size_mb: default_audit_max_size(),
            retain_days: default_audit_retain(),
        }
    }
}

const fn default_audit_enabled() -> bool {
    true
}

fn default_audit_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mcp-ssh-bridge")
        .join("audit.log")
}

const fn default_audit_max_size() -> u64 {
    100
}

const fn default_audit_retain() -> u32 {
    30
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// Maximum number of concurrent sessions
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,

    /// Idle timeout in seconds before a session is closed
    #[serde(default = "default_session_idle_timeout")]
    pub idle_timeout_seconds: u64,

    /// Maximum session age in seconds before forced closure
    #[serde(default = "default_session_max_age")]
    pub max_age_seconds: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_sessions: default_max_sessions(),
            idle_timeout_seconds: default_session_idle_timeout(),
            max_age_seconds: default_session_max_age(),
        }
    }
}

const fn default_max_sessions() -> usize {
    10
}

const fn default_session_idle_timeout() -> u64 {
    300 // 5 minutes
}

const fn default_session_max_age() -> u64 {
    3600 // 1 hour
}

/// SSH config auto-discovery configuration
///
/// When enabled, the bridge will parse `~/.ssh/config` and automatically
/// discover hosts. YAML-defined hosts take precedence over discovered ones.
/// FIND-023: disabled by default. Enabling exposes the operator's full
/// personal SSH host inventory (often >> the YAML-declared production set)
/// to MCP clients via the bridge's host-listing surfaces. Operators who
/// want the time-to-first-command convenience must opt in explicitly.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshConfigDiscovery {
    /// Enable SSH config auto-discovery (default: false — FIND-023).
    #[serde(default = "default_ssh_config_enabled")]
    pub enabled: bool,

    /// Path to the SSH config file (default: `~/.ssh/config`)
    #[serde(default = "default_ssh_config_path")]
    pub path: String,

    /// Host aliases to exclude from discovery
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl Default for SshConfigDiscovery {
    fn default() -> Self {
        Self {
            enabled: default_ssh_config_enabled(),
            path: default_ssh_config_path(),
            exclude: Vec::new(),
        }
    }
}

const fn default_ssh_config_enabled() -> bool {
    // FIND-023: discovery is opt-in. See SshConfigDiscovery doc comment.
    false
}

fn default_ssh_config_path() -> String {
    "~/.ssh/config".to_string()
}

/// Tool group activation configuration
///
/// Allows enabling or disabling groups of tools to reduce the MCP context
/// sent to the LLM. By default, all groups are enabled.
///
/// Available groups (74 groups, 337 tools):
///
/// Linux groups (59):
/// - `core`: `ssh_exec`, `ssh_exec_multi`, `ssh_status`, `ssh_health`, `ssh_history`,
///   `ssh_output_fetch`
/// - `file_transfer`: `ssh_upload`, `ssh_download`, `ssh_sync`
/// - `file_ops`: `ssh_file_read`, `ssh_file_write`, `ssh_files_write`, `ssh_file_chmod`,
///   `ssh_file_chown`, `ssh_file_stat`, `ssh_file_diff`, `ssh_file_patch`, `ssh_file_template`
/// - `sessions`: `ssh_session_create`, `ssh_session_exec`, `ssh_session_list`,
///   `ssh_session_close`
/// - `directory`: `ssh_ls`, `ssh_find`
/// - `monitoring`: `ssh_metrics`, `ssh_metrics_multi`, `ssh_tail`, `ssh_disk_usage`
/// - `tunnels`: `ssh_tunnel_create`, `ssh_tunnel_list`, `ssh_tunnel_close`
/// - `process`: `ssh_process_list`, `ssh_process_kill`, `ssh_process_top`
/// - `network`: `ssh_net_connections`, `ssh_net_interfaces`, `ssh_net_routes`, `ssh_net_ping`,
///   `ssh_net_traceroute`, `ssh_net_dns`
/// - `systemd`: `ssh_service_status`, `ssh_service_start`, `ssh_service_stop`,
///   `ssh_service_restart`, `ssh_service_list`, `ssh_service_logs`, `ssh_service_enable`,
///   `ssh_service_disable`, `ssh_service_daemon_reload`
/// - `systemd_timers`: `ssh_timer_list`, `ssh_timer_info`, `ssh_timer_enable`,
///   `ssh_timer_disable`, `ssh_timer_trigger`
/// - `firewall`: `ssh_firewall_status`, `ssh_firewall_list`, `ssh_firewall_allow`,
///   `ssh_firewall_deny`
/// - `package`: `ssh_pkg_list`, `ssh_pkg_search`, `ssh_pkg_install`, `ssh_pkg_update`,
///   `ssh_pkg_remove`
/// - `cron`: `ssh_cron_list`, `ssh_cron_add`, `ssh_cron_remove`
/// - `user_management`: `ssh_user_list`, `ssh_user_info`, `ssh_user_add`, `ssh_user_modify`,
///   `ssh_user_delete`, `ssh_group_list`, `ssh_group_add`, `ssh_group_delete`
/// - `storage`: `ssh_storage_lsblk`, `ssh_storage_df`, `ssh_storage_mount`,
///   `ssh_storage_umount`, `ssh_storage_lvm`, `ssh_storage_fdisk`, `ssh_storage_fstab`
/// - `journald`: `ssh_journal_query`, `ssh_journal_follow`, `ssh_journal_boots`,
///   `ssh_journal_disk_usage`
/// - `security_modules`: `ssh_selinux_status`, `ssh_selinux_booleans`,
///   `ssh_apparmor_status`, `ssh_apparmor_profiles`, `ssh_security_audit`
/// - `backup`: `ssh_backup_create`, `ssh_backup_list`, `ssh_backup_restore`,
///   `ssh_backup_snapshot`, `ssh_backup_verify`, `ssh_backup_schedule`
/// - `network_equipment`: `ssh_net_equip_show_run`, `ssh_net_equip_show_interfaces`,
///   `ssh_net_equip_show_routes`, `ssh_net_equip_show_arp`, `ssh_net_equip_show_version`,
///   `ssh_net_equip_show_vlans`, `ssh_net_equip_config`, `ssh_net_equip_save`
/// - `ldap`: `ssh_ldap_search`, `ssh_ldap_user_info`, `ssh_ldap_group_members`,
///   `ssh_ldap_add`, `ssh_ldap_modify`
/// - `database`: `ssh_db_query`, `ssh_db_dump`, `ssh_db_restore`
/// - `redis`: `ssh_redis_info`, `ssh_redis_cli`, `ssh_redis_keys`
/// - `postgresql`: `ssh_postgresql_query`, `ssh_postgresql_status`
/// - `mysql`: `ssh_mysql_query`, `ssh_mysql_status`
/// - `mongodb`: `ssh_mongodb_status`
/// - `docker`: `ssh_docker_ps`, `ssh_docker_logs`, `ssh_docker_inspect`, `ssh_docker_exec`,
///   `ssh_docker_compose`, `ssh_docker_images`, `ssh_docker_stats`, `ssh_docker_volume_ls`,
///   `ssh_docker_network_ls`, `ssh_docker_volume_inspect`, `ssh_docker_network_inspect`
/// - `podman`: `ssh_podman_ps`, `ssh_podman_logs`, `ssh_podman_inspect`, `ssh_podman_exec`,
///   `ssh_podman_images`, `ssh_podman_compose`
/// - `kubernetes`: `ssh_k8s_get`, `ssh_k8s_logs`, `ssh_k8s_describe`, `ssh_k8s_apply`,
///   `ssh_k8s_delete`, `ssh_k8s_rollout`, `ssh_k8s_scale`, `ssh_k8s_exec`, `ssh_k8s_top`,
///   `ssh_helm_list`, `ssh_helm_status`, `ssh_helm_upgrade`, `ssh_helm_install`,
///   `ssh_helm_rollback`, `ssh_helm_history`, `ssh_helm_uninstall`
/// - `esxi`: `ssh_esxi_vm_list`, `ssh_esxi_vm_info`, `ssh_esxi_vm_power`, `ssh_esxi_snapshot`,
///   `ssh_esxi_host_info`, `ssh_esxi_datastore_list`, `ssh_esxi_network_list`
/// - `nginx`: `ssh_nginx_status`, `ssh_nginx_test`, `ssh_nginx_reload`, `ssh_nginx_list_sites`
/// - `apache`: `ssh_apache_status`, `ssh_apache_vhosts`
/// - `letsencrypt`: `ssh_letsencrypt_status`
/// - `ansible`: `ssh_ansible_playbook`, `ssh_ansible_inventory`, `ssh_ansible_adhoc`,
///   `ssh_ansible_config`, `ssh_ansible_facts`, `ssh_ansible_lint`, `ssh_ansible_recap`,
///   `ssh_ansible_events`, `ssh_ansible_run_background`
/// - `awx`: `ssh_awx_status`, `ssh_awx_templates`, `ssh_awx_template_detail`,
///   `ssh_awx_job_launch`, `ssh_awx_job_status`, `ssh_awx_job_events`,
///   `ssh_awx_job_summary`, `ssh_awx_job_stdout`, `ssh_awx_job_cancel`,
///   `ssh_awx_inventories`, `ssh_awx_inventory_hosts`, `ssh_awx_project_sync`,
///   `ssh_awx_job_follow`
/// - `terraform`: `ssh_terraform_init`, `ssh_terraform_plan`, `ssh_terraform_apply`,
///   `ssh_terraform_state`, `ssh_terraform_output`
/// - `vault`: `ssh_vault_status`, `ssh_vault_read`, `ssh_vault_list`, `ssh_vault_write`
/// - `git`: `ssh_git_status`, `ssh_git_log`, `ssh_git_diff`, `ssh_git_pull`, `ssh_git_clone`,
///   `ssh_git_branch`, `ssh_git_checkout`
/// - `certificates`: `ssh_cert_check`, `ssh_cert_info`, `ssh_cert_expiry`
/// - `network_security`: `ssh_port_scan`, `ssh_ssl_audit`, `ssh_network_capture`,
///   `ssh_fail2ban_status`
/// - `compliance`: `ssh_cis_benchmark`, `ssh_stig_check`, `ssh_compliance_score`,
///   `ssh_compliance_report`
/// - `security_scan`: `ssh_sbom_generate`, `ssh_vuln_scan`, `ssh_compliance_check`
/// - `diagnostics`: `ssh_diagnose`, `ssh_incident_triage`, `ssh_compare_state`
/// - `performance`: `ssh_perf_trace`, `ssh_io_trace`, `ssh_latency_test`, `ssh_benchmark`
/// - `container_logs`: `ssh_container_log_search`, `ssh_container_log_stats`,
///   `ssh_container_events`, `ssh_container_health_history`
/// - `cron_analysis`: `ssh_cron_analyze`, `ssh_cron_history`, `ssh_at_jobs`
/// - `drift`: `ssh_env_snapshot`, `ssh_env_diff`, `ssh_env_drift`
/// - `cloud`: `ssh_aws_cli`, `ssh_cloud_metadata`, `ssh_cloud_tags`, `ssh_cloud_cost`
/// - `inventory`: `ssh_discover_hosts`, `ssh_inventory_sync`, `ssh_host_tags`
/// - `multicloud`: `ssh_multicloud_list`, `ssh_multicloud_sync`, `ssh_multicloud_compare`
/// - `alerting`: `ssh_alert_check`, `ssh_alert_list`, `ssh_alert_set`
/// - `capacity`: `ssh_capacity_collect`, `ssh_capacity_trend`, `ssh_capacity_predict`
/// - `incident`: `ssh_incident_timeline`, `ssh_incident_correlate`
/// - `orchestration`: `ssh_canary_exec`, `ssh_rolling_exec`, `ssh_fleet_diff`
/// - `runbooks`: `ssh_runbook_list`, `ssh_runbook_execute`, `ssh_runbook_validate`
/// - `log_aggregation`: `ssh_log_aggregate`, `ssh_log_search_multi`, `ssh_log_tail_multi`
/// - `key_management`: `ssh_key_generate`, `ssh_key_distribute`, `ssh_key_audit`
/// - `chatops`: `ssh_webhook_send`, `ssh_notify`
/// - `templates`: `ssh_template_list`, `ssh_template_show`, `ssh_template_apply`,
///   `ssh_template_validate`, `ssh_template_diff`
/// - `pty`: `ssh_pty_exec`, `ssh_pty_interact`, `ssh_pty_resize`
///
/// Windows groups (13):
/// - `windows_services`: `ssh_win_service_status`, `ssh_win_service_start`,
///   `ssh_win_service_stop`, `ssh_win_service_restart`, `ssh_win_service_list`,
///   `ssh_win_service_enable`, `ssh_win_service_disable`, `ssh_win_service_config`
/// - `windows_events`: `ssh_win_event_logs`, `ssh_win_event_query`,
///   `ssh_win_event_sources`, `ssh_win_event_tail`, `ssh_win_event_export`
/// - `active_directory`: `ssh_ad_user_list`, `ssh_ad_user_info`, `ssh_ad_group_list`,
///   `ssh_ad_group_members`, `ssh_ad_computer_list`, `ssh_ad_domain_info`
/// - `scheduled_tasks`: `ssh_schtask_list`, `ssh_schtask_info`, `ssh_schtask_run`,
///   `ssh_schtask_enable`, `ssh_schtask_disable`
/// - `windows_firewall`: `ssh_win_firewall_status`, `ssh_win_firewall_list`,
///   `ssh_win_firewall_allow`, `ssh_win_firewall_deny`, `ssh_win_firewall_remove`
/// - `iis`: `ssh_iis_status`, `ssh_iis_list_sites`, `ssh_iis_list_pools`, `ssh_iis_start`,
///   `ssh_iis_stop`, `ssh_iis_restart`
/// - `windows_updates`: `ssh_win_update_list`, `ssh_win_update_history`,
///   `ssh_win_update_install`, `ssh_win_update_search`, `ssh_win_update_reboot`
/// - `windows_perf`: `ssh_win_perf_cpu`, `ssh_win_perf_memory`, `ssh_win_perf_disk`,
///   `ssh_win_perf_network`, `ssh_win_perf_overview`, `ssh_win_disk_usage`
/// - `hyperv`: `ssh_hyperv_vm_list`, `ssh_hyperv_vm_info`, `ssh_hyperv_vm_start`,
///   `ssh_hyperv_vm_stop`, `ssh_hyperv_snapshot_list`, `ssh_hyperv_snapshot_create`,
///   `ssh_hyperv_host_info`, `ssh_hyperv_switch_list`
/// - `windows_registry`: `ssh_reg_query`, `ssh_reg_set`, `ssh_reg_list`, `ssh_reg_export`,
///   `ssh_reg_delete`
/// - `windows_features`: `ssh_win_feature_list`, `ssh_win_feature_info`,
///   `ssh_win_feature_install`, `ssh_win_feature_remove`
/// - `windows_network`: `ssh_win_net_adapters`, `ssh_win_net_ip`, `ssh_win_net_routes`,
///   `ssh_win_net_connections`, `ssh_win_net_ping`, `ssh_win_net_dns`
/// - `windows_process`: `ssh_win_process_list`, `ssh_win_process_info`,
///   `ssh_win_process_kill`, `ssh_win_process_top`, `ssh_win_process_by_name`
///
/// Cross-platform groups (2):
/// - `config`: `ssh_config_get`, `ssh_config_set`
/// - `recording`: `ssh_recording_start`, `ssh_recording_stop`, `ssh_recording_list`,
///   `ssh_recording_replay`, `ssh_recording_verify`
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolGroupsConfig {
    /// Map of group name to enabled status.
    ///
    /// FIND-024 (audit 2026-05-09): unlisted groups are now treated as
    /// **disabled** unless they appear in [`MINIMAL_DEFAULT_GROUPS`]. The
    /// previous semantics (unlisted = enabled) exposed all 75 groups /
    /// 357 handlers out of the box, violating least-privilege for
    /// operators who only need a small subset (e.g. `docker` + `service`).
    ///
    /// The default value is an empty map; resolution falls through to
    /// `MINIMAL_DEFAULT_GROUPS` membership in [`Self::is_group_enabled`].
    /// A YAML config that explicitly lists `core: false` still wins over
    /// the default profile.
    ///
    /// To enable a non-default group, list it explicitly with `true`. To
    /// disable a group from the default profile, list it with `false`.
    #[serde(default)]
    pub groups: HashMap<String, bool>,
}

/// Default-enabled tool groups (FIND-024).
///
/// Covers the eight groups that nearly every operator workflow uses:
/// raw exec, file ops, directory listing, process management, system
/// monitoring, network diagnostics, systemd service management, and
/// persistent tmux sessions. Everything else (containers, K8s, AD/LDAP,
/// cloud, `ESXi`, Hyper-V, Windows-specific, etc.) requires explicit
/// opt-in via the YAML map.
pub const MINIMAL_DEFAULT_GROUPS: &[&str] = &[
    "core",
    "file_ops",
    "directory",
    "process",
    "monitoring",
    "network",
    "systemd",
    "sessions",
];

impl ToolGroupsConfig {
    /// Check if a given tool group is enabled.
    ///
    /// Resolution order:
    /// 1. If the group appears in `self.groups` with an explicit value, use it.
    /// 2. Otherwise, group is enabled iff it is in [`MINIMAL_DEFAULT_GROUPS`].
    #[must_use]
    pub fn is_group_enabled(&self, group: &str) -> bool {
        match self.groups.get(group).copied() {
            Some(explicit) => explicit,
            None => MINIMAL_DEFAULT_GROUPS.contains(&group),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== SecurityConfig Tests ==============

    #[test]
    fn test_security_config_default() {
        let config = SecurityConfig::default();
        assert_eq!(config.mode, SecurityMode::Standard);
        assert!(config.whitelist.is_empty());
        assert!(!config.blacklist.is_empty()); // Has default blacklist
        assert!(config.sanitize_patterns.is_empty());
        assert!(config.sanitize.enabled);
    }

    #[test]
    fn test_security_mode_serialization() {
        let strict = SecurityMode::Strict;
        let standard = SecurityMode::Standard;
        let permissive = SecurityMode::Permissive;

        assert_eq!(serde_json::to_string(&strict).unwrap(), "\"strict\"");
        assert_eq!(serde_json::to_string(&standard).unwrap(), "\"standard\"");
        assert_eq!(
            serde_json::to_string(&permissive).unwrap(),
            "\"permissive\""
        );
    }

    #[test]
    fn test_security_mode_deserialization() {
        let strict: SecurityMode = serde_json::from_str("\"strict\"").unwrap();
        let standard: SecurityMode = serde_json::from_str("\"standard\"").unwrap();
        let normal: SecurityMode = serde_json::from_str("\"normal\"").unwrap();
        let permissive: SecurityMode = serde_json::from_str("\"permissive\"").unwrap();

        assert_eq!(strict, SecurityMode::Strict);
        assert_eq!(standard, SecurityMode::Standard);
        assert_eq!(normal, SecurityMode::Standard); // "normal" is alias for "standard"
        assert_eq!(permissive, SecurityMode::Permissive);
    }

    #[test]
    fn test_default_blacklist_patterns() {
        let blacklist = default_blacklist();
        assert!(blacklist.iter().any(|p| p.contains("rm")));
        assert!(blacklist.iter().any(|p| p.contains("mkfs")));
        assert!(blacklist.iter().any(|p| p.contains("dd")));
        assert!(blacklist.iter().any(|p| p.contains("chmod")));
        assert!(blacklist.iter().any(|p| p.contains("curl")));
        assert!(blacklist.iter().any(|p| p.contains("reboot")));
        assert!(blacklist.iter().any(|p| p.contains("poweroff")));
        assert!(blacklist.iter().any(|p| p.contains("shutdown")));
        assert!(blacklist.iter().any(|p| p.contains("iptables")));
    }

    // ============== HostKeyVerification Tests ==============

    #[test]
    fn test_host_key_verification_default() {
        let default = HostKeyVerification::default();
        assert_eq!(default, HostKeyVerification::Strict);
    }

    #[test]
    fn test_host_key_verification_serialization() {
        let strict = HostKeyVerification::Strict;
        let acceptnew = HostKeyVerification::AcceptNew;
        let off = HostKeyVerification::Off;

        assert_eq!(serde_json::to_string(&strict).unwrap(), "\"strict\"");
        assert_eq!(serde_json::to_string(&acceptnew).unwrap(), "\"acceptnew\"");
        assert_eq!(serde_json::to_string(&off).unwrap(), "\"off\"");
    }

    #[test]
    fn test_host_key_verification_deserialization() {
        let strict: HostKeyVerification = serde_json::from_str("\"strict\"").unwrap();
        let acceptnew: HostKeyVerification = serde_json::from_str("\"acceptnew\"").unwrap();
        let off: HostKeyVerification = serde_json::from_str("\"off\"").unwrap();

        assert_eq!(strict, HostKeyVerification::Strict);
        assert_eq!(acceptnew, HostKeyVerification::AcceptNew);
        assert_eq!(off, HostKeyVerification::Off);
    }

    // ============== AuthConfig Tests ==============

    #[test]
    fn test_auth_config_key_serialization() {
        let auth = AuthConfig::Key {
            path: "/path/to/key".to_string(),
            passphrase: Some(Zeroizing::new("secret".to_string())),
        };
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("\"type\":\"key\""));
        assert!(json.contains("\"/path/to/key\""));
    }

    #[test]
    fn test_auth_config_agent_serialization() {
        let auth = AuthConfig::Agent;
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("\"type\":\"agent\""));
    }

    #[test]
    fn test_auth_config_password_serialization() {
        let auth = AuthConfig::Password {
            password: Zeroizing::new("secret123".to_string()),
        };
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("\"type\":\"password\""));
        assert!(json.contains("\"secret123\""));
    }

    #[test]
    fn test_auth_config_deserialization() {
        let key_json = r#"{"type":"key","path":"/path/to/key"}"#;
        let agent_json = r#"{"type":"agent"}"#;
        let password_json = r#"{"type":"password","password":"secret"}"#;

        let key: AuthConfig = serde_json::from_str(key_json).unwrap();
        let agent: AuthConfig = serde_json::from_str(agent_json).unwrap();
        let password: AuthConfig = serde_json::from_str(password_json).unwrap();

        assert!(matches!(key, AuthConfig::Key { path, .. } if path == "/path/to/key"));
        assert!(matches!(agent, AuthConfig::Agent));
        assert!(matches!(password, AuthConfig::Password { password } if *password == "secret"));
    }

    // ============== LimitsConfig Tests ==============

    #[test]
    fn test_limits_config_default() {
        let config = LimitsConfig::default();
        assert_eq!(config.command_timeout_seconds, 1800);
        assert_eq!(config.max_output_bytes, 10 * 1024 * 1024);
        assert_eq!(config.max_concurrent_commands, 5);
        assert_eq!(config.connection_timeout_seconds, 10);
        assert_eq!(config.keepalive_interval_seconds, 30);
        assert_eq!(config.retry_attempts, 3);
        assert_eq!(config.retry_initial_delay_ms, 100);
        assert_eq!(config.rate_limit_per_second, 10); // 10 req/s per host
        assert_eq!(config.max_output_chars, 40_000);
        assert_eq!(config.output_cache_ttl_seconds, 300);
        assert_eq!(config.output_cache_max_entries, 100);
        assert_eq!(config.sftp_write_threshold_bytes, 65_536);
    }

    #[test]
    fn test_limits_config_retry_config() {
        let limits = LimitsConfig {
            retry_attempts: 5,
            retry_initial_delay_ms: 200,
            ..Default::default()
        };

        let retry_config = limits.retry_config();
        assert_eq!(retry_config.max_attempts, 5);
        assert_eq!(retry_config.initial_delay_ms, 200);
    }

    // ============== AuditConfig Tests ==============

    #[test]
    fn test_audit_config_default() {
        let config = AuditConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_size_mb, 100);
        assert_eq!(config.retain_days, 30);
        assert!(config.path.to_string_lossy().contains("audit.log"));
    }

    // ============== SessionConfig Tests ==============

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert_eq!(config.max_sessions, 10);
        assert_eq!(config.idle_timeout_seconds, 300);
        assert_eq!(config.max_age_seconds, 3600);
    }

    // ============== SanitizeConfig Tests ==============

    #[test]
    fn test_sanitize_config_default() {
        let config = SanitizeConfig::default();
        assert!(config.enabled);
        assert!(config.disable_builtin.is_empty());
        assert!(config.custom_patterns.is_empty());
    }

    #[test]
    fn test_custom_sanitize_pattern_default_replacement() {
        let pattern: CustomSanitizePattern =
            serde_json::from_str(r#"{"pattern": "secret_\\w+"}"#).unwrap();
        assert_eq!(pattern.replacement, "[REDACTED]");
        assert!(pattern.description.is_none());
    }

    #[test]
    fn test_custom_sanitize_pattern_with_all_fields() {
        let pattern: CustomSanitizePattern = serde_json::from_str(
            r#"{"pattern": "api_key=\\w+", "replacement": "[API_KEY]", "description": "API key pattern"}"#
        ).unwrap();
        assert_eq!(pattern.pattern, "api_key=\\w+");
        assert_eq!(pattern.replacement, "[API_KEY]");
        assert_eq!(pattern.description, Some("API key pattern".to_string()));
    }

    // ============== HostConfig Tests ==============

    #[test]
    fn test_host_config_default_port() {
        let json = r#"{
            "hostname": "example.com",
            "user": "admin",
            "auth": {"type": "agent"}
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(host.port, 22);
    }

    #[test]
    fn test_host_config_custom_port() {
        let json = r#"{
            "hostname": "example.com",
            "port": 2222,
            "user": "admin",
            "auth": {"type": "agent"}
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(host.port, 2222);
    }

    #[test]
    fn test_host_config_with_description() {
        let json = r#"{
            "hostname": "example.com",
            "user": "admin",
            "description": "Production server",
            "auth": {"type": "agent"}
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(host.description, Some("Production server".to_string()));
    }

    #[test]
    fn test_host_config_with_proxy_jump() {
        let json = r#"{
            "hostname": "internal.example.com",
            "user": "admin",
            "proxy_jump": "bastion",
            "auth": {"type": "agent"}
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(host.proxy_jump, Some("bastion".to_string()));
    }

    // ============== SocksProxyConfig Tests ==============

    #[test]
    fn test_socks_proxy_config_defaults() {
        let json = r#"{"hostname": "proxy.example.com"}"#;
        let config: SocksProxyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.hostname, "proxy.example.com");
        assert_eq!(config.port, 1080);
        assert_eq!(config.version, SocksVersion::Socks5);
        assert!(config.username.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_socks_proxy_config_full() {
        let json = r#"{
            "hostname": "proxy.corp.com",
            "port": 9050,
            "version": "socks4",
            "username": "user",
            "password": "pass"
        }"#;
        let config: SocksProxyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.hostname, "proxy.corp.com");
        assert_eq!(config.port, 9050);
        assert_eq!(config.version, SocksVersion::Socks4);
        assert_eq!(config.username, Some("user".to_string()));
        assert_eq!(config.password.as_deref().map(String::as_str), Some("pass"));
    }

    #[test]
    fn test_socks_version_default_is_socks5() {
        let default = SocksVersion::default();
        assert_eq!(default, SocksVersion::Socks5);
    }

    #[test]
    fn test_socks_version_serialization() {
        assert_eq!(
            serde_json::to_string(&SocksVersion::Socks5).unwrap(),
            "\"socks5\""
        );
        assert_eq!(
            serde_json::to_string(&SocksVersion::Socks4).unwrap(),
            "\"socks4\""
        );
    }

    #[test]
    fn test_socks_version_deserialization() {
        let socks5: SocksVersion = serde_json::from_str("\"socks5\"").unwrap();
        let socks4: SocksVersion = serde_json::from_str("\"socks4\"").unwrap();
        assert_eq!(socks5, SocksVersion::Socks5);
        assert_eq!(socks4, SocksVersion::Socks4);
    }

    #[test]
    fn test_host_config_with_socks_proxy() {
        let json = r#"{
            "hostname": "10.0.0.50",
            "user": "deploy",
            "auth": {"type": "agent"},
            "socks_proxy": {
                "hostname": "proxy.corp.com",
                "port": 1080,
                "version": "socks5"
            }
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert!(host.socks_proxy.is_some());
        let socks = host.socks_proxy.unwrap();
        assert_eq!(socks.hostname, "proxy.corp.com");
        assert_eq!(socks.port, 1080);
        assert_eq!(socks.version, SocksVersion::Socks5);
        assert!(host.proxy_jump.is_none());
    }

    #[test]
    fn test_host_config_socks_proxy_default_none() {
        let json = r#"{
            "hostname": "example.com",
            "user": "admin",
            "auth": {"type": "agent"}
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert!(host.socks_proxy.is_none());
    }

    #[test]
    fn test_socks_proxy_config_clone_and_debug() {
        let config = SocksProxyConfig {
            hostname: "proxy.test".to_string(),
            port: 1080,
            version: SocksVersion::Socks5,
            username: None,
            password: None,
        };
        let cloned = config.clone();
        assert_eq!(config.hostname, cloned.hostname);

        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("SocksProxyConfig"));
    }

    // ============== Config Clone and Debug Tests ==============

    #[test]
    fn test_security_config_clone_and_debug() {
        let config = SecurityConfig::default();
        let cloned = config.clone();
        assert_eq!(config.mode, cloned.mode);

        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("SecurityConfig"));
    }

    #[test]
    fn test_limits_config_clone_and_debug() {
        let config = LimitsConfig::default();
        let cloned = config.clone();
        assert_eq!(
            config.command_timeout_seconds,
            cloned.command_timeout_seconds
        );

        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("LimitsConfig"));
    }

    #[test]
    fn test_audit_config_clone_and_debug() {
        let config = AuditConfig::default();
        let cloned = config.clone();
        assert_eq!(config.enabled, cloned.enabled);

        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("AuditConfig"));
    }

    #[test]
    fn test_session_config_clone_and_debug() {
        let config = SessionConfig::default();
        let cloned = config.clone();
        assert_eq!(config.max_sessions, cloned.max_sessions);

        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("SessionConfig"));
    }

    // ============== ToolGroupsConfig Tests ==============

    #[test]
    fn test_tool_groups_config_default() {
        let config = ToolGroupsConfig::default();
        assert!(config.groups.is_empty());
    }

    #[test]
    fn test_tool_groups_config_default_profile_membership() {
        // FIND-024: default profile is the 8 groups in MINIMAL_DEFAULT_GROUPS.
        // Everything else is opt-in.
        let config = ToolGroupsConfig::default();

        // In default profile.
        assert!(config.is_group_enabled("core"));
        assert!(config.is_group_enabled("sessions"));
        assert!(config.is_group_enabled("file_ops"));
        assert!(config.is_group_enabled("directory"));
        assert!(config.is_group_enabled("process"));
        assert!(config.is_group_enabled("monitoring"));
        assert!(config.is_group_enabled("network"));
        assert!(config.is_group_enabled("systemd"));

        // NOT in default profile — must be opt-in now.
        assert!(!config.is_group_enabled("docker"));
        assert!(!config.is_group_enabled("kubernetes"));
        assert!(!config.is_group_enabled("active_directory"));
        assert!(!config.is_group_enabled("anything"));
    }

    #[test]
    fn test_tool_groups_config_explicit_disable() {
        let mut groups = HashMap::new();
        groups.insert("sessions".to_string(), false);
        let config = ToolGroupsConfig { groups };

        assert!(!config.is_group_enabled("sessions"));
        assert!(config.is_group_enabled("core"));
    }

    #[test]
    fn test_tool_groups_config_explicit_enable() {
        let mut groups = HashMap::new();
        groups.insert("core".to_string(), true);
        let config = ToolGroupsConfig { groups };

        assert!(config.is_group_enabled("core"));
    }

    #[test]
    fn test_tool_groups_config_deserialization() {
        let yaml = r"
            groups:
              sessions: false
              monitoring: false
              core: true
        ";
        let config: ToolGroupsConfig = serde_saphyr::from_str(yaml).unwrap();
        assert!(!config.is_group_enabled("sessions"));
        assert!(!config.is_group_enabled("monitoring"));
        assert!(config.is_group_enabled("core"));
        // FIND-024: `file_transfer` is NOT in MINIMAL_DEFAULT_GROUPS, so
        // unlisted means disabled now (was enabled prior to FIND-024).
        assert!(!config.is_group_enabled("file_transfer"));
    }

    #[test]
    fn test_tool_groups_config_empty_deserialization() {
        // FIND-024: empty config -> default profile via MINIMAL_DEFAULT_GROUPS.
        let yaml = "{}";
        let config: ToolGroupsConfig = serde_saphyr::from_str(yaml).unwrap();
        assert!(config.groups.is_empty());
        assert!(config.is_group_enabled("core")); // in default profile
        assert!(!config.is_group_enabled("docker")); // not in default profile
    }

    #[test]
    fn test_tool_groups_config_clone_and_debug() {
        let mut groups = HashMap::new();
        groups.insert("sessions".to_string(), false);
        let config = ToolGroupsConfig { groups };
        let cloned = config.clone();
        assert_eq!(
            config.is_group_enabled("sessions"),
            cloned.is_group_enabled("sessions")
        );

        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("ToolGroupsConfig"));
    }

    // ============== ClientOverride Tests ==============

    #[test]
    fn test_effective_max_output_chars_default() {
        let config = LimitsConfig::default();
        // Default is 40K for unknown clients
        assert_eq!(config.effective_max_output_chars(None), 40_000);
        assert_eq!(
            config.effective_max_output_chars(Some("unknown-client")),
            40_000
        );
        // Built-in overrides for known clients
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
        assert_eq!(
            config.effective_max_output_chars(Some("cursor-editor")),
            50_000
        );
        assert_eq!(config.effective_max_output_chars(Some("cline")), 80_000);
    }

    #[test]
    fn test_effective_max_output_chars_with_override() {
        // User-provided overrides replace built-in defaults entirely
        let config = LimitsConfig {
            client_overrides: vec![
                ClientOverride {
                    name_contains: "claude".to_string(),
                    match_mode: MatchMode::default(),
                    max_output_chars: Some(120_000),
                },
                ClientOverride {
                    name_contains: "cursor".to_string(),
                    match_mode: MatchMode::default(),
                    max_output_chars: Some(60_000),
                },
            ],
            ..Default::default()
        };

        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            120_000
        );
        assert_eq!(config.effective_max_output_chars(Some("Cursor")), 60_000);
        assert_eq!(config.effective_max_output_chars(Some("unknown")), 40_000);
        assert_eq!(config.effective_max_output_chars(None), 40_000);
    }

    #[test]
    fn test_effective_max_output_chars_case_insensitive() {
        let config = LimitsConfig {
            client_overrides: vec![ClientOverride {
                name_contains: "Claude".to_string(),
                match_mode: MatchMode::default(),
                max_output_chars: Some(80_000),
            }],
            ..Default::default()
        };

        assert_eq!(
            config.effective_max_output_chars(Some("CLAUDE-CODE")),
            80_000
        );
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
    }

    #[test]
    fn test_client_override_deserialization() {
        let yaml = r"
            name_contains: claude
            max_output_chars: 80000
        ";
        let ov: ClientOverride = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(ov.name_contains, "claude");
        assert_eq!(ov.max_output_chars, Some(80_000));
        assert_eq!(ov.match_mode, MatchMode::Prefix); // default
    }

    #[test]
    fn test_client_override_deserialization_with_match_mode() {
        let yaml = r"
            name_contains: claude
            match_mode: exact
            max_output_chars: 80000
        ";
        let ov: ClientOverride = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(ov.match_mode, MatchMode::Exact);

        let yaml_contains = r"
            name_contains: claude
            match_mode: contains
        ";
        let ov2: ClientOverride = serde_saphyr::from_str(yaml_contains).unwrap();
        assert_eq!(ov2.match_mode, MatchMode::Contains);
        assert_eq!(ov2.max_output_chars, None);
    }

    #[test]
    fn test_limits_with_client_overrides_deserialization() {
        let yaml = r"
            client_overrides:
              - name_contains: claude
                max_output_chars: 80000
              - name_contains: gemini
                max_output_chars: 200000
        ";
        let config: LimitsConfig = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(config.client_overrides.len(), 2);
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
        assert_eq!(
            config.effective_max_output_chars(Some("gemini-client")),
            200_000
        );
    }

    #[test]
    fn test_match_mode_default_is_prefix() {
        let config = LimitsConfig {
            client_overrides: vec![ClientOverride {
                name_contains: "claude".to_string(),
                match_mode: MatchMode::default(),
                max_output_chars: Some(80_000),
            }],
            ..Default::default()
        };

        // Prefix: "claude" matches "claude-code" but NOT "not-claude"
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
        assert_eq!(
            config.effective_max_output_chars(Some("not-claude")),
            40_000
        );
    }

    #[test]
    fn test_match_mode_exact() {
        let config = LimitsConfig {
            client_overrides: vec![ClientOverride {
                name_contains: "claude-code".to_string(),
                match_mode: MatchMode::Exact,
                max_output_chars: Some(80_000),
            }],
            ..Default::default()
        };

        // Exact: "claude-code" matches "Claude-Code" but NOT "claude-code-v2"
        assert_eq!(
            config.effective_max_output_chars(Some("Claude-Code")),
            80_000
        );
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code-v2")),
            40_000
        );
        assert_eq!(config.effective_max_output_chars(Some("claude")), 40_000);
    }

    #[test]
    fn test_match_mode_prefix() {
        let config = LimitsConfig {
            client_overrides: vec![ClientOverride {
                name_contains: "claude".to_string(),
                match_mode: MatchMode::Prefix,
                max_output_chars: Some(80_000),
            }],
            ..Default::default()
        };

        // Prefix: "claude" matches "claude-code" but NOT "not-claude"
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
        assert_eq!(config.effective_max_output_chars(Some("claude")), 80_000);
        assert_eq!(
            config.effective_max_output_chars(Some("not-claude")),
            40_000
        );
    }

    #[test]
    fn test_match_mode_contains() {
        let config = LimitsConfig {
            client_overrides: vec![ClientOverride {
                name_contains: "claude".to_string(),
                match_mode: MatchMode::Contains,
                max_output_chars: Some(80_000),
            }],
            ..Default::default()
        };

        // Contains: "claude" matches both "claude-code" AND "not-claude"
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
        assert_eq!(
            config.effective_max_output_chars(Some("not-claude")),
            80_000
        );
        assert_eq!(config.effective_max_output_chars(Some("cursor")), 40_000);
    }

    #[test]
    fn test_host_config_tags() {
        let json = r#"{
            "hostname": "example.com",
            "user": "admin",
            "auth": {"type": "agent"},
            "tags": ["production", "web"]
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(host.tags.len(), 2);
        assert!(host.has_tag("production"));
        assert!(host.has_tag("Production")); // case-insensitive
        assert!(!host.has_tag("staging"));
    }

    #[test]
    fn test_host_config_empty_tags_default() {
        let json = r#"{
            "hostname": "example.com",
            "user": "admin",
            "auth": {"type": "agent"}
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert!(host.tags.is_empty());
    }

    #[test]
    fn test_host_retry_config() {
        let json = r#"{
            "hostname": "example.com",
            "user": "admin",
            "auth": {"type": "agent"},
            "retry": {
                "max_attempts": 5,
                "initial_delay_ms": 200,
                "max_delay_ms": 60000
            }
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        let retry = host.retry.unwrap();
        assert_eq!(retry.max_attempts, Some(5));
        assert_eq!(retry.initial_delay_ms, Some(200));
        assert_eq!(retry.max_delay_ms, Some(60000));
    }

    // ============== HostConfig Method Tests ==============

    #[test]
    fn test_effective_shell_explicit_override() {
        let json = r#"{
            "hostname": "test",
            "user": "admin",
            "auth": {"type": "agent"},
            "os_type": "linux",
            "shell": "powershell"
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(host.effective_shell(), ShellType::PowerShell);
    }

    #[test]
    fn test_effective_shell_inferred_linux() {
        let json = r#"{
            "hostname": "test",
            "user": "admin",
            "auth": {"type": "agent"},
            "os_type": "linux"
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(host.effective_shell(), ShellType::Posix);
    }

    #[test]
    fn test_effective_shell_inferred_windows() {
        let json = r#"{
            "hostname": "test",
            "user": "admin",
            "auth": {"type": "agent"},
            "os_type": "windows"
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(host.effective_shell(), ShellType::Cmd);
    }

    #[test]
    fn test_has_tag_case_insensitive() {
        let json = r#"{
            "hostname": "test",
            "user": "admin",
            "auth": {"type": "agent"},
            "tags": ["Production", "Database"]
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert!(host.has_tag("production"));
        assert!(host.has_tag("PRODUCTION"));
        assert!(host.has_tag("database"));
        assert!(!host.has_tag("staging"));
    }

    #[test]
    fn test_has_tag_empty() {
        let json = r#"{
            "hostname": "test",
            "user": "admin",
            "auth": {"type": "agent"}
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert!(!host.has_tag("any"));
    }
}
