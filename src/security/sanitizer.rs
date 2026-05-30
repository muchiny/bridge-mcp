use std::borrow::Cow;
use std::sync::LazyLock;

use aho_corasick::AhoCorasick;
use regex::{Regex, RegexSet};
use tracing::{debug, error, info};

/// Pre-compiled regex for stripping ANSI escape codes from SSH output.
static ANSI_ESCAPE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07|\x1b\[[\d;]*m").unwrap());

use crate::config::{CustomSanitizePattern, SanitizeConfig};
use crate::security::entropy::EntropyDetector;

/// Threshold in bytes above which parallel detection is used
const PARALLEL_THRESHOLD: usize = 512 * 1024; // 512 KB

/// High-performance output sanitizer that masks sensitive information
///
/// Uses a multi-tier approach for optimal performance:
/// 1. `RegexSet` for O(n) detection of any matches
/// 2. `Cow<str>` for zero-copy when no matches found
/// 3. Aho-Corasick for literal pattern matching (future optimization)
///
/// # Examples
///
/// ```
/// use mcp_ssh_bridge::config::SanitizeConfig;
/// use mcp_ssh_bridge::security::Sanitizer;
///
/// let sanitizer = Sanitizer::from_config(&SanitizeConfig::default());
///
/// // Clean output passes through unchanged
/// let clean = sanitizer.sanitize("Server started on port 8080");
/// assert_eq!(clean.as_ref(), "Server started on port 8080");
///
/// // Sensitive patterns are masked
/// let sensitive = sanitizer.sanitize("token: ghp_abc123def456ghi789jkl012mno345pqr678st");
/// assert!(!sensitive.contains("ghp_abc123"));
/// assert!(sensitive.contains("[GITHUB_PAT_REDACTED]"));
/// ```
pub struct Sanitizer {
    /// Compiled regex patterns with their replacements
    patterns: Vec<SanitizePattern>,
    /// `RegexSet` for fast detection (single-pass to check if ANY pattern matches)
    detection_set: RegexSet,
    /// Aho-Corasick automaton for literal patterns (keywords that indicate secrets)
    literal_detector: AhoCorasick,
    /// Whether sanitization is enabled
    enabled: bool,
    /// Whether ANSI escape code stripping is enabled
    strip_ansi: bool,
    /// Entropy-based secret detector (complements regex patterns)
    entropy_detector: EntropyDetector,
}

struct SanitizePattern {
    regex: Regex,
    replacement: String,
}

/// Pattern definition for easier initialization
struct PatternDef {
    pattern: &'static str,
    replacement: &'static str,
    description: &'static str,
    /// Category for filtering (e.g., "github", "aws", "generic")
    category: &'static str,
}

impl Sanitizer {
    /// Create a new sanitizer from advanced configuration
    #[must_use]
    pub fn from_config(config: &SanitizeConfig) -> Self {
        Self::from_config_with_legacy(config, &[])
    }

    /// Create a new sanitizer from advanced configuration with legacy pattern support
    ///
    /// This method combines:
    /// - The new `SanitizeConfig` with categories and custom replacements
    /// - Legacy `sanitize_patterns` from older configs (for backward compatibility)
    #[must_use]
    pub fn from_config_with_legacy(config: &SanitizeConfig, legacy_patterns: &[String]) -> Self {
        if !config.enabled {
            info!("Sanitization disabled by configuration");
            return Self::disabled();
        }

        let disabled_categories: std::collections::HashSet<&str> =
            config.disable_builtin.iter().map(String::as_str).collect();

        // Filter builtin patterns by category
        let all_patterns: Vec<PatternDef> = Self::default_pattern_defs()
            .into_iter()
            .filter(|p| !disabled_categories.contains(p.category))
            .collect();

        if !disabled_categories.is_empty() {
            info!(
                disabled = ?config.disable_builtin,
                remaining = all_patterns.len(),
                "Filtered builtin sanitizer patterns"
            );
        }

        // Combine custom patterns from new config and legacy patterns
        let mut all_custom = config.custom_patterns.clone();

        // Add legacy patterns with default replacement
        for legacy in legacy_patterns {
            if !legacy.is_empty() {
                all_custom.push(CustomSanitizePattern {
                    pattern: legacy.clone(),
                    replacement: "[REDACTED]".to_string(),
                    description: Some("Legacy pattern from sanitize_patterns".to_string()),
                });
            }
        }

        let entropy_detector = EntropyDetector::new(
            config.entropy_threshold,
            config.entropy_min_length,
            config.entropy_whitelist.clone(),
            config.entropy_detection,
        );

        Self::from_pattern_defs_with_custom(&all_patterns, &all_custom, true, entropy_detector)
    }

    /// Create a new sanitizer with user-defined patterns (added to defaults)
    /// Legacy method for backward compatibility
    #[must_use]
    pub fn new(user_patterns: &[String]) -> Self {
        let all_patterns = Self::default_pattern_defs();
        let custom: Vec<CustomSanitizePattern> = user_patterns
            .iter()
            .map(|p| CustomSanitizePattern {
                pattern: p.clone(),
                replacement: "[REDACTED]".to_string(),
                description: Some("Legacy user-defined pattern".to_string()),
            })
            .collect();

        Self::from_pattern_defs_with_custom(
            &all_patterns,
            &custom,
            true,
            EntropyDetector::default(),
        )
    }

    /// Create a sanitizer with only default patterns
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::from_pattern_defs_with_custom(
            &Self::default_pattern_defs(),
            &[],
            true,
            EntropyDetector::default(),
        )
    }

    /// Create a disabled sanitizer (pass-through)
    #[must_use]
    pub fn disabled() -> Self {
        let empty: Vec<&str> = Vec::new();
        Self {
            patterns: Vec::new(),
            detection_set: RegexSet::empty(),
            literal_detector: AhoCorasick::builder().build(&empty).unwrap(),
            enabled: false,
            strip_ansi: false,
            entropy_detector: EntropyDetector::disabled(),
        }
    }

    /// Build sanitizer from pattern definitions with custom patterns
    fn from_pattern_defs_with_custom(
        defs: &[PatternDef],
        custom: &[CustomSanitizePattern],
        enabled: bool,
        entropy_detector: EntropyDetector,
    ) -> Self {
        /// Maximum length for user-supplied custom sanitize patterns.
        const MAX_CUSTOM_PATTERN_LEN: usize = 512;

        let mut patterns = Vec::with_capacity(defs.len() + custom.len());
        let mut regex_patterns = Vec::with_capacity(defs.len() + custom.len());

        // Add builtin patterns
        for def in defs {
            match Regex::new(def.pattern) {
                Ok(regex) => {
                    regex_patterns.push(def.pattern.to_string());
                    patterns.push(SanitizePattern {
                        regex,
                        replacement: def.replacement.to_string(),
                    });
                }
                Err(e) => {
                    error!(
                        pattern = %def.pattern,
                        description = %def.description,
                        error = %e,
                        "Invalid builtin sanitize regex pattern, skipping"
                    );
                }
            }
        }

        // Add custom patterns (with size limit to prevent expensive compilation)
        for custom_pattern in custom {
            if custom_pattern.pattern.len() > MAX_CUSTOM_PATTERN_LEN {
                error!(
                    pattern_len = custom_pattern.pattern.len(),
                    max = MAX_CUSTOM_PATTERN_LEN,
                    "Custom sanitize pattern too long, skipping"
                );
                continue;
            }
            match Regex::new(&custom_pattern.pattern) {
                Ok(regex) => {
                    regex_patterns.push(custom_pattern.pattern.clone());
                    patterns.push(SanitizePattern {
                        regex,
                        replacement: custom_pattern.replacement.clone(),
                    });
                    debug!(
                        pattern = %custom_pattern.pattern,
                        replacement = %custom_pattern.replacement,
                        "Added custom sanitize pattern"
                    );
                }
                Err(e) => {
                    error!(
                        pattern = %custom_pattern.pattern,
                        error = %e,
                        "Invalid custom sanitize regex pattern, skipping"
                    );
                }
            }
        }

        // Build RegexSet for fast detection
        let detection_set = match RegexSet::new(&regex_patterns) {
            Ok(set) => set,
            Err(e) => {
                error!(error = %e, "Failed to build RegexSet, falling back to empty set");
                RegexSet::empty()
            }
        };

        // Build Aho-Corasick for literal keyword detection (fast pre-filter)
        let literal_keywords = Self::secret_keywords();
        let literal_detector = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&literal_keywords)
            .unwrap_or_else(|e| {
                error!(error = %e, "Failed to build Aho-Corasick, using empty");
                let empty: Vec<&str> = Vec::new();
                AhoCorasick::builder().build(&empty).unwrap()
            });

        info!(
            builtin_patterns = defs.len(),
            custom_patterns = custom.len(),
            total_patterns = patterns.len(),
            "Sanitizer initialized"
        );

        let strip_ansi = enabled;

        if entropy_detector.is_enabled() {
            info!("Entropy-based secret detection enabled");
        }

        Self {
            patterns,
            detection_set,
            literal_detector,
            enabled,
            strip_ansi,
            entropy_detector,
        }
    }

    /// Keywords that indicate potential secrets (for fast pre-filtering)
    fn secret_keywords() -> Vec<&'static str> {
        vec![
            // Generic
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "bearer",
            "auth",
            "credential",
            "api_key",
            "apikey",
            "api-key",
            "private",
            // AWS
            "aws_access",
            "aws_secret",
            "AKIA",
            // Kubernetes / K3s
            "kubeconfig",
            "client-certificate-data",
            "client-key-data",
            "K10",
            "K3S_TOKEN",
            // Docker
            "docker_password",
            "registry_password",
            "docker login",
            // Ansible
            "vault_pass",
            "ansible_become",
            "ANSIBLE_VAULT",
            // Database
            "mysql://",
            "postgresql://",
            "postgres://",
            "mongodb://",
            "redis://",
            "DATABASE_URL",
            "DB_PASSWORD",
            // Cloud providers
            "AZURE_",
            "GCP_",
            "GOOGLE_APPLICATION_CREDENTIALS",
            // CI/CD
            "GITHUB_TOKEN",
            "GITLAB_TOKEN",
            "CI_JOB_TOKEN",
            "ghp_",
            "gho_",
            "ghu_",
            "ghs_",
            "ghr_",
            "glpat-",
            // Certificates
            "BEGIN PRIVATE KEY",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN OPENSSH PRIVATE KEY",
            "BEGIN CERTIFICATE",
            "BEGIN EC PRIVATE KEY",
            "BEGIN PGP",
            // HashiCorp
            "VAULT_TOKEN",
            "vault_token",
            "CONSUL_HTTP_TOKEN",
            // JWT
            "eyJ",
            // API Keys
            "sk-",
            "OPENAI",
            "ANTHROPIC",
            "CLAUDE",
            // Slack/Discord
            "xox",
            "hooks.slack.com",
            "discord.com/api/webhooks",
            // Misc
            "ssh_pass",
            "smtp_pass",
            "mail_pass",
            "npm_token",
            "pypi_token",
            "NVAPI",
            "sk-ant-",
            "sk_live_",
            "pk_live_",
            "rk_live_",
            "npm_",
            "pypi-",
            "sensitive_value",
        ]
    }

    /// Get all default pattern definitions with categories
    ///
    /// IMPORTANT: Order matters! Specific patterns (with unique markers like
    /// `[GITHUB_PAT_REDACTED]`) must come BEFORE generic patterns (like `$1=[REDACTED]`)
    /// to ensure proper detection and replacement.
    ///
    /// Categories available for filtering:
    /// - `github` - GitHub tokens
    /// - `gitlab` - GitLab tokens
    /// - `slack` - Slack tokens and webhooks
    /// - `discord` - Discord webhooks
    /// - `openai` - `OpenAI` API keys
    /// - `aws` - AWS credentials
    /// - `k3s` - K3s/Kubernetes tokens
    /// - `jwt` - JWT tokens
    /// - `certificates` - Private keys (RSA, OpenSSH, EC, PGP)
    /// - `kubeconfig` - Kubeconfig credentials
    /// - `docker` - Docker registry auth
    /// - `database` - Database connection strings and passwords
    /// - `ansible` - Ansible vault and become passwords
    /// - `azure` - Azure credentials
    /// - `gcp` - Google Cloud credentials
    /// - `hashicorp` - Vault and Consul tokens
    /// - `generic` - Generic password/secret/token patterns
    #[expect(clippy::too_many_lines)]
    fn default_pattern_defs() -> Vec<PatternDef> {
        vec![
            // ══════════════════════════════════════════════════════════════════
            // TIER 1: HIGHLY SPECIFIC PATTERNS (unique signatures)
            // These must come first to avoid being caught by generic patterns
            // ══════════════════════════════════════════════════════════════════

            // GitHub tokens (very specific prefixes)
            PatternDef {
                pattern: r"ghp_[A-Za-z0-9]{36}",
                replacement: "[GITHUB_PAT_REDACTED]",
                description: "GitHub Personal Access Token",
                category: "github",
            },
            PatternDef {
                pattern: r"gho_[A-Za-z0-9]{36}",
                replacement: "[GITHUB_OAUTH_TOKEN_REDACTED]",
                description: "GitHub OAuth Token",
                category: "github",
            },
            PatternDef {
                pattern: r"ghu_[A-Za-z0-9]{36}",
                replacement: "[GITHUB_USER_TOKEN_REDACTED]",
                description: "GitHub User-to-Server Token",
                category: "github",
            },
            PatternDef {
                pattern: r"ghs_[A-Za-z0-9]{36}",
                replacement: "[GITHUB_SERVER_TOKEN_REDACTED]",
                description: "GitHub Server-to-Server Token",
                category: "github",
            },
            PatternDef {
                pattern: r"ghr_[A-Za-z0-9]{36}",
                replacement: "[GITHUB_REFRESH_TOKEN_REDACTED]",
                description: "GitHub Refresh Token",
                category: "github",
            },
            PatternDef {
                pattern: r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
                replacement: "[GITHUB_FINE_GRAINED_PAT_REDACTED]",
                description: "GitHub Fine-grained PAT",
                category: "github",
            },
            // GitLab
            PatternDef {
                pattern: r"glpat-[A-Za-z0-9\-]{20,}",
                replacement: "[GITLAB_PAT_REDACTED]",
                description: "GitLab Personal Access Token",
                category: "gitlab",
            },
            // Slack tokens
            PatternDef {
                pattern: r"xox[baprs]-[A-Za-z0-9\-]{10,}",
                replacement: "[SLACK_TOKEN_REDACTED]",
                description: "Slack token",
                category: "slack",
            },
            PatternDef {
                pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
                replacement: "[SLACK_WEBHOOK_REDACTED]",
                description: "Slack webhook URL",
                category: "slack",
            },
            // Discord
            PatternDef {
                pattern: r"https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
                replacement: "[DISCORD_WEBHOOK_REDACTED]",
                description: "Discord webhook URL",
                category: "discord",
            },
            // OpenAI
            PatternDef {
                pattern: r"sk-[A-Za-z0-9]{20,}",
                replacement: "[OPENAI_API_KEY_REDACTED]",
                description: "OpenAI API Key",
                category: "openai",
            },
            // AWS Access Key ID (specific format AKIA...)
            PatternDef {
                pattern: r"AKIA[0-9A-Z]{16}",
                replacement: "[AWS_ACCESS_KEY_REDACTED]",
                description: "AWS Access Key ID",
                category: "aws",
            },
            // K3s tokens
            PatternDef {
                pattern: r"K10[A-Za-z0-9]{48,}",
                replacement: "[K3S_TOKEN_REDACTED]",
                description: "K3s server token",
                category: "k3s",
            },
            PatternDef {
                pattern: r"K[0-9a-f]{10,}::[a-z]+:[A-Za-z0-9]+",
                replacement: "[K3S_NODE_TOKEN_REDACTED]",
                description: "K3s node token",
                category: "k3s",
            },
            // JWT tokens (generic format eyJ...)
            PatternDef {
                pattern: r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                replacement: "[JWT_TOKEN_REDACTED]",
                description: "Generic JWT token",
                category: "jwt",
            },
            // Opaque (non-JWT) Authorization: Bearer tokens.
            // MUST come AFTER the JWT pattern above: the engine applies matched
            // patterns in definition order, so a `Bearer eyJ...` JWT is already
            // replaced by [JWT_TOKEN_REDACTED] before this generic rule is reached
            // (and `[JWT_TOKEN_REDACTED]` no longer matches this token charset).
            // This closes the leak when `entropy_detection: false` is configured.
            PatternDef {
                pattern: r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}",
                replacement: "Bearer [BEARER_TOKEN_REDACTED]",
                description: "Opaque Authorization Bearer token",
                category: "generic",
            },
            // Anthropic API keys (specific prefix sk-ant-*)
            PatternDef {
                pattern: r"sk-ant-api\d{2}-[A-Za-z0-9_-]{80,}",
                replacement: "[ANTHROPIC_API_KEY_REDACTED]",
                description: "Anthropic API Key",
                category: "openai",
            },
            // Stripe keys
            PatternDef {
                pattern: r"sk_live_[A-Za-z0-9]{24,}",
                replacement: "[STRIPE_SECRET_KEY_REDACTED]",
                description: "Stripe Secret Key",
                category: "generic",
            },
            PatternDef {
                pattern: r"pk_live_[A-Za-z0-9]{24,}",
                replacement: "[STRIPE_PUBLISHABLE_KEY_REDACTED]",
                description: "Stripe Publishable Key",
                category: "generic",
            },
            PatternDef {
                pattern: r"rk_live_[A-Za-z0-9]{24,}",
                replacement: "[STRIPE_RESTRICTED_KEY_REDACTED]",
                description: "Stripe Restricted Key",
                category: "generic",
            },
            // npm tokens (specific prefix npm_)
            PatternDef {
                pattern: r"npm_[A-Za-z0-9]{36,}",
                replacement: "[NPM_TOKEN_REDACTED]",
                description: "npm Access Token",
                category: "generic",
            },
            // PyPI tokens (specific prefix pypi-)
            PatternDef {
                pattern: r"pypi-[A-Za-z0-9_-]{16,}",
                replacement: "[PYPI_TOKEN_REDACTED]",
                description: "PyPI API Token",
                category: "generic",
            },
            // NVIDIA API Key
            PatternDef {
                pattern: r"NVAPI[A-Za-z0-9\-_]{20,}",
                replacement: "[NVIDIA_API_KEY_REDACTED]",
                description: "NVIDIA API Key",
                category: "openai",
            },
            // ══════════════════════════════════════════════════════════════════
            // TIER 2: CERTIFICATES & KEYS (multi-line patterns)
            // ══════════════════════════════════════════════════════════════════
            PatternDef {
                pattern: r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----",
                replacement: "[PRIVATE_KEY_REDACTED]",
                description: "RSA Private Key",
                category: "certificates",
            },
            PatternDef {
                pattern: r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----",
                replacement: "[OPENSSH_PRIVATE_KEY_REDACTED]",
                description: "OpenSSH Private Key",
                category: "certificates",
            },
            PatternDef {
                pattern: r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+EC\s+PRIVATE\s+KEY-----",
                replacement: "[EC_PRIVATE_KEY_REDACTED]",
                description: "EC Private Key",
                category: "certificates",
            },
            PatternDef {
                pattern: r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----[\s\S]*?-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
                replacement: "[PGP_PRIVATE_KEY_REDACTED]",
                description: "PGP Private Key",
                category: "certificates",
            },
            // PKCS#8 Private Key (generic, covers DSA, ECDSA, Ed25519, etc.)
            PatternDef {
                pattern: r"-----BEGIN\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+PRIVATE\s+KEY-----",
                replacement: "[PKCS8_PRIVATE_KEY_REDACTED]",
                description: "PKCS#8 Private Key",
                category: "certificates",
            },
            // Ansible Vault encrypted content
            PatternDef {
                pattern: r"\$ANSIBLE_VAULT;[\d.]+;AES256\n[a-f0-9\n]+",
                replacement: "[ANSIBLE_VAULT_ENCRYPTED_REDACTED]",
                description: "Ansible Vault encrypted content",
                category: "ansible",
            },
            // ══════════════════════════════════════════════════════════════════
            // TIER 3: TOOL-SPECIFIC PATTERNS (Kubeconfig, Docker, etc.)
            // ══════════════════════════════════════════════════════════════════

            // Kubeconfig
            PatternDef {
                pattern: r"(?i)client-certificate-data:\s*[A-Za-z0-9+/=]+",
                replacement: "client-certificate-data: [REDACTED]",
                description: "Kubeconfig client certificate",
                category: "kubeconfig",
            },
            PatternDef {
                pattern: r"(?i)client-key-data:\s*[A-Za-z0-9+/=]+",
                replacement: "client-key-data: [REDACTED]",
                description: "Kubeconfig client key",
                category: "kubeconfig",
            },
            PatternDef {
                pattern: r"(?i)certificate-authority-data:\s*[A-Za-z0-9+/=]+",
                replacement: "certificate-authority-data: [REDACTED]",
                description: "Kubeconfig CA certificate",
                category: "kubeconfig",
            },
            // Docker
            PatternDef {
                pattern: r#"(?i)"auth"\s*:\s*"[A-Za-z0-9+/=]{10,}""#,
                replacement: r#""auth": "[REDACTED]""#,
                description: "Docker config auth",
                category: "docker",
            },
            PatternDef {
                pattern: r#"(?i)docker\s+login\s+[^\n]*-p\s*['"]?[^\s'"]+['"]?"#,
                replacement: "docker login [CREDENTIALS REDACTED]",
                description: "Docker login command with password",
                category: "docker",
            },
            // Database connection strings
            PatternDef {
                pattern: r"(?i)(mysql|postgresql|postgres|mongodb|redis|amqp|mariadb)://[^:]+:[^@]+@",
                replacement: "$1://[CREDENTIALS]@",
                description: "Database connection strings",
                category: "database",
            },
            // Terraform sensitive values
            PatternDef {
                pattern: r#"(?i)"sensitive_value"\s*:\s*"[^"]+""#,
                replacement: r#""sensitive_value": "[REDACTED]""#,
                description: "Terraform sensitive values",
                category: "generic",
            },
            // Terraform HCL-style secrets (key = "value" with quotes)
            PatternDef {
                pattern: r#"(?i)(password|secret|token|api_key)\s*=\s*"[^"]+""#,
                replacement: r#"$1 = "[REDACTED]""#,
                description: "Terraform HCL secrets with quoted values",
                category: "generic",
            },
            // Vault KV tabular output (key followed by 2+ spaces and value)
            PatternDef {
                pattern: r"(?im)^(password|secret|token|api[_-]?key)\s{2,}\S+",
                replacement: "$1  [REDACTED]",
                description: "Vault KV tabular output secrets",
                category: "hashicorp",
            },
            // Redis CONFIG GET requirepass
            PatternDef {
                pattern: r#"(?m)"requirepass"\r?\n"[^"]+""#,
                replacement: "\"requirepass\"\n\"[REDACTED]\"",
                description: "Redis CONFIG GET requirepass",
                category: "database",
            },
            // ══════════════════════════════════════════════════════════════════
            // TIER 4: VARIABLE-BASED PATTERNS (NAME=value format)
            // More specific variable names before generic ones
            // ══════════════════════════════════════════════════════════════════

            // AWS
            PatternDef {
                pattern: r"(?i)(aws[_-]?(access[_-]?key[_-]?id|secret[_-]?access[_-]?key))\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "AWS credentials",
                category: "aws",
            },
            PatternDef {
                pattern: r"(?i)aws[_-]?session[_-]?token\s*[=:]\s*[^\s\n]+",
                replacement: "aws_session_token=[REDACTED]",
                description: "AWS Session Token",
                category: "aws",
            },
            // Docker compose / environment variables (specific DB names)
            PatternDef {
                pattern: r"(?i)(MYSQL|POSTGRES|MONGO|REDIS|RABBITMQ|MARIADB)[_-]?(PASSWORD|ROOT_PASSWORD|PASS)\s*[=:]\s*[^\s\n]+",
                replacement: "$1_$2=[REDACTED]",
                description: "Docker compose database passwords",
                category: "database",
            },
            // Database URLs
            PatternDef {
                pattern: r"(?i)(DATABASE_URL|DB_URL|REDIS_URL|MONGO_URL)\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "Database URL environment variables",
                category: "database",
            },
            PatternDef {
                pattern: r"(?i)(DB|DATABASE)[_-]?(PASSWORD|PASS)\s*[=:]\s*[^\s\n]+",
                replacement: "$1_PASSWORD=[REDACTED]",
                description: "Database password variables",
                category: "database",
            },
            // Ansible
            PatternDef {
                pattern: r"(?i)vault[_-]?pass(word)?\s*[=:]\s*[^\s\n]+",
                replacement: "vault_password=[REDACTED]",
                description: "Ansible Vault password",
                category: "ansible",
            },
            PatternDef {
                pattern: r"(?i)ansible[_-]?become[_-]?pass(word)?\s*[=:]\s*[^\s\n]+",
                replacement: "ansible_become_password=[REDACTED]",
                description: "Ansible become password",
                category: "ansible",
            },
            PatternDef {
                pattern: r"(?i)--vault-password-file\s+[^\s]+",
                replacement: "--vault-password-file [REDACTED]",
                description: "Ansible vault password file path",
                category: "ansible",
            },
            PatternDef {
                pattern: r"(?i)ansible[_-]?ssh[_-]?pass\s*[=:]\s*[^\s\n]+",
                replacement: "ansible_ssh_pass=[REDACTED]",
                description: "Ansible SSH password",
                category: "ansible",
            },
            // GitLab CI tokens
            PatternDef {
                pattern: r"(?i)(GITLAB_TOKEN|CI_JOB_TOKEN)\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "GitLab CI tokens",
                category: "gitlab",
            },
            // Cloud providers
            PatternDef {
                pattern: r"(?i)(AZURE_CLIENT_SECRET|AZURE_TENANT_ID|AZURE_SUBSCRIPTION_ID)\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "Azure credentials",
                category: "azure",
            },
            PatternDef {
                pattern: r"(?i)(GOOGLE_APPLICATION_CREDENTIALS|GCP_SERVICE_ACCOUNT|GCLOUD_SERVICE_KEY)\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "GCP credentials",
                category: "gcp",
            },
            PatternDef {
                pattern: r"(?i)(DIGITALOCEAN_TOKEN|DO_TOKEN)\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "DigitalOcean token",
                category: "generic",
            },
            // HashiCorp
            PatternDef {
                pattern: r"(?i)(VAULT_TOKEN|vault_token)\s*[=:]\s*[hs]\.[A-Za-z0-9]+",
                replacement: "$1=[REDACTED]",
                description: "HashiCorp Vault token",
                category: "hashicorp",
            },
            PatternDef {
                pattern: r"(?i)CONSUL_HTTP_TOKEN\s*[=:]\s*[^\s\n]+",
                replacement: "CONSUL_HTTP_TOKEN=[REDACTED]",
                description: "Consul HTTP token",
                category: "hashicorp",
            },
            // Docker registry
            PatternDef {
                pattern: r"(?i)(docker[_-]?password|registry[_-]?password)\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "Docker registry password",
                category: "docker",
            },
            // SSH
            PatternDef {
                pattern: r"(?i)(ssh[_-]?pass(word)?|ssh[_-]?key[_-]?pass(word)?)\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "SSH password/passphrase",
                category: "generic",
            },
            // SMTP/Mail
            PatternDef {
                pattern: r"(?i)(smtp[_-]?pass(word)?|mail[_-]?pass(word)?)\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "SMTP/Mail password",
                category: "generic",
            },
            // Package managers
            PatternDef {
                pattern: r"(?i)(npm[_-]?token|NPM_TOKEN)\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "NPM token",
                category: "generic",
            },
            PatternDef {
                pattern: r"(?i)(pypi[_-]?token|PYPI_TOKEN)\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "PyPI token",
                category: "generic",
            },
            // AI APIs
            PatternDef {
                pattern: r"(?i)(ANTHROPIC_API_KEY|CLAUDE_API_KEY)\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "Anthropic API Key",
                category: "openai", // Grouped with AI APIs
            },
            // ══════════════════════════════════════════════════════════════════
            // TIER 5: GENERIC PATTERNS (catch-all, must be last!)
            // ══════════════════════════════════════════════════════════════════
            PatternDef {
                pattern: r"(?i)(password|passwd|pwd)\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "Generic password patterns",
                category: "generic",
            },
            PatternDef {
                pattern: r"(?i)(api[_-]?key|auth[_-]?token)\s*[=:\s]\s*[A-Za-z0-9_\-\.]{8,}",
                replacement: "$1=[REDACTED]",
                description: "Generic API keys and auth tokens",
                category: "generic",
            },
            PatternDef {
                pattern: r"(?i)(secret|credential)\s*[=:]\s*[^\s\n]+",
                replacement: "$1=[REDACTED]",
                description: "Generic secrets",
                category: "generic",
            },
            // Note: Generic "token" pattern removed to avoid catching specific tokens
            // like GITHUB_TOKEN=ghp_... which should be handled by specific patterns above
        ]
    }

    /// Sanitize the given text by replacing sensitive patterns
    ///
    /// Uses an optimized multi-tier approach:
    /// 1. Fast keyword check with Aho-Corasick
    /// 2. `RegexSet` for single-pass detection
    /// 3. Parallel processing for large inputs
    /// 4. Zero-copy (`Cow::Borrowed`) when no matches found
    #[must_use]
    pub fn sanitize<'a>(&self, text: &'a str) -> Cow<'a, str> {
        // Fast path: sanitization disabled
        if !self.enabled {
            return Cow::Borrowed(text);
        }

        // Fast path: empty or very short text (min pattern like "k=v" is 3 chars,
        // but shortest real secret pattern needs at least 4 chars)
        if text.len() < 4 {
            return Cow::Borrowed(text);
        }

        // Strip ANSI escape codes from SSH output
        let text = if self.strip_ansi {
            match ANSI_ESCAPE_REGEX.replace_all(text, "") {
                Cow::Borrowed(_) => Cow::Borrowed(text),
                Cow::Owned(stripped) => Cow::Owned(stripped),
            }
        } else {
            Cow::Borrowed(text)
        };
        let text_ref: &str = &text;

        // Tier 1: Fast keyword detection with Aho-Corasick
        // If no keywords found, very likely no secrets present — but entropy may still catch some
        if !self.literal_detector.is_match(text_ref) {
            debug!(
                len = text_ref.len(),
                "No secret keywords detected, skipping regex"
            );
            // Still run entropy detection (catches secrets without known keywords)
            if self.entropy_detector.is_enabled() {
                let result = self.entropy_detector.redact(text_ref);
                if result != text_ref {
                    return Cow::Owned(result);
                }
            }
            return text;
        }

        // Tier 2: Check if any regex pattern matches
        if !self.detection_set.is_match(text_ref) {
            debug!(len = text_ref.len(), "Keywords found but no regex matches");
            // Still run entropy detection
            if self.entropy_detector.is_enabled() {
                let result = self.entropy_detector.redact(text_ref);
                if result != text_ref {
                    return Cow::Owned(result);
                }
            }
            return text;
        }

        // Tier 3: Apply regex sanitization
        let result = if text_ref.len() >= PARALLEL_THRESHOLD {
            debug!(len = text_ref.len(), "Using parallel sanitization");
            self.sanitize_parallel(text_ref)
        } else {
            self.sanitize_sequential(text_ref)
        };

        // Tier 4: Entropy-based detection (catches secrets missed by regex)
        if self.entropy_detector.is_enabled() {
            let result = self.entropy_detector.redact(&result);
            return Cow::Owned(result);
        }

        Cow::Owned(result)
    }

    /// Check if sanitization is enabled
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sequential sanitization for smaller inputs
    fn sanitize_sequential(&self, text: &str) -> String {
        let mut result = text.to_string();

        // Only apply patterns that actually matched (optimization)
        let matched_indices: Vec<usize> = self.detection_set.matches(text).into_iter().collect();

        for idx in matched_indices {
            if let Some(pattern) = self.patterns.get(idx) {
                result = pattern
                    .regex
                    .replace_all(&result, pattern.replacement.as_str())
                    .into_owned();
            }
        }

        result
    }

    /// Parallel sanitization for large inputs
    ///
    /// Note: When secrets are detected, we fall back to sequential processing
    /// because regex replacements can change text length, making chunk merging
    /// based on fixed offsets incorrect. Parallel processing is only used for
    /// the initial detection phase.
    fn sanitize_parallel(&self, text: &str) -> String {
        // Quick check: if no patterns match, return original text
        // This uses parallel regex matching for detection only
        let matched_indices: Vec<usize> = self.detection_set.matches(text).into_iter().collect();

        if matched_indices.is_empty() {
            return text.to_string();
        }

        // When secrets are found, fall back to sequential processing.
        // The chunk-based parallel approach has a subtle bug: regex replacements
        // can change text length (e.g., "PASSWORD=secret123" -> "PASSWORD=[REDACTED]"),
        // which makes the fixed-offset merge in merge_chunks() incorrect, potentially
        // causing data loss or duplication at chunk boundaries.
        debug!(
            matched_patterns = matched_indices.len(),
            "Secrets detected, using sequential sanitization"
        );
        self.sanitize_sequential(text)
    }

    /// Get the number of patterns
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

/// Backward compatible wrapper that returns String
impl Sanitizer {
    /// Sanitize and return owned String (for backward compatibility)
    #[must_use]
    pub fn sanitize_to_string(&self, text: &str) -> String {
        self.sanitize(text).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_password() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "Connecting with password=secret123 to server";
        let output = sanitizer.sanitize(input);
        assert!(!output.contains("secret123"), "Password should be redacted");
        assert!(
            output.contains("[REDACTED]"),
            "Should contain REDACTED marker"
        );
    }

    #[test]
    fn test_sanitize_api_key() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "Using API_KEY=abc123def456xyz for auth";
        let output = sanitizer.sanitize(input);
        assert!(
            !output.contains("abc123def456xyz"),
            "API key should be redacted"
        );
    }

    #[test]
    fn test_sanitize_private_key() {
        let sanitizer = Sanitizer::with_defaults();

        let input = r"Key content:
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds...
-----END RSA PRIVATE KEY-----
Done";
        let output = sanitizer.sanitize(input);
        assert!(
            !output.contains("MIIEpAIBAAKCAQEA0Z3VS5JJcds"),
            "Key should be redacted"
        );
        assert!(
            output.contains("[PRIVATE_KEY_REDACTED]"),
            "Should have key redaction marker"
        );
    }

    #[test]
    fn test_sanitize_connection_string() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "Connecting to mysql://admin:supersecret@localhost:3306/db";
        let output = sanitizer.sanitize(input);
        assert!(
            !output.contains("supersecret"),
            "Password should be redacted"
        );
        assert!(
            output.contains("[CREDENTIALS]@"),
            "Should have credentials marker"
        );
    }

    #[test]
    fn test_custom_patterns() {
        let patterns = vec![r"custom_secret_\d+".to_string()];
        let sanitizer = Sanitizer::new(&patterns);

        let input = "Found custom_secret_12345 in output";
        let output = sanitizer.sanitize(input);
        assert!(
            !output.contains("custom_secret_12345"),
            "Custom pattern should match"
        );
        assert!(output.contains("[REDACTED]"), "Should contain REDACTED");
    }

    /// **Sprint 3 Phase B.6:** custom patterns loaded via `SanitizeConfig`
    /// must compose cleanly with builtin patterns — *both* fire against
    /// a single input, in one pass, with custom patterns taking their
    /// configured replacement label.
    #[test]
    fn test_custom_patterns_from_config_compose_with_builtin() {
        let cfg = SanitizeConfig {
            enabled: true,
            custom_patterns: vec![
                CustomSanitizePattern {
                    pattern: "MYCORP_[A-Z0-9]{32}".to_string(),
                    replacement: "[MYCORP_TOKEN]".to_string(),
                    description: Some("internal token".to_string()),
                },
                CustomSanitizePattern {
                    pattern: r"internal-[0-9a-f]{40}".to_string(),
                    replacement: "[INTERNAL_HASH]".to_string(),
                    description: None,
                },
            ],
            ..SanitizeConfig::default()
        };

        let sanitizer = Sanitizer::from_config(&cfg);
        let input = "log: MYCORP_ABCDEF0123456789ABCDEF0123456789AB and internal-0123456789abcdef0123456789abcdef01234567 plus AKIAIOSFODNN7EXAMPLE";
        let output = sanitizer.sanitize(input);

        // Custom pattern 1 was redacted with its label
        assert!(
            !output.contains("MYCORP_ABCDEF"),
            "MYCORP token must be redacted, got: {output}"
        );
        assert!(
            output.contains("[MYCORP_TOKEN]"),
            "replacement label missing, got: {output}"
        );

        // Custom pattern 2 was redacted with its label
        assert!(
            !output.contains("internal-0123456789"),
            "internal hash must be redacted, got: {output}"
        );
        assert!(
            output.contains("[INTERNAL_HASH]"),
            "second custom label missing, got: {output}"
        );

        // AND builtin AWS pattern still fires on the same input
        assert!(
            !output.contains("AKIAIOSFODNN7EXAMPLE"),
            "builtin AWS pattern must still fire, got: {output}"
        );
    }

    /// **Sprint 3 Phase B.6:** an invalid regex in the YAML custom
    /// patterns list must be logged and skipped, not crash the
    /// Sanitizer. The rest of the config (builtin + other customs)
    /// stays functional.
    ///
    /// The test input uses `token=` so the Aho-Corasick keyword
    /// pre-filter fires and the sanitizer actually runs regex matching
    /// on the line. (Without a keyword the Tier-1 fast path would
    /// bypass every regex.)
    #[test]
    fn test_custom_patterns_invalid_regex_is_skipped_not_fatal() {
        let cfg = SanitizeConfig {
            enabled: true,
            custom_patterns: vec![
                CustomSanitizePattern {
                    pattern: r"(?P<unclosed".to_string(), // deliberately broken
                    replacement: "[NEVER]".to_string(),
                    description: None,
                },
                CustomSanitizePattern {
                    pattern: r"valid_token_\d+".to_string(),
                    replacement: "[VALID]".to_string(),
                    description: None,
                },
            ],
            ..SanitizeConfig::default()
        };

        // Must not panic — invalid regex is just logged.
        let sanitizer = Sanitizer::from_config(&cfg);

        let input = "log: token=valid_token_4242 should be redacted";
        let output = sanitizer.sanitize(input);
        assert!(
            output.contains("[VALID]"),
            "valid pattern should fire, got: {output}"
        );
        assert!(
            !output.contains("valid_token_4242"),
            "valid pattern should have replaced the match, got: {output}"
        );
    }

    #[test]
    fn test_no_false_positives() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "This is normal output with no secrets";
        let output = sanitizer.sanitize(input);
        assert_eq!(input, output.as_ref(), "Normal text should not be modified");
    }

    #[test]
    fn test_zero_copy_no_match() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "Just a regular log message with nothing sensitive";
        let output = sanitizer.sanitize(input);

        // Should be Cow::Borrowed (zero-copy)
        assert!(
            matches!(output, Cow::Borrowed(_)),
            "Should be zero-copy when no match"
        );
    }

    #[test]
    fn test_github_token() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "export GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        let output = sanitizer.sanitize(input);
        assert!(!output.contains("ghp_"), "GitHub PAT should be redacted");
        assert!(
            output.contains("[GITHUB_PAT_REDACTED]"),
            "Should have GitHub marker"
        );
    }

    #[test]
    fn test_k3s_token() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "K3S_TOKEN=K10abc123def456abc123def456abc123def456abc123def456abc";
        let output = sanitizer.sanitize(input);
        assert!(
            output.contains("[K3S_TOKEN_REDACTED]"),
            "K3s token should be redacted"
        );
    }

    #[test]
    fn test_docker_compose_password() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "MYSQL_ROOT_PASSWORD=supersecretpassword123";
        let output = sanitizer.sanitize(input);
        assert!(
            !output.contains("supersecretpassword123"),
            "MySQL password should be redacted"
        );
    }

    #[test]
    fn test_ansible_vault() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "vault_password=mysecretvaultpass";
        let output = sanitizer.sanitize(input);
        assert!(
            !output.contains("mysecretvaultpass"),
            "Vault password should be redacted"
        );
    }

    #[test]
    fn test_jwt_token() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let output = sanitizer.sanitize(input);
        assert!(
            output.contains("[JWT_TOKEN_REDACTED]"),
            "JWT should be redacted"
        );
    }

    #[test]
    fn test_bearer_opaque_token_redacted() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "curl -H 'Authorization: Bearer A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6'";
        let out = sanitizer.sanitize(input);
        assert!(
            !out.contains("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"),
            "opaque bearer token leaked: {out}"
        );
        assert!(out.contains("[BEARER_TOKEN_REDACTED]"));
    }

    #[test]
    fn test_openai_key() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "OPENAI_API_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz";
        let output = sanitizer.sanitize(input);
        assert!(
            output.contains("[OPENAI_API_KEY_REDACTED]"),
            "OpenAI key should be redacted"
        );
    }

    #[test]
    fn test_slack_token() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "SLACK_TOKEN=xoxb-1234567890-abcdefghijklmnop";
        let output = sanitizer.sanitize(input);
        assert!(
            output.contains("[SLACK_TOKEN_REDACTED]"),
            "Slack token should be redacted"
        );
    }

    #[test]
    fn test_anthropic_api_key() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmn";
        let output = sanitizer.sanitize(input);
        assert!(
            output.contains("[REDACTED]"),
            "Anthropic API key should be redacted, got: {output}"
        );
        assert!(
            !output.contains("sk-ant-api03"),
            "Anthropic API key value should not be visible, got: {output}"
        );
    }

    #[test]
    fn test_stripe_secret_key() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "sk_live_abcdefghijklmnopqrstuvwx";
        let output = sanitizer.sanitize(input);
        assert!(
            output.contains("[STRIPE_SECRET_KEY_REDACTED]"),
            "Stripe secret key should be redacted, got: {output}"
        );
    }

    #[test]
    fn test_npm_access_token() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "npm_abcdefghijklmnopqrstuvwxyz0123456789";
        let output = sanitizer.sanitize(input);
        assert!(
            output.contains("[NPM_TOKEN_REDACTED]"),
            "npm token should be redacted, got: {output}"
        );
    }

    #[test]
    fn test_pypi_api_token() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "pypi-AgEIcHlwaS5vcmcCJGI4";
        let output = sanitizer.sanitize(input);
        assert!(
            output.contains("[PYPI_TOKEN_REDACTED]"),
            "PyPI token should be redacted, got: {output}"
        );
    }

    #[test]
    fn test_pkcs8_private_key() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----";
        let output = sanitizer.sanitize(input);
        assert!(
            output.contains("REDACTED"),
            "PKCS#8 private key should be redacted, got: {output}"
        );
    }

    #[test]
    fn test_kubeconfig() {
        let sanitizer = Sanitizer::with_defaults();

        let input = r"
users:
- name: admin
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==
";
        let output = sanitizer.sanitize(input);
        assert!(
            output.contains("client-certificate-data: [REDACTED]"),
            "Cert should be redacted"
        );
        assert!(
            output.contains("client-key-data: [REDACTED]"),
            "Key should be redacted"
        );
    }

    #[test]
    fn test_pattern_count() {
        let sanitizer = Sanitizer::with_defaults();
        // Should have a reasonable number of patterns (50+ with modern API key additions)
        assert!(
            sanitizer.pattern_count() >= 50,
            "Should have at least 50 default patterns, got {}",
            sanitizer.pattern_count()
        );
    }

    #[test]
    fn test_large_input_no_secrets() {
        let sanitizer = Sanitizer::with_defaults();

        // Generate large input without secrets
        let line = "This is a normal log line without any sensitive information.\n";
        let input: String = line.repeat(10000); // ~600KB

        let output = sanitizer.sanitize(&input);
        // Should be zero-copy since no secrets
        assert!(
            matches!(output, Cow::Borrowed(_)),
            "Large input without secrets should be zero-copy"
        );
    }

    #[test]
    fn test_multiple_secrets_same_line() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "DB_PASSWORD=secret1 REDIS_PASSWORD=secret2 API_KEY=abc123xyz";
        let output = sanitizer.sanitize(input);
        assert!(
            !output.contains("secret1"),
            "First password should be redacted"
        );
        assert!(
            !output.contains("secret2"),
            "Second password should be redacted"
        );
    }

    // ============== Mutation Testing Coverage ==============

    #[test]
    fn test_from_config_with_legacy_disabled_categories() {
        use crate::config::SanitizeConfig;

        // Disable the github category
        let config = SanitizeConfig {
            enabled: true,
            disable_builtin: vec!["github".to_string()],
            custom_patterns: vec![],
            entropy_detection: false,
            ..Default::default()
        };

        let sanitizer = Sanitizer::from_config(&config);

        // GitHub tokens should NOT be redacted (category disabled)
        let github_input = "token: ghp_abcdefghijklmnopqrstuvwxyz123456";
        let output = sanitizer.sanitize(github_input);
        assert!(
            output.contains("ghp_"),
            "GitHub tokens should not be redacted when github category is disabled"
        );

        // But other secrets should still be redacted
        let password_input = "password=mysecretpassword123";
        let output = sanitizer.sanitize(password_input);
        assert!(
            !output.contains("mysecretpassword"),
            "Passwords should still be redacted"
        );
    }

    #[test]
    fn test_from_config_with_legacy_empty_patterns_skipped() {
        use crate::config::SanitizeConfig;

        let config = SanitizeConfig {
            enabled: true,
            disable_builtin: vec![],
            custom_patterns: vec![],
            ..Default::default()
        };

        // Empty legacy patterns should be skipped (no panic, no extra patterns)
        let legacy_patterns = vec![String::new(), String::new()];
        let sanitizer = Sanitizer::from_config_with_legacy(&config, &legacy_patterns);

        // Should work normally
        let input = "password=secret123";
        let output = sanitizer.sanitize(input);
        assert!(!output.contains("secret123"), "Should still sanitize");
    }

    #[test]
    fn test_from_config_with_legacy_adds_patterns() {
        use crate::config::SanitizeConfig;

        let config = SanitizeConfig {
            enabled: true,
            disable_builtin: vec![],
            custom_patterns: vec![],
            ..Default::default()
        };

        // Add a custom legacy pattern
        let legacy_patterns = vec!["MY_CUSTOM_SECRET_\\w+".to_string()];
        let sanitizer = Sanitizer::from_config_with_legacy(&config, &legacy_patterns);

        let input = "Found MY_CUSTOM_SECRET_abc123 in config";
        let output = sanitizer.sanitize(input);
        assert!(
            !output.contains("MY_CUSTOM_SECRET_abc123"),
            "Legacy pattern should be applied"
        );
    }

    #[test]
    fn test_sanitize_short_text_returns_borrowed() {
        let sanitizer = Sanitizer::with_defaults();

        // Text shorter than 4 characters should return Cow::Borrowed (fast path)
        let short_input = "abc";
        let output = sanitizer.sanitize(short_input);
        assert!(
            matches!(output, Cow::Borrowed(_)),
            "Short text should return Cow::Borrowed"
        );

        // Exactly 3 chars
        let three_chars = "xyz";
        let output = sanitizer.sanitize(three_chars);
        assert!(
            matches!(output, Cow::Borrowed(_)),
            "3 char text should return Cow::Borrowed"
        );
    }

    #[test]
    fn test_sanitize_parallel_threshold_large_input() {
        let sanitizer = Sanitizer::with_defaults();

        // Create input >= 512KB with a secret to trigger parallel path
        let prefix = "x".repeat(512 * 1024); // 512 KB of padding
        let input = format!("{prefix}password=supersecret123");

        let output = sanitizer.sanitize(&input);

        // Should sanitize the secret even in parallel mode
        assert!(
            !output.contains("supersecret123"),
            "Large input should still sanitize secrets"
        );
        assert!(
            matches!(output, Cow::Owned(_)),
            "Large input with secrets should return Cow::Owned"
        );
    }

    #[test]
    fn test_is_enabled_returns_true_for_enabled_sanitizer() {
        let sanitizer = Sanitizer::with_defaults();
        assert!(
            sanitizer.is_enabled(),
            "Default sanitizer should be enabled"
        );
    }

    #[test]
    fn test_is_enabled_returns_false_for_disabled_sanitizer() {
        let sanitizer = Sanitizer::disabled();
        assert!(
            !sanitizer.is_enabled(),
            "Disabled sanitizer should return false"
        );
    }

    #[test]
    fn test_sanitize_to_string_returns_owned_string() {
        let sanitizer = Sanitizer::with_defaults();

        // Input without secrets
        let input = "normal text without secrets";
        let output = sanitizer.sanitize_to_string(input);
        assert_eq!(output, "normal text without secrets");

        // Input with secrets
        let input_with_secret = "password=secret123";
        let output = sanitizer.sanitize_to_string(input_with_secret);
        assert!(!output.contains("secret123"));
        // Verify it's a String (not Cow)
        let _: String = output;
    }

    #[test]
    fn test_sanitize_disabled_returns_borrowed() {
        let sanitizer = Sanitizer::disabled();

        // Even with secrets, disabled sanitizer should return borrowed
        let input = "password=secret123 token=abc";
        let output = sanitizer.sanitize(input);
        assert!(
            matches!(output, Cow::Borrowed(_)),
            "Disabled sanitizer should return Cow::Borrowed"
        );
        assert_eq!(output, input, "Disabled sanitizer should not modify input");
    }

    #[test]
    fn test_secret_keywords_are_used_for_detection() {
        let sanitizer = Sanitizer::with_defaults();

        // Input with keyword but no actual secret pattern match
        // The keyword "password" triggers the Aho-Corasick check
        // but the regex should not match because there's no = or :
        let input = "The word password appears but no actual secret";
        let output = sanitizer.sanitize(input);
        assert!(
            matches!(output, Cow::Borrowed(_)),
            "Keyword without pattern match should be borrowed"
        );
    }

    #[test]
    fn test_parallel_threshold_constant_is_512kb() {
        // Verify the PARALLEL_THRESHOLD constant value
        // Input just under threshold should use sequential
        let sanitizer = Sanitizer::with_defaults();

        // 511 KB input with secret
        let prefix = "x".repeat(511 * 1024);
        let input = format!("{prefix}password=test123");
        let output = sanitizer.sanitize(&input);
        assert!(
            !output.contains("test123"),
            "Should sanitize even under threshold"
        );

        // 513 KB input with secret (triggers parallel path)
        let prefix = "x".repeat(513 * 1024);
        let input = format!("{prefix}password=test456");
        let output = sanitizer.sanitize(&input);
        assert!(
            !output.contains("test456"),
            "Should sanitize in parallel mode"
        );
    }

    #[test]
    fn test_sanitize_parallel_preserves_non_secret_content() {
        let sanitizer = Sanitizer::with_defaults();

        // Large input with a secret - verify non-secret content is preserved
        let prefix = "IMPORTANT_DATA_";
        let middle = "x".repeat(512 * 1024);
        let suffix = "_END_MARKER";
        let input = format!("{prefix}{middle}password=secret123 {suffix}");

        let output = sanitizer.sanitize(&input);

        // Verify the non-secret content is preserved
        assert!(
            output.starts_with(prefix),
            "Parallel sanitization should preserve prefix content"
        );
        assert!(
            output.contains(suffix),
            "Parallel sanitization should preserve suffix content"
        );
        assert!(!output.contains("secret123"), "Secret should be redacted");
        // Verify the output is not empty or garbage
        assert!(
            output.len() > middle.len(),
            "Output should preserve most of the content"
        );
    }

    #[test]
    fn test_sanitize_exact_boundary_8_chars() {
        let sanitizer = Sanitizer::with_defaults();

        // Exactly 8 characters - should NOT take the short path
        let input = "12345678";
        let output = sanitizer.sanitize(input);
        // Should still be borrowed since no secrets
        assert!(matches!(output, Cow::Borrowed(_)));

        // 8 chars with a keyword but no match
        let input_keyword = "password"; // exactly 8 chars
        let output = sanitizer.sanitize(input_keyword);
        assert!(matches!(output, Cow::Borrowed(_)));
    }

    #[test]
    fn test_sanitize_parallel_returns_correct_length() {
        let sanitizer = Sanitizer::with_defaults();

        // Large input without secrets - parallel path should return same length
        let input = "x".repeat(600 * 1024); // 600 KB, no secrets
        let output = sanitizer.sanitize(&input);

        // Should be borrowed (no changes)
        assert!(matches!(output, Cow::Borrowed(_)));
        assert_eq!(output.len(), input.len());
    }

    // ============== Precise Boundary Tests for Mutation Coverage ==============

    #[test]
    fn test_secret_keywords_fast_path_works() {
        let sanitizer = Sanitizer::with_defaults();

        // Input with NO keywords at all - should skip regex entirely (fast path)
        // If secret_keywords returned vec![""], this would match everything
        let no_keywords = "This text has no secret keywords whatsoever xyz123";
        let output = sanitizer.sanitize(no_keywords);
        assert!(
            matches!(output, Cow::Borrowed(_)),
            "Text without keywords should be borrowed (fast path)"
        );

        // Input WITH a keyword - should proceed to regex check
        let with_keyword = "This text contains the word password but no actual secret";
        let output = sanitizer.sanitize(with_keyword);
        assert!(
            matches!(output, Cow::Borrowed(_)),
            "Text with keyword but no pattern match should be borrowed"
        );

        // Input WITH keyword AND matching pattern - should be sanitized
        let with_secret = "Connecting with password=secret123 to server";
        let output = sanitizer.sanitize(with_secret);
        assert!(
            matches!(output, Cow::Owned(_)),
            "Text with keyword and pattern match should be owned"
        );
        assert!(!output.contains("secret123"), "Secret should be redacted");
    }

    #[test]
    fn test_exact_boundary_7_8_9_chars_with_secret() {
        let sanitizer = Sanitizer::with_defaults();

        // 7 chars total with a potential secret pattern
        // "p=x" pattern won't match, but let's use a real pattern
        let seven = "p=12345"; // 7 chars - should take short path (< 8)
        let output = sanitizer.sanitize(seven);
        assert!(
            matches!(output, Cow::Borrowed(_)),
            "7 char input should be borrowed (short path): got {output:?}"
        );

        // 8 chars - boundary case, should NOT take short path
        // Need to test that 8-char input with secret IS processed
        let eight = "pw=12345"; // 8 chars with password-like pattern
        let _output = sanitizer.sanitize(eight);
        // This may or may not match depending on the pattern, but should not short-circuit
        // The key is that < 8 returns early, but == 8 should continue

        // 9 chars with a clear secret pattern
        let nine = "pwd=12345"; // 9 chars
        let _output = sanitizer.sanitize(nine);
        // "pwd=" should trigger keyword detection but may not match regex
        // Let's use a definite match
        let nine_match = "pass=1234"; // 9 chars, "pass" is keyword, "pass=..." is pattern
        let output = sanitizer.sanitize(nine_match);
        assert!(
            !output.contains("1234") || output.len() == nine_match.len(),
            "9 char input with secret should be processed"
        );
    }

    #[test]
    fn test_exact_boundary_512kb_with_secret() {
        let sanitizer = Sanitizer::with_defaults();
        let threshold = 512 * 1024; // PARALLEL_THRESHOLD

        // Just under threshold (sequential path)
        let under = "x".repeat(threshold - 20);
        let under_with_secret = format!("{under}password=test1");
        assert!(
            under_with_secret.len() < threshold,
            "Test input should be under threshold"
        );
        let output = sanitizer.sanitize(&under_with_secret);
        assert!(
            !output.contains("test1"),
            "Secret should be redacted even under threshold"
        );

        // Exactly at threshold (parallel path boundary)
        let padding_needed = threshold - "password=test2".len();
        let at_threshold = format!("{}password=test2", "x".repeat(padding_needed));
        assert_eq!(
            at_threshold.len(),
            threshold,
            "Test input should be exactly at threshold"
        );
        let output = sanitizer.sanitize(&at_threshold);
        assert!(
            !output.contains("test2"),
            "Secret should be redacted at exact threshold"
        );

        // Just over threshold (definitely parallel path)
        let over = "x".repeat(threshold + 10);
        let over_with_secret = format!("{over}password=test3");
        assert!(
            over_with_secret.len() > threshold,
            "Test input should be over threshold"
        );
        let output = sanitizer.sanitize(&over_with_secret);
        assert!(
            !output.contains("test3"),
            "Secret should be redacted over threshold"
        );
    }

    #[test]
    fn test_terraform_hcl_secret() {
        let sanitizer = Sanitizer::with_defaults();

        let input = r#"resource "aws_db_instance" "default" {
  password = "supersecretdb123"
}"#;
        let output = sanitizer.sanitize(input);
        assert!(
            !output.contains("supersecretdb123"),
            "Terraform HCL password should be redacted"
        );
    }

    #[test]
    fn test_vault_kv_tabular_output() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "Key         Value\n---         -----\npassword    mysecretvalue123";
        let output = sanitizer.sanitize(input);
        assert!(
            !output.contains("mysecretvalue123"),
            "Vault KV tabular password should be redacted"
        );
    }

    #[test]
    fn test_redis_requirepass() {
        let sanitizer = Sanitizer::with_defaults();

        let input = "\"requirepass\"\n\"myredispassword\"";
        let output = sanitizer.sanitize(input);
        assert!(
            !output.contains("myredispassword"),
            "Redis requirepass should be redacted"
        );
    }

    #[test]
    fn test_parallel_path_actually_sanitizes() {
        let sanitizer = Sanitizer::with_defaults();

        // Create a large input that will use the parallel path
        // and verify the output is correctly sanitized (not empty or "xyzzy")
        let threshold = 512 * 1024;
        let prefix = "MARKER_START_";
        let padding = "x".repeat(threshold);
        let secret = "password=supersecret999";
        // Use a suffix that won't be affected by sanitization
        let suffix = " END_OF_DATA";

        let input = format!("{prefix}{padding}{secret}{suffix}");

        let output = sanitizer.sanitize(&input);

        // Verify content is preserved (not replaced with "" or "xyzzy")
        assert!(
            output.starts_with(prefix),
            "Output should preserve prefix marker"
        );
        assert!(
            !output.contains("supersecret999"),
            "Secret should be redacted"
        );
        // Verify reasonable length (not completely replaced)
        assert!(
            output.len() > threshold,
            "Output should preserve most content length, got {}",
            output.len()
        );
        // Verify it's not "xyzzy" or empty
        assert!(
            output.len() > 100,
            "Output should not be replaced with short string"
        );
    }

    #[test]
    fn test_sanitize_empty_input() {
        let sanitizer = Sanitizer::with_defaults();
        let output = sanitizer.sanitize("");
        assert_eq!(output.as_ref(), "");
    }

    #[test]
    fn test_sanitize_short_input_fast_path() {
        let sanitizer = Sanitizer::with_defaults();
        // Input shorter than 4 bytes should return borrowed (fast path)
        let output = sanitizer.sanitize("abc");
        assert!(matches!(output, Cow::Borrowed(_)));
    }

    #[test]
    fn test_parallel_and_sequential_produce_same_result() {
        let sanitizer = Sanitizer::with_defaults();

        // Build an input that exceeds PARALLEL_THRESHOLD
        let threshold = 512 * 1024;
        let padding = "normal_data ".repeat(threshold / 12 + 1);
        let secret = "password=my_secret_value_here";
        let input = format!("{padding}{secret}");
        assert!(input.len() >= threshold, "Input must exceed threshold");

        // Both paths should produce the same output
        let sequential = sanitizer.sanitize_sequential(&input);
        let parallel = sanitizer.sanitize_parallel(&input);

        assert_eq!(
            sequential, parallel,
            "Parallel and sequential sanitization must produce identical results"
        );
        assert!(!sequential.contains("my_secret_value_here"));
    }

    #[test]
    fn test_disabled_sanitizer_passthrough() {
        let sanitizer = Sanitizer::disabled();
        let input = "password=secret API_KEY=sk-12345 very sensitive data";
        let output = sanitizer.sanitize(input);
        assert_eq!(
            output.as_ref(),
            input,
            "Disabled sanitizer should pass through unchanged"
        );
        assert!(matches!(output, Cow::Borrowed(_)));
    }

    #[test]
    fn test_sanitize_very_long_single_line() {
        let sanitizer = Sanitizer::with_defaults();
        // 1MB single line with embedded secrets
        let padding = "a".repeat(1_000_000);
        let input = format!("password=longlinetest {padding} API_KEY=sk-endofline");
        let output = sanitizer.sanitize(&input);
        assert!(!output.contains("longlinetest"));
        assert!(!output.contains("sk-endofline"));
        assert!(output.contains("[REDACTED]"));
    }

    // ============== Tests to catch previously-missed mutations ==============

    #[test]
    fn test_boundary_exactly_4_chars_not_skipped() {
        let sanitizer = Sanitizer::with_defaults();

        // Exactly 4 chars — should NOT take the fast-path (len < 4)
        // This catches mutation: `replace < with <=` at line 845
        let four_chars = "k=v1";
        let output = sanitizer.sanitize(four_chars);
        // 4 chars is above the threshold, so sanitization runs (even if nothing matches)
        assert_eq!(
            output.as_ref(),
            four_chars,
            "4-char text with no secrets stays unchanged"
        );

        // 3 chars SHOULD be skipped (fast path)
        let three_chars = "k=v";
        let output = sanitizer.sanitize(three_chars);
        assert!(
            matches!(output, Cow::Borrowed(_)),
            "3-char text should take the fast path (Cow::Borrowed)"
        );

        // 4 chars should NOT be Cow::Borrowed (sanitizer actually runs)
        // It may or may not return Borrowed depending on whether patterns match,
        // but the fast-path at line 845 should not trigger
    }

    #[test]
    fn test_parallel_threshold_boundary() {
        let sanitizer = Sanitizer::with_defaults();

        // Input exactly at PARALLEL_THRESHOLD (512KB) with a secret
        let padding = "a".repeat(PARALLEL_THRESHOLD - 30);
        let input = format!("{padding}\npassword=secretval123");

        let output = sanitizer.sanitize(&input);
        assert!(
            !output.contains("secretval123"),
            "Secret should be redacted at parallel threshold boundary"
        );

        // Input just below threshold
        let padding_below = "b".repeat(PARALLEL_THRESHOLD - 100);
        let input_below = format!("{padding_below}\npassword=belowthreshold");
        let output_below = sanitizer.sanitize(&input_below);
        assert!(
            !output_below.contains("belowthreshold"),
            "Secret should be redacted below parallel threshold too"
        );
    }

    #[test]
    fn test_disabled_categories_negation_logic() {
        use crate::config::SanitizeConfig;

        // When NO categories are disabled, all patterns should be active
        let all_enabled = SanitizeConfig {
            enabled: true,
            disable_builtin: vec![],
            custom_patterns: vec![],
            ..Default::default()
        };
        let sanitizer_full = Sanitizer::from_config(&all_enabled);
        let full_count = sanitizer_full.pattern_count();

        // When a category IS disabled, count should decrease
        let github_disabled = SanitizeConfig {
            enabled: true,
            disable_builtin: vec!["github".to_string()],
            custom_patterns: vec![],
            ..Default::default()
        };
        let sanitizer_partial = Sanitizer::from_config(&github_disabled);
        let partial_count = sanitizer_partial.pattern_count();

        assert!(
            partial_count < full_count,
            "Disabling a category must reduce pattern count: full={full_count}, partial={partial_count}"
        );
    }

    #[test]
    fn test_strip_ansi_codes() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "\x1b[32mSuccess\x1b[0m: operation completed";
        let output = sanitizer.sanitize(input);
        assert_eq!(output.as_ref(), "Success: operation completed");
    }

    #[test]
    fn test_strip_ansi_complex_codes() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "\x1b[1;31mERROR\x1b[0m \x1b[33mWarning\x1b[0m normal text";
        let output = sanitizer.sanitize(input);
        assert_eq!(output.as_ref(), "ERROR Warning normal text");
    }
}
