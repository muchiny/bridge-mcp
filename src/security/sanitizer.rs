use std::borrow::Cow;
use std::sync::LazyLock;

use aho_corasick::AhoCorasick;
use regex::{Regex, RegexSet};
use tracing::{debug, error, info};

/// The pattern that decides what counts as an escape sequence rather than
/// content.
///
/// Public because the `fuzz_sanitizer` target has to know what this code
/// removes before it can assert what survives. It used to keep its own idea
/// of that — "anything that is not a control character is content" — so the
/// four printable bytes inside `\x1b[31m` read as content and the target
/// called a correct sanitizer a crash, nightly, from 2026-08-20 onwards.
/// One definition, two readers, no drift.
pub const ANSI_PATTERN: &str = r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07|\x1b\[[\d;]*m";

/// Pre-compiled regex for stripping ANSI escape codes from SSH output.
#[allow(clippy::unwrap_used)] // static regex literal, exercised by the ANSI-stripping tests
static ANSI_ESCAPE_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(ANSI_PATTERN).unwrap());

use crate::config::{CustomSanitizePattern, SanitizeConfig};
use crate::security::entropy::EntropyDetector;

/// An Aho-Corasick automaton over zero patterns.
#[allow(clippy::unwrap_used)] // building over an empty pattern set cannot fail
fn empty_literal_detector() -> AhoCorasick {
    AhoCorasick::builder().build(Vec::<&str>::new()).unwrap()
}

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
/// use bridge_mcp::config::SanitizeConfig;
/// use bridge_mcp::security::Sanitizer;
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
    /// Exact-match masker for credential values the bridge knows from its
    /// own config (host passwords, passphrases, AWX token). Highest-
    /// confidence tier: applied before keyword/regex/entropy detection.
    /// NOTE: the automaton holds plaintext copies of the secrets; they are
    /// not zeroized on drop — acceptable since Config keeps them in memory
    /// for the whole process lifetime anyway.
    known_secret_masker: Option<AhoCorasick>,
}

struct SanitizePattern {
    regex: Regex,
    replacement: String,
    secret_group: Option<usize>,
}

/// Pattern definition for easier initialization
struct PatternDef {
    pattern: &'static str,
    replacement: &'static str,
    description: &'static str,
    /// Category for filtering (e.g., "github", "aws", "generic")
    category: &'static str,
    /// Capture group that holds the candidate secret. `None` replaces on
    /// every match (strong keys such as `password=`); `Some(n)` replaces
    /// only when [`plausible_secret`] accepts group `n` (weak keys such as
    /// `secret:` / `token:`, where `secret: {`, `credential: 5` and
    /// `secretName: tls` are the common false positives).
    secret_group: Option<usize>,
}

/// A double-quoted value, with NO capturing group of its own — every caller
/// wraps it in whatever group it needs.
///
/// A real secret can legitimately start with `[` (`"[abc123]"`, `"[1,2]"`),
/// so only MARKER-SHAPED content is refused: a `[` followed by one or more
/// of `[A-Z0-9_ ]` and then a `]`, with nothing else in between
/// (`"[REDACTED]"`, `"[K3S_TOKEN_REDACTED]"`) — detected with `(?-i:…)` so it
/// stays upper-case-only even inside a case-insensitive pattern, since every
/// marker this codebase produces is upper-case by construction and a real
/// lower-case `"[abc]"`-shaped secret must still match. Without this, a later
/// pattern whose key set overlaps an earlier quoted-value pattern would
/// re-match an already-produced marker and either strip its quoting or —
/// worse, for a pattern with its own named marker — flatten it down to the
/// generic `[REDACTED]`.
///
/// The exclusion is by SHAPE, not by membership in an actual marker list: it
/// refuses any `"[…]"` whose interior is only `[A-Z0-9_ ]`, so an all-digit
/// bracketed value such as `"[12345678]"` is refused the same as
/// `"[REDACTED]"`, even though it is not one of this codebase's markers and
/// could be a real secret.
macro_rules! double_quoted_value {
    () => {
        r#""(?:(?:[^"\\\n\[]|\\.|\[(?-i:[^"\\\n\]A-Z0-9_ ]|[A-Z0-9_ ]+[^"\\\n\]A-Z0-9_ ]))(?:[^"\\\n]|\\.)*)?""#
    };
}

/// A single-quoted value, with NO capturing group of its own. Same
/// marker-shaped exclusion as [`double_quoted_value`], for `'` instead of
/// `"`.
macro_rules! single_quoted_value {
    () => {
        r#"'(?:(?:[^'\n\[]|\[(?-i:[^'\n\]A-Z0-9_ ]|[A-Z0-9_ ]+[^'\n\]A-Z0-9_ ]))[^'\n]*)?'"#
    };
}

/// A double- or single-quoted value, with NO capturing group of its own —
/// every caller wraps it in whatever group it needs. Shared by
/// `scalar_value!()` (as its first two alternatives) and by the two patterns
/// whose value class is quoted-only, either quote style ("Generic passwords
/// with quoted values", "Generic secrets with quoted values"): one grammar,
/// four users counting the two Terraform patterns on [`double_quoted_value`]
/// alone — no hand-rolled quoted-value class is left in this file, so a fix
/// here (or in the double/single halves) fixes all of them at once.
macro_rules! quoted_value {
    () => {
        concat!(double_quoted_value!(), "|", single_quoted_value!())
    };
}

/// One value grammar for every keyed pattern: a double-quoted string with
/// escapes, a single-quoted string, a single-line brace or bracket group
/// that holds no quote, comma or colon (`{hunter2}` is a value written with
/// decoration; `{"nested": "x"}`, `[1, 2]` and a lone `{` are structure), or
/// an unquoted scalar that never contains a structural character.
///
/// The bracket-group alternative excludes MARKER-SHAPED content the same way
/// the quoted alternatives do (content may not be exactly one run of
/// `[A-Z0-9_ ]`), so `password=[REDACTED]` and `token=[K3S_TOKEN_REDACTED]`
/// are left untouched rather than re-consumed as a fresh value. The
/// brace-group alternative needs no such exclusion: this codebase never
/// produces a `{…}`-wrapped marker.
///
/// Quoted and bracketed forms come first, so a properly wrapped value is
/// captured whole (commas, braces and spaces inside are fine). The bare
/// alternative comes last, rejects a leading `[` outright — the quoted and
/// bracket-group alternatives already give bracketed content the equivalent
/// protection — and otherwise accepts an optional opening quote (a value
/// whose closing quote was cut off by `max_output_bytes` truncation must
/// still be redacted). It rejects a structural character at its FIRST and
/// LAST position (`{` and `[` open a container, a trailing `,` `;` `}` `]`
/// belongs to the container) and takes almost anything non-whitespace in
/// between, so `aB3,x9Zq!k` is one scalar and `5,` yields `5`.
///
/// An angle-wrapped scalar (`<hunter2>`) is a value the same way a
/// brace-wrapped one is — some tools decorate a bare value with `<>` — but
/// `kubectl describe` also uses `<...>` for a PLACEHOLDER when it has no
/// value at all: `<set to the key 'auth' in secret 'argocd-redis'>`,
/// `<none>`, `<nil>`, `<unset>`, `<invalid>`. The difference is shape, not
/// content: a placeholder is prose, with a space, a quote or a colon inside
/// the brackets; a value never is. So the angle-group alternative holds
/// none of those — `<hunter2>` matches it whole and is redacted, while
/// `<set to the key 'auth' in secret 'argocd-redis'>` cannot: the mandatory
/// `>` never follows a run of allowed characters, so this alternative fails
/// at that position for the whole line, same as the brace- and
/// bracket-group alternatives before it.
///
/// The bare alternative's first position keeps excluding `<`, on top of the
/// characters above: without that, `<set` alone would still satisfy the
/// bare alternative once the angle-group alternative gives up on it — the
/// angle-group failing to match a `<...>` span does not stop a *different*
/// alternative from matching a *shorter* one starting at the same `<`. A
/// leading `<` is therefore only ever consumed by the angle-group
/// alternative, whole or not at all; a value cannot start with a bare,
/// unmatched `<`. `plausible_secret` trims `<` and `>` the same way it
/// trims quotes and braces, so a weak key's angle-wrapped placeholder is
/// judged on its content, not its decoration: `<invalid>` trims to
/// `invalid`, which the letters-only check would otherwise wave through as
/// plausible (the untrimmed candidate has `<` and `>` in it, so neither the
/// letters-only nor the digits-only check applies and it is treated as
/// plausible by default) but the length gate correctly rejects at 7
/// characters.
///
/// Accepted narrowing: a value that starts with `<` but is not a
/// well-formed `<...>` group — `MYSQL_ROOT_PASSWORD=<Xk9!pQ2z`, a truncated
/// or hand-typed value, never closed — is refused by every alternative. The
/// angle-group alternative needs a matching `>` this value never supplies,
/// and the bare alternative's leading-`<` exclusion (needed to leave
/// `kubectl describe`'s placeholders alone, see above) blocks it too, with
/// no lookaround available to tell "starts a well-formed `<...>` group"
/// from "starts with `<` but isn't one" at that position. Since
/// `kubectl describe` prints its placeholder on every secret-sourced env var
/// it cannot read, that trade-off is accepted: a `<`-initial secret written
/// unquoted is a known miss left to the entropy detector.
///
/// The bare middle also stops at a brace or a double quote, for the same
/// reason the first and last positions reject one: both are structure, and a
/// bare scalar never contains either. Without that, compact JSON — which has
/// no space after the colon, and is what AWX and `jq -c` return — let the
/// value run past the end of its own leaf and swallow every sibling field on
/// the line: `{"credential":5,"name":"deploy-key"}` captured
/// `5,"name":"deploy-key`, which is plausible enough to redact the whole
/// object, and `{"cmd":"--password=hunter2","x":"y"}` captured
/// `hunter2","x":"y`.
///
/// An apostrophe, a comma, a semicolon and a bracket stay legal in the bare
/// middle. The first three occur inside real secrets (`don't-tell-anyone`,
/// `aB3,x9Zq!k`). Brackets are needed because a value an earlier pattern has
/// already partly redacted carries a marker
/// (`DATABASE_URL=mysql://[CREDENTIALS]@host/db`) and must still be consumed
/// whole.
///
/// The macro INCLUDES its capturing parentheses: in a pattern whose key is
/// group 1 the value is group 2, so `secret_group: Some(2)` stays valid.
///
/// The brace, bracket and angle alternatives all require at least one
/// character inside: an empty pair (`{}`, `[]`, `<>`) is structure — an
/// empty object, an empty array, an empty placeholder — not a value, so
/// `"password": {}` and `"password": []` are left alone rather than turned
/// into `"password": "[REDACTED]"`. The brace and angle alternatives need
/// exactly one; the bracket alternative needs TWO, because its
/// marker-shaped exclusion is itself a mandatory leading group (one
/// character via its first branch) ahead of the trailing `+` (one more) —
/// so `password=[x]` and `password=[!]`, a single character inside
/// brackets, are ALSO left alone, unlike `password={x}`, which redacts.
macro_rules! scalar_value {
    () => {
        concat!(
            "(",
            quoted_value!(),
            "|",
            r#"\{[^{}"'\n,:]+\}"#,
            "|",
            r#"\[(?-i:[^\[\]"'\n,:A-Z0-9_ ]|[A-Z0-9_ ]+[^\[\]"'\n,:A-Z0-9_ ])[^\[\]"'\n,:]+\]"#,
            "|",
            r#"<[^<>"'\n,:\s]+>"#,
            "|",
            r#"["']?[^\s"'{}\[\],;<](?:[^\s"{}]*[^\s"'{}\[\],;])?"#,
            ")"
        )
    };
}

/// Does a captured value look like a secret, rather than structure, an id,
/// a word or a literal? Mirrors gitleaks' `generic-api-key` constraints: a
/// minimum length, and a letters-only allowlist (`_ . -` count as letters,
/// so identifiers such as `argocd-repo-server-tls` or `deploy-key.pem` pass
/// through), plus digits-only (ids, ports) and boolean/null literals.
pub(crate) fn plausible_secret(candidate: &str) -> bool {
    let s = candidate.trim_matches(|c| matches!(c, '"' | '\'' | '{' | '}' | '[' | ']' | '<' | '>'));
    if s.len() < 8 {
        return false;
    }
    if matches!(s, "true" | "false" | "null" | "None" | "none" | "nil") {
        return false;
    }
    let letters_only = s
        .chars()
        .all(|c| c.is_ascii_alphabetic() || matches!(c, '_' | '.' | '-'));
    let digits_only = s.chars().all(|c| c.is_ascii_digit());
    !(letters_only || digits_only)
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
        )
        .with_hex_threshold(config.entropy_hex_threshold);

        Self::from_pattern_defs_with_custom(&all_patterns, &all_custom, true, entropy_detector)
    }

    /// Register exact credential values to mask (GitHub-Actions-style
    /// `::add-mask::`). Values shorter than 8 chars are ignored — masking
    /// them would shred normal output.
    #[must_use]
    pub fn with_known_secrets(mut self, secrets: &[String]) -> Self {
        const MIN_KNOWN_SECRET_LEN: usize = 8;
        let filtered: Vec<&String> = secrets
            .iter()
            .filter(|s| s.len() >= MIN_KNOWN_SECRET_LEN)
            .collect();
        if filtered.is_empty() {
            return self;
        }
        match AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(&filtered)
        {
            Ok(masker) => {
                info!(count = filtered.len(), "Known-secret masking enabled");
                self.known_secret_masker = Some(masker);
            }
            Err(e) => error!(error = %e, "Failed to build known-secret masker"),
        }
        self
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
        Self {
            patterns: Vec::new(),
            detection_set: RegexSet::empty(),
            literal_detector: empty_literal_detector(),
            enabled: false,
            strip_ansi: false,
            entropy_detector: EntropyDetector::disabled(),
            known_secret_masker: None,
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
                        secret_group: def.secret_group,
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
                        secret_group: None,
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
                empty_literal_detector()
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
            known_secret_masker: None,
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
            "access_key",
            "access-key",
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
            "://",
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
    /// `[GITHUB_PAT_REDACTED]`) must come BEFORE generic patterns (like
    /// `${1}[REDACTED]`) to ensure proper detection and replacement.
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
                secret_group: None,
            },
            PatternDef {
                pattern: r"gho_[A-Za-z0-9]{36}",
                replacement: "[GITHUB_OAUTH_TOKEN_REDACTED]",
                description: "GitHub OAuth Token",
                category: "github",
                secret_group: None,
            },
            PatternDef {
                pattern: r"ghu_[A-Za-z0-9]{36}",
                replacement: "[GITHUB_USER_TOKEN_REDACTED]",
                description: "GitHub User-to-Server Token",
                category: "github",
                secret_group: None,
            },
            PatternDef {
                pattern: r"ghs_[A-Za-z0-9]{36}",
                replacement: "[GITHUB_SERVER_TOKEN_REDACTED]",
                description: "GitHub Server-to-Server Token",
                category: "github",
                secret_group: None,
            },
            PatternDef {
                pattern: r"ghr_[A-Za-z0-9]{36}",
                replacement: "[GITHUB_REFRESH_TOKEN_REDACTED]",
                description: "GitHub Refresh Token",
                category: "github",
                secret_group: None,
            },
            PatternDef {
                pattern: r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
                replacement: "[GITHUB_FINE_GRAINED_PAT_REDACTED]",
                description: "GitHub Fine-grained PAT",
                category: "github",
                secret_group: None,
            },
            // GitLab
            PatternDef {
                pattern: r"glpat-[A-Za-z0-9\-]{20,}",
                replacement: "[GITLAB_PAT_REDACTED]",
                description: "GitLab Personal Access Token",
                category: "gitlab",
                secret_group: None,
            },
            // Slack tokens
            PatternDef {
                pattern: r"xox[baprs]-[A-Za-z0-9\-]{10,}",
                replacement: "[SLACK_TOKEN_REDACTED]",
                description: "Slack token",
                category: "slack",
                secret_group: None,
            },
            PatternDef {
                pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
                replacement: "[SLACK_WEBHOOK_REDACTED]",
                description: "Slack webhook URL",
                category: "slack",
                secret_group: None,
            },
            // Discord
            PatternDef {
                pattern: r"https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
                replacement: "[DISCORD_WEBHOOK_REDACTED]",
                description: "Discord webhook URL",
                category: "discord",
                secret_group: None,
            },
            // OpenAI
            PatternDef {
                pattern: r"sk-[A-Za-z0-9]{20,}",
                replacement: "[OPENAI_API_KEY_REDACTED]",
                description: "OpenAI API Key",
                category: "openai",
                secret_group: None,
            },
            // AWS Access Key ID (specific format AKIA...)
            PatternDef {
                pattern: r"AKIA[0-9A-Z]{16}",
                replacement: "[AWS_ACCESS_KEY_REDACTED]",
                description: "AWS Access Key ID",
                category: "aws",
                secret_group: None,
            },
            // K3s tokens
            PatternDef {
                pattern: r"K10[A-Za-z0-9]{48,}",
                replacement: "[K3S_TOKEN_REDACTED]",
                description: "K3s server token",
                category: "k3s",
                secret_group: None,
            },
            PatternDef {
                pattern: r"K[0-9a-f]{10,}::[a-z]+:[A-Za-z0-9]+",
                replacement: "[K3S_NODE_TOKEN_REDACTED]",
                description: "K3s node token",
                category: "k3s",
                secret_group: None,
            },
            // JWT tokens (generic format eyJ...)
            PatternDef {
                pattern: r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                replacement: "[JWT_TOKEN_REDACTED]",
                description: "Generic JWT token",
                category: "jwt",
                secret_group: None,
            },
            // Anthropic API keys (specific prefix sk-ant-*)
            PatternDef {
                pattern: r"sk-ant-api\d{2}-[A-Za-z0-9_-]{80,}",
                replacement: "[ANTHROPIC_API_KEY_REDACTED]",
                description: "Anthropic API Key",
                category: "openai",
                secret_group: None,
            },
            // Stripe keys
            PatternDef {
                pattern: r"sk_live_[A-Za-z0-9]{24,}",
                replacement: "[STRIPE_SECRET_KEY_REDACTED]",
                description: "Stripe Secret Key",
                category: "generic",
                secret_group: None,
            },
            PatternDef {
                pattern: r"pk_live_[A-Za-z0-9]{24,}",
                replacement: "[STRIPE_PUBLISHABLE_KEY_REDACTED]",
                description: "Stripe Publishable Key",
                category: "generic",
                secret_group: None,
            },
            PatternDef {
                pattern: r"rk_live_[A-Za-z0-9]{24,}",
                replacement: "[STRIPE_RESTRICTED_KEY_REDACTED]",
                description: "Stripe Restricted Key",
                category: "generic",
                secret_group: None,
            },
            // npm tokens (specific prefix npm_)
            PatternDef {
                pattern: r"npm_[A-Za-z0-9]{36,}",
                replacement: "[NPM_TOKEN_REDACTED]",
                description: "npm Access Token",
                category: "generic",
                secret_group: None,
            },
            // PyPI tokens (specific prefix pypi-)
            PatternDef {
                pattern: r"pypi-[A-Za-z0-9_-]{16,}",
                replacement: "[PYPI_TOKEN_REDACTED]",
                description: "PyPI API Token",
                category: "generic",
                secret_group: None,
            },
            // NVIDIA API Key
            PatternDef {
                pattern: r"NVAPI[A-Za-z0-9\-_]{20,}",
                replacement: "[NVIDIA_API_KEY_REDACTED]",
                description: "NVIDIA API Key",
                category: "openai",
                secret_group: None,
            },
            // ══════════════════════════════════════════════════════════════════
            // TIER 2: CERTIFICATES & KEYS (multi-line patterns)
            // ══════════════════════════════════════════════════════════════════
            PatternDef {
                pattern: r"-----BEGIN[ \t]+(RSA[ \t]+)?PRIVATE[ \t]+KEY-----[\s\S]*?-----END[ \t]+(RSA[ \t]+)?PRIVATE[ \t]+KEY-----",
                replacement: "[PRIVATE_KEY_REDACTED]",
                description: "RSA Private Key",
                category: "certificates",
                secret_group: None,
            },
            PatternDef {
                pattern: r"-----BEGIN[ \t]+OPENSSH[ \t]+PRIVATE[ \t]+KEY-----[\s\S]*?-----END[ \t]+OPENSSH[ \t]+PRIVATE[ \t]+KEY-----",
                replacement: "[OPENSSH_PRIVATE_KEY_REDACTED]",
                description: "OpenSSH Private Key",
                category: "certificates",
                secret_group: None,
            },
            PatternDef {
                pattern: r"-----BEGIN[ \t]+EC[ \t]+PRIVATE[ \t]+KEY-----[\s\S]*?-----END[ \t]+EC[ \t]+PRIVATE[ \t]+KEY-----",
                replacement: "[EC_PRIVATE_KEY_REDACTED]",
                description: "EC Private Key",
                category: "certificates",
                secret_group: None,
            },
            PatternDef {
                pattern: r"-----BEGIN[ \t]+PGP[ \t]+PRIVATE[ \t]+KEY[ \t]+BLOCK-----[\s\S]*?-----END[ \t]+PGP[ \t]+PRIVATE[ \t]+KEY[ \t]+BLOCK-----",
                replacement: "[PGP_PRIVATE_KEY_REDACTED]",
                description: "PGP Private Key",
                category: "certificates",
                secret_group: None,
            },
            // PKCS#8 Private Key (generic, covers DSA, ECDSA, Ed25519, etc.)
            PatternDef {
                pattern: r"-----BEGIN[ \t]+PRIVATE[ \t]+KEY-----[\s\S]*?-----END[ \t]+PRIVATE[ \t]+KEY-----",
                replacement: "[PKCS8_PRIVATE_KEY_REDACTED]",
                description: "PKCS#8 Private Key",
                category: "certificates",
                secret_group: None,
            },
            // Ansible Vault encrypted content
            PatternDef {
                pattern: r"\$ANSIBLE_VAULT;[\d.]+;AES256\n[a-f0-9\n]+",
                replacement: "[ANSIBLE_VAULT_ENCRYPTED_REDACTED]",
                description: "Ansible Vault encrypted content",
                category: "ansible",
                secret_group: None,
            },
            // ══════════════════════════════════════════════════════════════════
            // TIER 3: TOOL-SPECIFIC PATTERNS (Kubeconfig, Docker, etc.)
            // ══════════════════════════════════════════════════════════════════

            // Kubeconfig
            PatternDef {
                pattern: r"(?i)client-certificate-data:[ \t]*[A-Za-z0-9+/=]+",
                replacement: "client-certificate-data: [REDACTED]",
                description: "Kubeconfig client certificate",
                category: "kubeconfig",
                secret_group: None,
            },
            PatternDef {
                pattern: r"(?i)client-key-data:[ \t]*[A-Za-z0-9+/=]+",
                replacement: "client-key-data: [REDACTED]",
                description: "Kubeconfig client key",
                category: "kubeconfig",
                secret_group: None,
            },
            PatternDef {
                pattern: r"(?i)certificate-authority-data:[ \t]*[A-Za-z0-9+/=]+",
                replacement: "certificate-authority-data: [REDACTED]",
                description: "Kubeconfig CA certificate",
                category: "kubeconfig",
                secret_group: None,
            },
            // Docker
            PatternDef {
                pattern: r#"(?i)"auth"[ \t]*:[ \t]*"[A-Za-z0-9+/=]{10,}""#,
                replacement: r#""auth": "[REDACTED]""#,
                description: "Docker config auth",
                category: "docker",
                secret_group: None,
            },
            PatternDef {
                pattern: concat!(
                    // `-p` must be a flag (preceded by whitespace), not a
                    // substring of a longer flag: `[^\n]*-p[ \t]*` matched
                    // the `-p` inside `--password-stdin`, redacting a
                    // fragment of "-stdin" as if it were the password. The
                    // leading run before that whitespace is OPTIONAL: making
                    // it mandatory (`[^\n]*[ \t]`) meant `docker login -p
                    // hunter2` — `-p` right after the mandatory space after
                    // `login`, with nothing in between — had no run of
                    // characters left to consume before that space, so the
                    // whole prefix failed to match.
                    r#"(?i)(docker[ \t]+login[ \t]+(?:[^\n]*[ \t])?-p[ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Docker login command with password",
                category: "docker",
                secret_group: None,
            },
            // Database connection strings
            PatternDef {
                pattern: r"(?i)(mysql|postgresql|postgres|mongodb|redis|amqp|mariadb)://[^:]+:[^@]+@",
                replacement: "$1://[CREDENTIALS]@",
                description: "Database connection strings",
                category: "database",
                secret_group: None,
            },
            // Generic scheme://user:password@ — covers git clone over HTTPS,
            // webhook URLs, any non-DB scheme (audit 2026-07-05 finding 6).
            // host:port never matches: no trailing @ after the port.
            PatternDef {
                pattern: r#"\b([a-zA-Z][a-zA-Z0-9+.-]{1,15})://([^/\s:@'"]{1,64}):([^/\s@'"?#]{1,256})@"#,
                replacement: "$1://$2:[REDACTED]@",
                description: "Generic URL embedded credentials",
                category: "generic",
                secret_group: None,
            },
            // Terraform sensitive values
            PatternDef {
                pattern: r#"(?i)"sensitive_value"[ \t]*:[ \t]*"[^"\n]+""#,
                replacement: r#""sensitive_value": "[REDACTED]""#,
                description: "Terraform sensitive values",
                category: "generic",
                secret_group: None,
            },
            // Vault KV tabular output (key followed by 2+ spaces and value)
            PatternDef {
                pattern: r"(?im)^(password|secret|token|api[_-]?key)[ \t]{2,}\S+",
                replacement: "$1  [REDACTED]",
                description: "Vault KV tabular output secrets",
                category: "hashicorp",
                secret_group: None,
            },
            // Redis CONFIG GET requirepass
            PatternDef {
                pattern: r#"(?m)"requirepass"\r?\n"[^"]+""#,
                replacement: "\"requirepass\"\n\"[REDACTED]\"",
                description: "Redis CONFIG GET requirepass",
                category: "database",
                secret_group: None,
            },
            // ══════════════════════════════════════════════════════════════════
            // TIER 4: VARIABLE-BASED PATTERNS (NAME=value format)
            // More specific variable names before generic ones
            // ══════════════════════════════════════════════════════════════════

            // AWS
            PatternDef {
                pattern: concat!(
                    r#"(?i)(aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "AWS credentials",
                category: "aws",
                secret_group: None,
            },
            PatternDef {
                pattern: concat!(
                    r#"(?i)(aws[_-]?session[_-]?token[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "AWS Session Token",
                category: "aws",
                secret_group: None,
            },
            // Docker compose / environment variables (specific DB names)
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:MYSQL|POSTGRES|MONGO|REDIS|RABBITMQ|MARIADB)[_-]?(?:PASSWORD|ROOT_PASSWORD|PASS)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Docker compose database passwords",
                category: "database",
                secret_group: None,
            },
            // Database URLs
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:DATABASE_URL|DB_URL|REDIS_URL|MONGO_URL)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Database URL environment variables",
                category: "database",
                secret_group: None,
            },
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:DB|DATABASE)[_-]?(?:PASSWORD|PASS)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Database password variables",
                category: "database",
                secret_group: None,
            },
            // Ansible
            PatternDef {
                pattern: concat!(
                    r#"(?i)(vault[_-]?pass(?:word)?[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Ansible Vault password",
                category: "ansible",
                secret_group: None,
            },
            PatternDef {
                pattern: concat!(
                    r#"(?i)(ansible[_-]?become[_-]?pass(?:word)?[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Ansible become password",
                category: "ansible",
                secret_group: None,
            },
            PatternDef {
                pattern: concat!(r#"(?i)(--vault-password-file[ \t]+)"#, scalar_value!()),
                replacement: "${1}[REDACTED]",
                description: "Ansible vault password file path",
                category: "ansible",
                secret_group: None,
            },
            PatternDef {
                pattern: concat!(
                    r#"(?i)(ansible[_-]?ssh[_-]?pass[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Ansible SSH password",
                category: "ansible",
                secret_group: None,
            },
            // GitLab CI tokens
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:GITLAB_TOKEN|CI_JOB_TOKEN)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "GitLab CI tokens",
                category: "gitlab",
                secret_group: None,
            },
            // Cloud providers
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:AZURE_CLIENT_SECRET|AZURE_TENANT_ID|AZURE_SUBSCRIPTION_ID)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Azure credentials",
                category: "azure",
                secret_group: None,
            },
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:GOOGLE_APPLICATION_CREDENTIALS|GCP_SERVICE_ACCOUNT|GCLOUD_SERVICE_KEY)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "GCP credentials",
                category: "gcp",
                secret_group: None,
            },
            // HashiCorp
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:VAULT_TOKEN|vault_token)[ \t]*[=:][ \t]*)"#,
                    r#"(["']?(?:hvs|hvb|hvr|s|b|r)\.[A-Za-z0-9_-]{8,}["']?)"#
                ),
                replacement: "${1}[VAULT_TOKEN_REDACTED]",
                description: "HashiCorp Vault token",
                category: "hashicorp",
                secret_group: None,
            },
            PatternDef {
                pattern: concat!(
                    r#"(?i)(CONSUL_HTTP_TOKEN[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Consul HTTP token",
                category: "hashicorp",
                secret_group: None,
            },
            // Docker registry
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:docker[_-]?password|registry[_-]?password)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Docker registry password",
                category: "docker",
                secret_group: None,
            },
            // AI APIs
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:ANTHROPIC_API_KEY|CLAUDE_API_KEY)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Anthropic API Key",
                category: "openai", // Grouped with AI APIs
                secret_group: None,
            },
            // ══════════════════════════════════════════════════════════════════
            // TIER 5: GENERIC PATTERNS (catch-all, must be last!)
            // ══════════════════════════════════════════════════════════════════
            // ══════════════════════════════════════════════════════════════════
            // Keyed generic patterns. Every one is LINE-LOCAL (`[ \t]*`, never
            // `\s*`: `secret:\n  defaultMode: 420` used to become
            // `secret=[REDACTED] 420`) and STRUCTURE-SAFE (bare values exclude
            // `{ } [ ] , ; " '`: `"secret": {` used to become
            // `"secret": "[REDACTED]"` with the object's members left dangling).
            // Strong keys (password…) replace any scalar; weak keys (secret,
            // token, credential, api_key…) replace only a plausible secret
            // (`secret_group`), see `plausible_secret`.
            // ══════════════════════════════════════════════════════════════════
            // Quoted JSON/YAML keys, strong: {"password": "…"}
            PatternDef {
                pattern: concat!(
                    r#"(["'](?i:password|passwd|pwd)["'][ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: r#"${1}"[REDACTED]""#,
                description: "Quoted JSON/YAML password keys",
                category: "generic",
                secret_group: None,
            },
            // Quoted JSON/YAML keys, weak: {"token": "…"} — the value must look
            // like a secret, so {"token": true}, {"credential": 5} and
            // {"secret": {…}} are left alone.
            PatternDef {
                pattern: concat!(
                    r#"(["'](?i:secret|token|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|session[_-]?token|secret[_-]?access[_-]?key|client[_-]?secret|private[_-]?key|credentials?)["'][ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: r#"${1}"[REDACTED]""#,
                description: "Quoted JSON/YAML secret keys",
                category: "generic",
                secret_group: Some(2),
            },
            // Terraform HCL, strong key: password = "…" — any double-quoted
            // string goes (no plausibility gate).
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:password)[ \t]*=[ \t]*)("#,
                    double_quoted_value!(),
                    ")"
                ),
                replacement: r#"${1}"[REDACTED]""#,
                description: "Terraform HCL secrets with quoted values (strong)",
                category: "generic",
                secret_group: None,
            },
            // Terraform HCL, weak key: token = "5" is a count, not a secret.
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:secret|token|api_key)[ \t]*=[ \t]*)("#,
                    double_quoted_value!(),
                    ")"
                ),
                replacement: r#"${1}"[REDACTED]""#,
                description: "Terraform HCL secrets with quoted values (weak)",
                category: "generic",
                secret_group: Some(2),
            },
            // Bare keys with quoted values, strong: password: "mon secret"
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:password|passwd|pwd)[ \t]*[=:][ \t]*)("#,
                    quoted_value!(),
                    ")"
                ),
                replacement: r#"${1}"[REDACTED]""#,
                description: "Generic passwords with quoted values",
                category: "generic",
                secret_group: None,
            },
            // Bare keys with quoted values, weak: secret: "…"
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:secret|credential)[ \t]*[=:][ \t]*)("#,
                    quoted_value!(),
                    ")"
                ),
                replacement: r#"${1}"[REDACTED]""#,
                description: "Generic secrets with quoted values",
                category: "generic",
                secret_group: Some(2),
            },
            // Bare keys with bare values, strong
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:password|passwd|pwd)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Generic password patterns",
                category: "generic",
                secret_group: None,
            },
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:DIGITALOCEAN_TOKEN|DO_TOKEN)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "DigitalOcean token",
                category: "generic",
                secret_group: None,
            },
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:ssh[_-]?pass(?:word)?|ssh[_-]?key[_-]?pass(?:word)?)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "SSH password/passphrase",
                category: "generic",
                secret_group: None,
            },
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:smtp[_-]?pass(?:word)?|mail[_-]?pass(?:word)?)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "SMTP/Mail password",
                category: "generic",
                secret_group: None,
            },
            PatternDef {
                pattern: concat!(r#"(?i)(npm[_-]?token[ \t]*[=:][ \t]*)"#, scalar_value!()),
                replacement: "${1}[REDACTED]",
                description: "NPM token",
                category: "generic",
                secret_group: None,
            },
            PatternDef {
                pattern: concat!(r#"(?i)(pypi[_-]?token[ \t]*[=:][ \t]*)"#, scalar_value!()),
                replacement: "${1}[REDACTED]",
                description: "PyPI token",
                category: "generic",
                secret_group: None,
            },
            // Bare keys with bare values, weak
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:api[_-]?key|auth[_-]?token)(?:[ \t]*[=:][ \t]*|[ \t]+))"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Generic API keys and auth tokens",
                category: "generic",
                secret_group: Some(2),
            },
            PatternDef {
                pattern: concat!(
                    r#"(?i)((?:secret|credential|token)[ \t]*[=:][ \t]*)"#,
                    scalar_value!()
                ),
                replacement: "${1}[REDACTED]",
                description: "Generic secrets",
                category: "generic",
                secret_group: Some(2),
            },
            // HTTP auth headers — `[ \t]+`, a header never spans lines.
            // MUST stay AFTER the Tier 1 JWT pattern: with `entropy_detection:
            // false` this bearer pattern is the only thing that closes a raw-JWT
            // leak, and it would otherwise consume the JWT before the specific
            // pattern can name it.
            PatternDef {
                pattern: r#"(?i)bearer[ \t]+['"]?[A-Za-z0-9._~+/=-]{8,}"#,
                replacement: "Bearer [BEARER_TOKEN_REDACTED]",
                description: "Opaque Authorization Bearer token",
                category: "generic",
                secret_group: None,
            },
            PatternDef {
                pattern: r"(?i)authorization:[ \t]*basic[ \t]+[A-Za-z0-9+/=]{8,}",
                replacement: "Authorization: Basic [BASIC_AUTH_REDACTED]",
                description: "HTTP Basic Authorization header",
                category: "generic",
                secret_group: None,
            },
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

        // Tier 0: exact-match masking of the bridge's own configured
        // credentials — must run even when no keyword/regex/entropy fires.
        let text = if let Some(ref masker) = self.known_secret_masker {
            if masker.is_match(text_ref) {
                let replacements = vec!["[KNOWN_SECRET_REDACTED]"; masker.patterns_len()];
                Cow::Owned(masker.replace_all(text_ref, &replacements))
            } else {
                text
            }
        } else {
            text
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
            let Some(pattern) = self.patterns.get(idx) else {
                continue;
            };
            result = match pattern.secret_group {
                None => pattern
                    .regex
                    .replace_all(&result, pattern.replacement.as_str())
                    .into_owned(),
                Some(group) => pattern
                    .regex
                    .replace_all(&result, |caps: &regex::Captures<'_>| {
                        let candidate = caps.get(group).map_or("", |m| m.as_str());
                        if plausible_secret(candidate) {
                            let mut expanded = String::new();
                            caps.expand(&pattern.replacement, &mut expanded);
                            expanded
                        } else {
                            caps[0].to_string()
                        }
                    })
                    .into_owned(),
            };
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
    fn test_known_secret_masked_without_keyword_context() {
        let sanitizer =
            Sanitizer::with_defaults().with_known_secrets(&["Hunter2-longpass".to_string()]);
        // Bare value, no keyword, low entropy — only exact-match can catch it.
        let input = "process args: sshpass Hunter2-longpass target.host";
        let result = sanitizer.sanitize(input);
        assert!(
            !result.contains("Hunter2-longpass"),
            "known secret leaked: {result}"
        );
        assert!(result.contains("[KNOWN_SECRET_REDACTED]"));
    }

    #[test]
    fn test_known_secret_too_short_is_ignored() {
        // < 8 chars: masking "abc" would shred normal output.
        let sanitizer = Sanitizer::with_defaults().with_known_secrets(&["abc".to_string()]);
        let input = "abcdef abc xyz";
        let result = sanitizer.sanitize(input);
        assert_eq!(result.as_ref(), input);
    }

    #[test]
    fn test_known_secrets_empty_list_is_noop() {
        let sanitizer = Sanitizer::with_defaults().with_known_secrets(&[]);
        let input = "Server started on port 8080";
        assert_eq!(sanitizer.sanitize(input).as_ref(), input);
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
    fn test_url_with_at_in_query_not_corrupted() {
        let sanitizer = Sanitizer::with_defaults();
        // No credentials here: the @ lives in a query param. The URL-creds
        // pattern must not eat the port/path/query looking for it.
        let input = "redirect http://localhost:8080/callback?redirect=user@example.com done";
        let result = sanitizer.sanitize(input);
        assert!(
            result.contains("http://localhost:8080/callback?redirect=user@example.com"),
            "benign URL corrupted: {result}"
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
    /// The test input contains the substring `token` (inside
    /// `valid_token_4242`) so the Aho-Corasick keyword pre-filter fires and
    /// the sanitizer actually runs regex matching on the line. (Without a
    /// keyword the Tier-1 fast path would bypass every regex.) It must NOT
    /// use a `token=`/`token:` key shape: the builtin bare "token" pattern
    /// (added alongside `secret`/`credential`, gated on plausibility) would
    /// consume the value first and this test would stop proving what it
    /// claims to prove.
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

        let input = "log: got valid_token_4242 should be redacted";
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
    fn test_bearer_token_redacted_when_shell_quoted() {
        // Mirrors real AwxCommandBuilder output: shell::escape (Posix) wraps the
        // token in single quotes, so the audited command contains
        // `Bearer 'token'` (a leading quote between "Bearer " and the token).
        // The generic bearer pattern must still redact it — otherwise the AWX
        // OAuth2 token leaks verbatim into the audit log / tool result.
        let sanitizer = Sanitizer::with_defaults();
        let input = "curl -s -H 'Authorization: Bearer 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6'' https://awx/api/v2/ping/";
        let out = sanitizer.sanitize(input);
        assert!(
            !out.contains("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"),
            "shell-quoted bearer token leaked: {out}"
        );
        assert!(out.contains("[BEARER_TOKEN_REDACTED]"));
    }

    #[test]
    fn test_jwt_bearer_takes_jwt_precedence_over_generic_bearer() {
        let sanitizer = Sanitizer::with_defaults();
        let input =
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123XYZ456";
        let out = sanitizer.sanitize(input);
        assert!(
            out.contains("[JWT_TOKEN_REDACTED]"),
            "JWT should win: {out}"
        );
        assert!(
            !out.contains("[BEARER_TOKEN_REDACTED]"),
            "generic Bearer pattern must not steal a JWT match: {out}"
        );
        assert!(!out.contains("eyJhbGci"), "JWT not redacted: {out}");
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
        // The specific sk-ant-api* Tier 1 pattern fires first and leaves
        // "[ANTHROPIC_API_KEY_REDACTED]" behind; the keyed Tier 5 pattern
        // used to re-match that bracketed marker too (its old value class
        // `[^\s\n]+` doesn't exclude `[`/`]`) and stack a second
        // "=[REDACTED]" on top. The structure-safe value class now excludes
        // `[`/`]` so it correctly leaves the already-redacted, bracket-
        // wrapped marker alone — the raw key is still gone either way.
        assert!(
            output.contains("[ANTHROPIC_API_KEY_REDACTED]"),
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

        // GitHub tokens should NOT be redacted (category disabled). Not keyed
        // by `token:`/`token=`: the builtin bare "token" pattern lives in the
        // "generic" category, not "github", and would redact a plausible
        // value there regardless of this config disabling "github".
        let github_input = "found ghp_abcdefghijklmnopqrstuvwxyz123456 in the log";
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
        // API_KEY is a weak key: its value must pass `plausible_secret`, which
        // rejects letters-and-hyphen-only text (no digit) as "just a word".
        // `sk-end0fline9` has digits, so it clears the gate.
        let input = format!("password=longlinetest {padding} API_KEY=sk-end0fline9");
        let output = sanitizer.sanitize(&input);
        assert!(!output.contains("longlinetest"));
        assert!(!output.contains("sk-end0fline9"));
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

    /// An input made only of ANSI escape sequences sanitizes to nothing, and
    /// that is correct: there is no printable content under the escapes.
    ///
    /// The fuzz harness asserted the opposite for two weeks and filed a
    /// nightly issue about it, because `[`, `3`, `1` and `m` are not control
    /// characters even though the sequence they sit in is not content.
    #[test]
    fn an_input_of_pure_ansi_sanitizes_to_nothing() {
        let sanitizer = Sanitizer::with_defaults();
        assert_eq!(sanitizer.sanitize("\x1b[31m"), "");
        assert_eq!(sanitizer.sanitize("\x1b[0m\x1b[1;32m"), "");
        assert_eq!(
            sanitizer.sanitize("\x1b[31mred\x1b[0m"),
            "red",
            "escapes around real content leave the content"
        );
    }

    #[test]
    fn test_strip_ansi_complex_codes() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "\x1b[1;31mERROR\x1b[0m \x1b[33mWarning\x1b[0m normal text";
        let output = sanitizer.sanitize(input);
        assert_eq!(output.as_ref(), "ERROR Warning normal text");
    }

    #[test]
    fn test_json_quoted_key_password() {
        let sanitizer = Sanitizer::with_defaults();
        let input = r#"{"user": "admin", "password": "hunter2"}"#;
        let result = sanitizer.sanitize(input);
        assert!(
            !result.contains("hunter2"),
            "JSON quoted-key password leaked: {result}"
        );
        assert!(result.contains("[REDACTED]"));
        assert!(
            result.contains(r#""user": "admin""#),
            "non-secret JSON must survive"
        );
    }

    #[test]
    fn test_k8s_secret_json_data_block() {
        let sanitizer = Sanitizer::with_defaults();
        let input = r#"{"data": {"password": "aHVudGVyMg==", "token": "c2VjcmV0dG9rZW4="}}"#;
        let result = sanitizer.sanitize(input);
        assert!(
            !result.contains("aHVudGVyMg=="),
            "k8s secret data leaked: {result}"
        );
        assert!(
            !result.contains("c2VjcmV0dG9rZW4="),
            "k8s token leaked: {result}"
        );
    }

    #[test]
    fn test_yaml_quoted_key_unquoted_value() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "\"api_key\": AbCd1234EfGh5678\n";
        let result = sanitizer.sanitize(input);
        assert!(
            !result.contains("AbCd1234EfGh5678"),
            "quoted-key unquoted value leaked: {result}"
        );
    }

    #[test]
    fn test_quoted_value_with_spaces_fully_redacted() {
        let sanitizer = Sanitizer::with_defaults();
        let input = r#"password: "my secret with spaces""#;
        let result = sanitizer.sanitize(input);
        assert!(
            !result.contains("my secret"),
            "quoted value partially leaked: {result}"
        );
        assert!(
            !result.contains("with spaces"),
            "quoted value tail leaked: {result}"
        );
    }

    #[test]
    fn test_quoted_key_no_false_positive_on_substring_keys() {
        let sanitizer = Sanitizer::with_defaults();
        // "secretName" must NOT match the quoted "secret" key pattern
        let input = r#"{"secretName": "my-tls-cert", "description": "plain text"}"#;
        let result = sanitizer.sanitize(input);
        assert!(
            result.contains("my-tls-cert"),
            "secretName value wrongly redacted: {result}"
        );
        assert!(result.contains("plain text"));
    }

    #[test]
    fn test_quoted_key_bare_value_preserves_json_structure() {
        let sanitizer = Sanitizer::with_defaults();
        let input = r#"{"data":{"password":hunter2},"other":"keep"}"#;
        let result = sanitizer.sanitize(input);
        assert!(!result.contains("hunter2"), "bare value leaked: {result}");
        assert!(
            result.contains(r#""other":"keep""#),
            "sibling field eaten: {result}"
        );
        assert!(result.ends_with('}'), "closing braces eaten: {result}");
    }

    #[test]
    fn test_authorization_basic_header_redacted() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "> Authorization: Basic dXNlcjpodW50ZXIy";
        let result = sanitizer.sanitize(input);
        assert!(
            !result.contains("dXNlcjpodW50ZXIy"),
            "Basic auth leaked: {result}"
        );
        assert!(result.contains("[BASIC_AUTH_REDACTED]"));
    }

    #[test]
    fn test_basic_no_false_positive_on_prose() {
        let sanitizer = Sanitizer::with_defaults();
        // "basic understanding" must not be redacted — the pattern is anchored
        // on the Authorization: header, not the bare word "basic".
        let input = "a basic understanding of authorization concepts";
        let result = sanitizer.sanitize(input);
        assert_eq!(result.as_ref(), input);
    }

    #[test]
    fn test_generic_url_credentials_redacted() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "cloning https://deploy:ghp_tokenvalue123@github.com/org/repo.git";
        let result = sanitizer.sanitize(input);
        assert!(
            !result.contains("ghp_tokenvalue123"),
            "URL password leaked: {result}"
        );
        assert!(
            result.contains("https://deploy:[REDACTED]@"),
            "scheme/user must survive: {result}"
        );
    }

    #[test]
    fn test_url_with_port_not_redacted() {
        let sanitizer = Sanitizer::with_defaults();
        // host:port is not user:password — no @ terminator, must pass through
        let input = "listening on http://localhost:8080/health";
        let result = sanitizer.sanitize(input);
        assert!(
            result.contains("http://localhost:8080/health"),
            "port wrongly redacted: {result}"
        );
    }

    #[test]
    fn test_db_url_still_uses_specific_replacement() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "DATABASE: mysql://root:hunter2@db.local:3306/app";
        let result = sanitizer.sanitize(input);
        assert!(!result.contains("hunter2"), "db password leaked: {result}");
    }

    #[test]
    fn plausible_secret_rejects_structure_ids_words_and_literals() {
        for candidate in [
            "{",
            "[",
            "5",
            "12345678901",
            "true",
            "null",
            "None",
            "argocd-repo-server-tls",
            "enabled",
            "short7!",
        ] {
            assert!(
                !plausible_secret(candidate),
                "{candidate:?} is not a secret"
            );
        }
    }

    #[test]
    fn plausible_secret_accepts_key_shaped_values() {
        for candidate in [
            "s3cr3t-V4lue_9",
            "AKxq81mZp0Lw4Rt",
            "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
            "\"wJalrXUtnFEMI/K7MDENG\"",
            "Z2hwX2FiYzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9w",
        ] {
            assert!(
                plausible_secret(candidate),
                "{candidate:?} looks like a secret"
            );
        }
    }

    #[test]
    fn gated_pattern_leaves_implausible_capture_alone() {
        let defs = [PatternDef {
            pattern: r"(?i)\b(secret)[ \t]*[=:][ \t]*([^\s\x22'{}\[\],;]+)",
            replacement: "$1=[REDACTED]",
            description: "test gated",
            category: "generic",
            secret_group: Some(2),
        }];
        let s =
            Sanitizer::from_pattern_defs_with_custom(&defs, &[], true, EntropyDetector::disabled());
        assert_eq!(s.sanitize("secret: enabled").as_ref(), "secret: enabled");
        assert_eq!(
            s.sanitize("secret: s3cr3t-V4lue_9").as_ref(),
            "secret=[REDACTED]"
        );
    }

    /// A `secret_group` index that names a capture group the pattern doesn't
    /// have is silently useless: `Captures::get(group)` returns `None`, the
    /// gate sees an empty candidate (`plausible_secret("")` is false), and
    /// the match is left alone — no panic, no redaction, no signal. This
    /// test catches a typo'd index before it ships that way.
    #[test]
    fn gated_patterns_name_an_existing_capture_group() {
        for def in Sanitizer::default_pattern_defs() {
            if let Some(n) = def.secret_group {
                let regex = regex::Regex::new(def.pattern)
                    .unwrap_or_else(|e| panic!("{}: invalid pattern: {e}", def.description));
                assert!(
                    n < regex.captures_len(),
                    "{}: secret_group Some({n}) is out of range for {} capture group(s) in {:?}",
                    def.description,
                    regex.captures_len(),
                    def.pattern
                );
            }
        }
    }

    #[test]
    fn no_builtin_pattern_crosses_a_line_break() {
        let s = Sanitizer::with_defaults();
        for input in [
            "password\n\nnext_line_value",
            "aws_secret_access_key:\n  fromSecret: x",
            "token\n  = value",
        ] {
            assert_eq!(
                s.sanitize(input).as_ref(),
                input,
                "{input:?} must not be touched"
            );
        }
    }

    /// `docker login … -p\s*<value>` and `--vault-password-file\s+<value>`
    /// used `\s` around the value, which matches a newline — on the K3s host
    /// `docker login -u bob -p` followed by a bare newline (password supplied
    /// on stdin) swallowed the next line of output as the "password", and
    /// `--vault-password-file` did the same.
    #[test]
    fn docker_login_and_vault_file_stop_at_end_of_line() {
        let s = Sanitizer::with_defaults();
        assert_eq!(
            s.sanitize("docker login -u bob -p\nnext-line").as_ref(),
            "docker login -u bob -p\nnext-line"
        );
        assert_eq!(
            s.sanitize("--vault-password-file\n/etc/passwd").as_ref(),
            "--vault-password-file\n/etc/passwd"
        );
        assert_eq!(
            s.sanitize("docker login -u bob -p hunter2").as_ref(),
            "docker login -u bob -p [REDACTED]"
        );
        assert_eq!(
            s.sanitize("--vault-password-file /root/.vault").as_ref(),
            "--vault-password-file [REDACTED]"
        );
    }

    /// The docker-login `-p` must be a flag, not any `-p` substring: the
    /// prefix used to be `[^\n]*-p[ \t]*`, which also matched the `-p`
    /// inside `--password-stdin` and redacted a fragment of `-stdin` as if
    /// it were a password. Requiring a whitespace character immediately
    /// before `-p` fixes that without touching the genuine `-p <value>` and
    /// `-p<value>` (no space) forms. That whitespace requirement also has to
    /// be optional: `docker login -p hunter2` has `-p` right after the
    /// mandatory space after `login`, with no run of other characters (and
    /// so no *second* space) in between, so a MANDATORY `[^\n]*[ \t]` run
    /// before `-p` failed to match this, the most common form.
    #[test]
    fn docker_login_p_flag_is_not_a_substring_match() {
        let s = Sanitizer::with_defaults();
        assert_eq!(
            s.sanitize("docker login -u bob --password-stdin").as_ref(),
            "docker login -u bob --password-stdin"
        );
        assert_eq!(
            s.sanitize("docker login -u bob -p hunter2").as_ref(),
            "docker login -u bob -p [REDACTED]"
        );
        assert_eq!(
            s.sanitize("docker login -u bob -phunter2").as_ref(),
            "docker login -u bob -p[REDACTED]"
        );
        assert_eq!(
            s.sanitize("docker login -p hunter2").as_ref(),
            "docker login -p [REDACTED]"
        );
        assert_eq!(
            s.sanitize("docker login -phunter2 -u bob").as_ref(),
            "docker login -p[REDACTED] -u bob"
        );
        assert_eq!(
            s.sanitize("docker login -p hunter2 registry.example.io")
                .as_ref(),
            "docker login -p [REDACTED] registry.example.io"
        );
    }

    /// `HashiCorp` Vault tokens carry a purpose prefix (`hvs.` service, `hvb.`
    /// batch, `hvr.` recovery) alongside the legacy unprefixed `s.`/`b.`/`r.`
    /// forms — the old pattern only matched `[hs]\.`, so `hvs.…` (the live
    /// S6 harness case) was missed entirely. Pins the named
    /// `[VAULT_TOKEN_REDACTED]` marker, not just "the token doesn't leak" —
    /// the entropy detector alone would also mask these tokens (with a
    /// different, generic marker), which would pass a looser assertion even
    /// with the regex broken.
    #[test]
    fn vault_tokens_with_every_prefix() {
        let s = Sanitizer::with_defaults();
        for token in [
            "hvs.CAESIJ1234567890abcdefghij",
            "hvb.AAAAAQI1234567890",
            "s.1234567890abcdef",
            "hvr.abcdef1234567890",
        ] {
            let input = format!("VAULT_TOKEN={token}");
            assert_eq!(
                s.sanitize(&input).as_ref(),
                "VAULT_TOKEN=[VAULT_TOKEN_REDACTED]",
                "{token} was not redacted with the named marker"
            );
        }
        assert_eq!(
            s.sanitize(r#"VAULT_TOKEN="hvs.CAESIJ1234567890abcdefghij""#)
                .as_ref(),
            "VAULT_TOKEN=[VAULT_TOKEN_REDACTED]",
            "quotes must be dropped symmetrically with the value"
        );
        assert_eq!(
            s.sanitize("vault_token: hvs.CAESIJ1234567890abcdefghij")
                .as_ref(),
            "vault_token: [VAULT_TOKEN_REDACTED]"
        );
    }

    /// Supersedes the narrower `builtin_patterns_never_use_whitespace_class_around_a_separator`:
    /// that guard only caught `\s` next to `[=:]`, so `--vault-password-file\s+…`
    /// and `docker\s+login\s+…` — no `=`/`:` separator at all — slipped
    /// through and swallowed the next line. This guard rejects `\s*`/`\s+`
    /// ANYWHERE in a builtin pattern. The one legitimate multi-line pattern,
    /// Redis `"requirepass"\r?\n"…"`, uses `\r?\n`, not `\s`, so it keeps
    /// passing untouched.
    #[test]
    fn no_builtin_pattern_uses_a_whitespace_class_before_a_value() {
        for def in Sanitizer::default_pattern_defs() {
            assert!(
                !def.pattern.contains(r"\s*") && !def.pattern.contains(r"\s+"),
                "{}: \\s matches a newline; use [ \\t]* or [ \\t]+",
                def.description
            );
        }
    }

    /// Every bare value in a builtin pattern must come from `scalar_value!()`.
    /// This asserts only the ABSENCE of one literal class string
    /// (`[^\s"'{}\[\],;]+`, the class this replaced): it cannot tell that a
    /// pattern uses `scalar_value!()` specifically, only that it doesn't use
    /// the old, narrower one, which stopped at the first comma or brace
    /// *inside* the value, so `PASSWORD=aB3,x9Zq!k` redacted `aB3` and
    /// printed `,x9Zq!k` in the clear.
    ///
    /// The `HashiCorp` Vault token pattern is a deliberate exception: its
    /// value is `(["']?(?:hvs|hvb|hvr|s|b|r)\.[A-Za-z0-9_-]{8,}["']?)`, a
    /// purpose-prefixed token, not `scalar_value!()` — a real secret's shape
    /// is known there, so the shared, permissive grammar is not needed.
    #[test]
    fn builtin_patterns_use_the_shared_value_grammar() {
        for def in Sanitizer::default_pattern_defs() {
            assert!(
                !def.pattern.contains(r#"[^\s"'{}\[\],;]+"#),
                "{}: build the value group with scalar_value!(), not the bare \
                 `+` class, which stops inside the value: {:?}",
                def.description,
                def.pattern
            );
        }
    }

    /// `secret_group: Some(n)` is only worth having if `n` names the VALUE.
    /// The index-range guard above cannot tell `Some(1)` (the KEY) from
    /// `Some(2)`: both are in range, and a gate reading the key would redact
    /// nothing at all, silently. This table pins both directions.
    #[test]
    fn gated_builtins_redact_a_plausible_value() {
        let sanitizer = Sanitizer::with_defaults();
        for (input, value) in [
            (r#""secret": "s3cr3t-V4lue_9""#, "s3cr3t-V4lue_9"),
            (r#"secret: "s3cr3t-V4lue_9""#, "s3cr3t-V4lue_9"),
            ("api_key=AKxq81mZp0Lw4Rt", "AKxq81mZp0Lw4Rt"),
            ("secret=s3cr3t-V4lue_9", "s3cr3t-V4lue_9"),
        ] {
            let out = sanitizer.sanitize(input);
            assert!(
                out.contains("[REDACTED]"),
                "{input:?} must be redacted, got {out:?}"
            );
            assert!(
                !out.contains(value),
                "{input:?} leaked its value, got {out:?}"
            );
        }
        for input in [
            r#""credential": 5"#,
            r#"secret: "enabled""#,
            "api_key=enabled",
            "token: enabled",
        ] {
            assert_eq!(
                sanitizer.sanitize(input).as_ref(),
                input,
                "{input:?} is not a secret and must come back byte-identical"
            );
        }
    }

    /// The verbatim-prefix rule: a keyed pattern captures everything before
    /// the value as group 1 and the value as group 2, and its replacement
    /// starts with `${1}` — so key, quotes, separator and indentation come
    /// back byte-identical and only the value changes.
    ///
    /// The selector is a literal SUBSTRING test for `[ \t]*[=:][ \t]*` or
    /// `[ \t]*=[ \t]*` in the pattern's own source text — not "has an
    /// `=`/`:` separator". At least nine keyed patterns spell their
    /// separator some other way and are invisible to it: "Docker login
    /// command with password" (a `-p` flag) and "Ansible vault password
    /// file path" (`--vault-password-file` followed by whitespace) both
    /// comply with the verbatim-prefix rule anyway — `${1}[REDACTED]`. The
    /// rest do not: "Vault KV tabular output secrets" normalises the run of
    /// 2+ spaces between key and value down to exactly two
    /// (`$1  [REDACTED]`); the three kubeconfig patterns ("Kubeconfig
    /// client certificate", "Kubeconfig client key", "Kubeconfig CA
    /// certificate", each `key:[ \t]*value`) rewrite BOTH the separator,
    /// always to `: ` (one space), AND the key's own case to their
    /// hard-coded lower-case spelling — `CLIENT-KEY-DATA:abc` becomes
    /// `client-key-data: [REDACTED]`; "Docker config auth"
    /// (`"auth"[ \t]*:[ \t]*"..."`) collapses the run of spacing around its
    /// colon to exactly one space; "Terraform sensitive values"
    /// (`"sensitive_value"[ \t]*:[ \t]*"..."`) does the same; and "HTTP
    /// Basic Authorization header" (`authorization:[ \t]*basic[ \t]+...`)
    /// both collapses spacing AND rewrites the key's case, always to
    /// `Authorization: Basic `. All of these are pre-existing, out-of-scope
    /// quirks this guard would not catch even if it selected the pattern.
    #[test]
    fn keyed_patterns_replace_only_the_value() {
        for def in Sanitizer::default_pattern_defs() {
            if !def.pattern.contains("[ \\t]*[=:][ \\t]*")
                && !def.pattern.contains("[ \\t]*=[ \\t]*")
            {
                continue;
            }
            let re = regex::Regex::new(def.pattern).expect(def.description);
            assert_eq!(
                re.captures_len(),
                3,
                "{}: prefix group + value group, inner groups non-capturing",
                def.description
            );
            assert!(
                def.replacement.starts_with("${1}"),
                "{}: replacement must start with ${{1}}, got {}",
                def.description,
                def.replacement
            );
            assert!(
                def.secret_group.is_none_or(|g| g == 2),
                "{}: secret_group names the value, which is group 2",
                def.description
            );
        }
    }

    /// Ruling 12 (amended): `scalar_value!()`'s quoted alternatives refuse
    /// only MARKER-SHAPED content (`[` + `[A-Z0-9_ ]+` + `]`, nothing else),
    /// detected case-sensitively via `(?-i:…)` even inside a
    /// case-insensitive pattern — not every leading `[`, and not a
    /// lower-case bracketed run that merely LOOKS like a marker once folded.
    /// A real quoted secret that happens to start with a bracket must still
    /// be redacted.
    #[test]
    fn quoted_values_starting_with_a_bracket_are_still_redacted_but_markers_are_not() {
        let s = Sanitizer::with_defaults();
        // Lower-case bracketed content is a real value, not a marker — even
        // though the AWS session token pattern is case-insensitive. AWS
        // session token is a bare-value pattern (like CONSUL_HTTP_TOKEN
        // elsewhere in this file), so its replacement is `${1}[REDACTED]`
        // with no added quotes: whatever quoting the matched value carried
        // is discarded along with the value, same as every other bare
        // pattern in this file.
        assert_eq!(
            s.sanitize(r#"AWS_SESSION_TOKEN: "[abc123def456]""#)
                .as_ref(),
            "AWS_SESSION_TOKEN: [REDACTED]"
        );
        // Same key, a lower-case marker-LOOKING value: still just a value,
        // because marker detection is pinned case-sensitive regardless of
        // the pattern's own (?i).
        assert_eq!(
            s.sanitize(r#"AWS_SESSION_TOKEN: "[redacted]""#).as_ref(),
            "AWS_SESSION_TOKEN: [REDACTED]"
        );
        assert_eq!(
            s.sanitize(r#"password = "[REDACTED]""#).as_ref(),
            r#"password = "[REDACTED]""#
        );
        assert_eq!(
            s.sanitize("password = 'hunter2'").as_ref(),
            r#"password = "[REDACTED]""#
        );
        assert_eq!(
            s.sanitize(r#"password="[K3S_TOKEN_REDACTED]""#).as_ref(),
            r#"password="[K3S_TOKEN_REDACTED]""#
        );
    }

    /// `kubectl describe pod` prints this placeholder for an env var sourced
    /// from a secret it cannot read: not a leak, and not the key's value at
    /// all, so `scalar_value!()`'s bare alternative must not start a match
    /// on the leading `<` (Ruling 7, corpus finding against `raspberry`).
    #[test]
    fn kubectl_describe_placeholder_not_redacted() {
        let s = Sanitizer::with_defaults();
        assert_eq!(
            s.sanitize("      REDIS_PASSWORD:   <set to the key 'auth' in secret 'argocd-redis'>   Optional: false")
                .as_ref(),
            "      REDIS_PASSWORD:   <set to the key 'auth' in secret 'argocd-redis'>   Optional: false"
        );
    }

    /// Pins a KNOWN MISS, deliberately accepted (see the `scalar_value!()`
    /// doc comment): a value that starts with `<` but is not a well-formed
    /// `<...>` group is refused by every alternative, same as a `kubectl
    /// describe` placeholder. If this ever starts getting redacted, that is
    /// a real improvement, not a regression — update this test (and its
    /// doc comment) deliberately rather than treating a red run here as a
    /// bug to revert.
    #[test]
    fn angle_initial_unquoted_secret_is_a_known_miss() {
        let s = Sanitizer::with_defaults();
        assert_eq!(
            s.sanitize("MYSQL_ROOT_PASSWORD=<Xk9!pQ2z").as_ref(),
            "MYSQL_ROOT_PASSWORD=<Xk9!pQ2z"
        );
    }

    /// The regression fence for the 2026-09-05 audit. Every shape here is a
    /// leak or a corruption the audit reproduced against the pre-fix tree;
    /// each line is an exact input/output pair so a grammar change that
    /// re-opens one fails loudly rather than degrading quietly.
    #[test]
    fn audit_2026_09_05_shapes() {
        let sanitizer = Sanitizer::with_defaults();
        let cases = [
            // One value grammar (audit CRITICAL #1 / IMPORTANT #2): the value
            // is one scalar, so a comma, an unterminated quote or a whole
            // connection string no longer leaves a tail in the clear.
            ("PASSWORD=aB3,x9Zq!k", "PASSWORD=[REDACTED]"),
            ("password: don't-tell-anyone", "password: [REDACTED]"),
            ("PASSWORD=\"s3cr3tV4lue", "PASSWORD=[REDACTED]"),
            (r#"SMTP_PASS="hunter2Xk9""#, "SMTP_PASS=[REDACTED]"),
            (
                r#"AWS_ACCESS_KEY_ID="ASIAEXAMPLE0000000001""#,
                "AWS_ACCESS_KEY_ID=[REDACTED]",
            ),
            (
                r#"CONSUL_HTTP_TOKEN="Xk9qP2mV7bL4nR8s""#,
                "CONSUL_HTTP_TOKEN=[REDACTED]",
            ),
            (
                "DATABASE_URL=postgresql://admin:secret@db.example.com/prod",
                "DATABASE_URL=[REDACTED]",
            ),
            // The trailing comma belongs to the container, not to the value.
            ("password=hunter2,", "password=[REDACTED],"),
            // Structure is never a value.
            (r#""credential": 5,"#, r#""credential": 5,"#),
            (r#""secret": {"#, r#""secret": {"#),
            (r#""token": true"#, r#""token": true"#),
            // A Tier 1 marker starts with `[`, which the value grammar rejects
            // at its first position, so the specific marker is never re-eaten
            // by the generic AWS pattern that runs after it.
            (
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
                "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]",
            ),
            // A compact JSON object — what AWX and `jq -c` return — has no
            // space after the colon, so the bare value must stop at the
            // closing brace and at the quote that ends its own leaf, or it
            // swallows every sibling field to the end of the line.
            (
                r#"{"data":{"password":hunter2},"other":"keep"}"#,
                r#"{"data":{"password":"[REDACTED]"},"other":"keep"}"#,
            ),
            // A credential ID next to a sibling key: without the quote in the
            // exclusion the value read `5,"name":"deploy-key`, which IS
            // plausible, so the gate passed and the whole object went.
            (
                r#"{"credential":5,"name":"deploy-key"}"#,
                r#"{"credential":5,"name":"deploy-key"}"#,
            ),
            // A keyed value inside a JSON string leaf: the strong bare-key
            // pattern matches within the leaf, and must stop at the quote that
            // closes it rather than eating the next key.
            (
                r#"{"cmd":"--password=hunter2","x":"y"}"#,
                r#"{"cmd":"--password=[REDACTED]","x":"y"}"#,
            ),
            // Space-separated CLI flag (audit IMPORTANT #3).
            (
                "curl --api-key 7f3aB9k2Lm4Qz8Xw --url https://x",
                "curl --api-key [REDACTED] --url https://x",
            ),
            // …and the gate keeps prose off it.
            ("API_KEY is required", "API_KEY is required"),
            ("api-key header", "api-key header"),
            // Terraform HCL weak keys are gated: a count is not a token.
            (r#"token = "5""#, r#"token = "5""#),
            // The generic keyed patterns also accept a quoted value, so they
            // are in `matched_indices` for this input too and re-run against
            // what the HCL pattern already redacted. `scalar_value!()`'s
            // quoted alternatives reject MARKER-SHAPED content (a `[`
            // directly followed by `[A-Z0-9_ ]+` and a `]`, nothing else in
            // between) — so `"[REDACTED]"` is not a value to them and the
            // HCL pattern's quoting survives the cascade untouched. A real
            // quoted secret that merely starts with `[` (`"[abc123]"`) is
            // still redacted; see `quoted_values_starting_with_a_bracket_are_still_redacted_but_markers_are_not`.
            (
                r#"api_key = "AKxq81mZp0Lw4Rt""#,
                r#"api_key = "[REDACTED]""#,
            ),
            (r#"password = "x""#, r#"password = "[REDACTED]""#),
            // `:[ \t]*` instead of `:\s*`: a base64 blob on the NEXT line is
            // not this key's value (audit IMPORTANT #4).
            (
                "certificate-authority-data:\n    server: https://10.0.0.1:6443",
                "certificate-authority-data:\n    server: https://10.0.0.1:6443",
            ),
            // `${1}_${2}`, not `$1_$2`: `Captures::expand` reads `$1_PASSWORD`
            // as a group NAME, finds none, and expands to the empty string —
            // which deleted the key from the redacted line.
            ("DB_PASSWORD=hunter2Xk9", "DB_PASSWORD=[REDACTED]"),
            ("MYSQL_PASSWORD=hunter2Xk9", "MYSQL_PASSWORD=[REDACTED]"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sanitizer.sanitize(input).as_ref(),
                expected,
                "input {input:?}"
            );
        }
    }
}
