//! Configuration file watcher for hot-reload support
//!
//! Watches the configuration file and reloads it when changes are detected.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Minimum interval between reloads to avoid processing duplicate events
/// from editors that generate multiple filesystem events per save.
const DEBOUNCE_DURATION: Duration = Duration::from_millis(500);

use super::{Config, load_config};
use crate::security::CommandValidator;

/// Decide whether a filesystem event must trigger a config reload.
///
/// Functional core of the watcher: the notify callback passes the current
/// instant explicitly, so kind/path filtering and the debounce window are
/// unit-testable without a real filesystem or clock. On acceptance the
/// debounce timestamp is updated.
fn should_process_event(
    event: &Event,
    config_path: &Path,
    last_reload: &Mutex<Instant>,
    now: Instant,
) -> bool {
    // Accept both Modify and Create events to handle atomic saves
    // (vim/nano/VSCode write a temp file then rename it over the original,
    // which produces Create rather than Modify).
    let relevant_kind = event.kind.is_modify() || event.kind.is_create();
    let concerns_config = event.paths.iter().any(|p| p == config_path);
    if !(relevant_kind && concerns_config) {
        return false;
    }

    let mut last = last_reload
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if now.duration_since(*last) < DEBOUNCE_DURATION {
        debug!(path = %config_path.display(), "Debouncing config reload");
        return false;
    }
    *last = now;
    true
}

/// Build the notify callback shared by all constructors.
fn make_reload_handler(
    path: PathBuf,
    config: Arc<RwLock<Config>>,
    validator: Option<Arc<CommandValidator>>,
    on_reload: Option<Arc<dyn Fn() + Send + Sync>>,
) -> impl Fn(notify::Result<Event>) + Send + 'static {
    // Initialize the debounce timestamp to an instant in the past so the
    // first change is processed immediately.
    let last_reload = Arc::new(Mutex::new(
        Instant::now()
            .checked_sub(DEBOUNCE_DURATION)
            .unwrap_or_else(Instant::now),
    ));
    move |res| match res {
        Ok(event) => {
            if !should_process_event(&event, &path, &last_reload, Instant::now()) {
                return;
            }
            info!(path = %path.display(), "Configuration file changed, reloading...");
            match load_config(&path) {
                Ok(new_config) => {
                    let security_config = new_config.security.clone();
                    {
                        // blocking_write: we're in a sync callback on the
                        // notify watcher thread, not a tokio task.
                        let mut guard = config.blocking_write();
                        *guard = new_config;
                    }
                    if let Some(ref v) = validator {
                        v.reload(&security_config);
                    }
                    info!("Configuration reloaded successfully");
                    if let Some(ref cb) = on_reload {
                        cb();
                    }
                }
                Err(e) => {
                    error!(
                        error = %e,
                        "Failed to reload configuration, keeping previous config"
                    );
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "File watch error");
        }
    }
}

/// Configuration file watcher for hot-reload
///
/// When the configuration file is modified, the watcher automatically
/// reloads the configuration and updates the shared config, then triggers
/// a reload of security rules in the validator.
pub struct ConfigWatcher {
    /// The underlying file watcher (kept alive to maintain watching)
    _watcher: RecommendedWatcher,
    /// Path being watched
    path: PathBuf,
}

impl ConfigWatcher {
    /// Create a new configuration watcher
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to the configuration file to watch
    /// * `config` - Shared configuration that will be updated on changes
    ///
    /// # Errors
    ///
    /// Returns an error if the file watcher cannot be created or if
    /// the path cannot be watched.
    pub fn new(config_path: &Path, config: Arc<RwLock<Config>>) -> notify::Result<Self> {
        Self::with_validator(config_path, config, None)
    }

    /// Create a new configuration watcher with validator hot-reload support
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to the configuration file to watch
    /// * `config` - Shared configuration that will be updated on changes
    /// * `validator` - Optional command validator to reload when security config changes
    ///
    /// # Errors
    ///
    /// Returns an error if the file watcher cannot be created or if
    /// the path cannot be watched.
    pub fn with_validator(
        config_path: &Path,
        config: Arc<RwLock<Config>>,
        validator: Option<Arc<CommandValidator>>,
    ) -> notify::Result<Self> {
        Self::build(config_path, config, validator, None)
    }

    /// Create a configuration watcher with validator and reload notifications.
    ///
    /// After a successful config reload, `on_reload` is invoked so the server
    /// can send `list_changed` notifications to the MCP client.
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to the configuration file to watch
    /// * `config` - Shared configuration that will be updated on changes
    /// * `validator` - Optional command validator to reload when security config changes
    /// * `on_reload` - Callback invoked after each successful reload
    ///
    /// # Errors
    ///
    /// Returns an error if the file watcher cannot be created or if
    /// the path cannot be watched.
    pub fn with_notifications(
        config_path: &Path,
        config: Arc<RwLock<Config>>,
        validator: Option<Arc<CommandValidator>>,
        on_reload: Arc<dyn Fn() + Send + Sync>,
    ) -> notify::Result<Self> {
        Self::build(config_path, config, validator, Some(on_reload))
    }

    /// Shared constructor: wires the reload handler to a watcher on the
    /// config file's parent directory.
    fn build(
        config_path: &Path,
        config: Arc<RwLock<Config>>,
        validator: Option<Arc<CommandValidator>>,
        on_reload: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> notify::Result<Self> {
        // Verify the config file exists before setting up the watcher
        if !config_path.exists() {
            return Err(notify::Error::path_not_found());
        }

        let path = config_path.to_path_buf();
        let mut watcher = notify::recommended_watcher(make_reload_handler(
            path.clone(),
            config,
            validator,
            on_reload,
        ))?;

        // Watch the parent directory instead of the file directly.
        // On Linux, inotify watches file inodes. When editors do atomic saves
        // (write temp file, rename over original), the original inode is deleted
        // and a new one is created, causing the watcher to lose track.
        // Watching the parent directory avoids this issue.
        let watch_path = config_path.parent().unwrap_or(config_path);
        watcher.watch(watch_path, RecursiveMode::NonRecursive)?;

        info!(path = %config_path.display(), "Started watching configuration file for changes");

        Ok(Self {
            _watcher: watcher,
            path,
        })
    }

    /// Get the path being watched
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::io::Write;
    use std::time::Duration;

    use crate::config::{
        AuditConfig, AuthConfig, HostConfig, HostKeyVerification, HttpTransportConfig,
        LimitsConfig, OsType, SecurityConfig, SecurityMode, SessionConfig, SshConfigDiscovery,
        ToolGroupsConfig,
    };

    fn create_test_config() -> Config {
        let mut hosts = HashMap::new();
        hosts.insert(
            "test-host".to_string(),
            HostConfig {
                hostname: "localhost".to_string(),
                port: 22,
                user: "testuser".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::Off,
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
                shell: None,
                retry: None,
                protocol: crate::config::Protocol::default(),
                #[cfg(feature = "winrm")]
                winrm_use_tls: None,
                #[cfg(feature = "winrm")]
                winrm_accept_invalid_certs: None,
                #[cfg(feature = "winrm")]
                winrm_operation_timeout_secs: None,
                #[cfg(feature = "winrm")]
                winrm_max_envelope_size: None,
            },
        );

        Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        }
    }

    fn write_config_to_file(path: &Path, config: &Config) {
        let yaml = serde_saphyr::to_string(config).unwrap();
        let mut file = fs::File::create(path).unwrap();
        file.write_all(yaml.as_bytes()).unwrap();
        file.flush().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[tokio::test]
    async fn test_config_watcher_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial_config = create_test_config();
        write_config_to_file(&config_path, &initial_config);

        let config = Arc::new(RwLock::new(initial_config));
        let watcher = ConfigWatcher::new(&config_path, Arc::clone(&config));

        assert!(watcher.is_ok());
        let watcher = watcher.unwrap();
        assert_eq!(watcher.path(), config_path);
    }

    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn test_config_watcher_detects_changes() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let mut initial_config = create_test_config();
        write_config_to_file(&config_path, &initial_config);

        let config = Arc::new(RwLock::new(initial_config.clone()));
        let _watcher = ConfigWatcher::new(&config_path, Arc::clone(&config)).unwrap();

        // Give the inotify watcher time to register with the kernel before
        // the first write. Under instrumented builds (llvm-cov) the watcher
        // thread can be slow to come online, causing the first event to be
        // missed when the write happens immediately after `new()`.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Modify the config file
        initial_config.hosts.insert(
            "new-host".to_string(),
            HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Agent,
                description: Some("New host".to_string()),
                host_key_verification: HostKeyVerification::Off,
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
                shell: None,
                retry: None,
                protocol: crate::config::Protocol::default(),
                #[cfg(feature = "winrm")]
                winrm_use_tls: None,
                #[cfg(feature = "winrm")]
                winrm_accept_invalid_certs: None,
                #[cfg(feature = "winrm")]
                winrm_operation_timeout_secs: None,
                #[cfg(feature = "winrm")]
                winrm_max_envelope_size: None,
            },
        );
        write_config_to_file(&config_path, &initial_config);

        // Poll for the change rather than sleeping a fixed interval. Filesystem
        // event delivery latency varies widely (especially under instrumented
        // builds like llvm-cov), so a fixed 1500ms sleep is flaky. Retry for up
        // to 5 seconds, sleeping 100ms between checks.
        let mut detected = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if config.read().await.hosts.contains_key("new-host") {
                detected = true;
                break;
            }
        }
        assert!(detected, "Config watcher did not detect changes");
    }

    #[tokio::test]
    async fn test_config_watcher_path_accessor() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("test_config.yaml");

        let config = create_test_config();
        write_config_to_file(&config_path, &config);

        let shared_config = Arc::new(RwLock::new(config));
        let watcher = ConfigWatcher::new(&config_path, shared_config).unwrap();

        assert_eq!(watcher.path(), config_path);
        assert!(watcher.path().ends_with("test_config.yaml"));
    }

    #[tokio::test]
    async fn test_config_watcher_with_validator() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let config = create_test_config();
        write_config_to_file(&config_path, &config);

        let shared_config = Arc::new(RwLock::new(config.clone()));
        let validator = Arc::new(CommandValidator::new(&config.security));

        let watcher = ConfigWatcher::with_validator(&config_path, shared_config, Some(validator));

        assert!(watcher.is_ok());
    }

    #[tokio::test]
    async fn test_config_watcher_nonexistent_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("nonexistent.yaml");

        let config = Arc::new(RwLock::new(create_test_config()));
        let result = ConfigWatcher::new(&config_path, config);

        // Should fail because file doesn't exist
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_config_watcher_without_validator() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let config = create_test_config();
        write_config_to_file(&config_path, &config);

        let shared_config = Arc::new(RwLock::new(config));
        let watcher = ConfigWatcher::with_validator(&config_path, shared_config, None);

        assert!(watcher.is_ok());
    }

    #[tokio::test]
    async fn test_config_watcher_preserves_config_on_invalid_yaml() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial_config = create_test_config();
        write_config_to_file(&config_path, &initial_config);

        let config = Arc::new(RwLock::new(initial_config));
        let _watcher = ConfigWatcher::new(&config_path, Arc::clone(&config)).unwrap();

        // Write invalid YAML
        fs::write(&config_path, "invalid: yaml: content: [[[").unwrap();

        // Wait for watcher to attempt reload
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Config should still have original content
        let current_config = config.read().await;
        assert!(current_config.hosts.contains_key("test-host"));
    }

    /// Simulate an atomic save (write to temp file, rename over original).
    /// This is how vim, nano, VS Code, and most editors save files.
    fn atomic_save(path: &Path, config: &Config) {
        let temp_path = path.with_extension("yaml.tmp");
        write_config_to_file(&temp_path, config);
        fs::rename(&temp_path, path).unwrap();
    }

    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn test_config_watcher_detects_atomic_save() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let mut initial_config = create_test_config();
        write_config_to_file(&config_path, &initial_config);

        let config = Arc::new(RwLock::new(initial_config.clone()));
        let _watcher = ConfigWatcher::new(&config_path, Arc::clone(&config)).unwrap();

        // Simulate an atomic save (how editors like vim/nano save files)
        initial_config.hosts.insert(
            "atomic-host".to_string(),
            HostConfig {
                hostname: "10.0.0.1".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Agent,
                description: Some("Added via atomic save".to_string()),
                host_key_verification: HostKeyVerification::Off,
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
                shell: None,
                retry: None,
                protocol: crate::config::Protocol::default(),
                #[cfg(feature = "winrm")]
                winrm_use_tls: None,
                #[cfg(feature = "winrm")]
                winrm_accept_invalid_certs: None,
                #[cfg(feature = "winrm")]
                winrm_operation_timeout_secs: None,
                #[cfg(feature = "winrm")]
                winrm_max_envelope_size: None,
            },
        );
        atomic_save(&config_path, &initial_config);

        // Wait for PollWatcher to detect the change
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let current_config = config.read().await;
        assert!(
            current_config.hosts.contains_key("atomic-host"),
            "Config should detect atomic save (write temp + rename)"
        );
    }

    #[tokio::test]
    async fn test_config_watcher_reloads_validator_on_atomic_save() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial_config = create_test_config();
        write_config_to_file(&config_path, &initial_config);

        let shared_config = Arc::new(RwLock::new(initial_config.clone()));
        let validator = Arc::new(CommandValidator::new(&initial_config.security));

        // Default is strict mode with empty whitelist, so "ls" is denied
        assert!(validator.validate("ls").is_err());

        let _watcher = ConfigWatcher::with_validator(
            &config_path,
            Arc::clone(&shared_config),
            Some(Arc::clone(&validator)),
        )
        .unwrap();

        // Atomic save: change to permissive mode
        let mut new_config = initial_config;
        new_config.security.mode = SecurityMode::Permissive;
        atomic_save(&config_path, &new_config);

        // Wait for PollWatcher to detect the change and reload the validator
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("ls").is_ok(),
            "Validator should be reloaded after atomic save"
        );
    }

    // ============== Whitelist hot-reload tests ==============

    /// Helper: create a config with specific security settings
    fn config_with_security(
        mode: SecurityMode,
        whitelist: Vec<&str>,
        blacklist: Vec<&str>,
    ) -> Config {
        let mut config = create_test_config();
        config.security.mode = mode;
        config.security.whitelist = whitelist.into_iter().map(String::from).collect();
        config.security.blacklist = blacklist.into_iter().map(String::from).collect();
        config
    }

    /// Helper: set up a watcher with a validator
    fn setup_watcher_with_validator(
        config_path: &Path,
        config: &Config,
    ) -> (Arc<RwLock<Config>>, Arc<CommandValidator>, ConfigWatcher) {
        let shared_config = Arc::new(RwLock::new(config.clone()));
        let validator = Arc::new(CommandValidator::new(&config.security));
        let watcher = ConfigWatcher::with_validator(
            config_path,
            Arc::clone(&shared_config),
            Some(Arc::clone(&validator)),
        )
        .unwrap();
        (shared_config, validator, watcher)
    }

    #[tokio::test]
    async fn test_reload_adds_whitelist_pattern() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        // Start with strict mode, whitelist: only "ls"
        let initial = config_with_security(SecurityMode::Strict, vec![r"^ls\b"], vec![]);
        write_config_to_file(&config_path, &initial);

        let (_cfg, validator, _watcher) = setup_watcher_with_validator(&config_path, &initial);

        assert!(validator.validate("ls -la").is_ok());
        assert!(
            validator.validate("cat /etc/hosts").is_err(),
            "cat not whitelisted yet"
        );

        // Reload: add "cat" to whitelist
        let updated = config_with_security(SecurityMode::Strict, vec![r"^ls\b", r"^cat\b"], vec![]);
        atomic_save(&config_path, &updated);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("cat /etc/hosts").is_ok(),
            "cat should be allowed after whitelist reload"
        );
        assert!(validator.validate("ls -la").is_ok(), "ls should still work");
    }

    #[tokio::test]
    async fn test_reload_removes_whitelist_pattern() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        // Start with strict mode, whitelist: "ls" and "cat"
        let initial = config_with_security(SecurityMode::Strict, vec![r"^ls\b", r"^cat\b"], vec![]);
        write_config_to_file(&config_path, &initial);

        let (_cfg, validator, _watcher) = setup_watcher_with_validator(&config_path, &initial);

        assert!(validator.validate("ls").is_ok());
        assert!(validator.validate("cat file").is_ok());

        // Reload: remove "cat" from whitelist
        let updated = config_with_security(SecurityMode::Strict, vec![r"^ls\b"], vec![]);
        atomic_save(&config_path, &updated);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(validator.validate("ls").is_ok(), "ls should still work");
        assert!(
            validator.validate("cat file").is_err(),
            "cat should be denied after removal from whitelist"
        );
    }

    #[tokio::test]
    async fn test_reload_replaces_whitelist_entirely() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial = config_with_security(SecurityMode::Strict, vec![r"^ls\b", r"^pwd$"], vec![]);
        write_config_to_file(&config_path, &initial);

        let (_cfg, validator, _watcher) = setup_watcher_with_validator(&config_path, &initial);

        assert!(validator.validate("ls").is_ok());
        assert!(validator.validate("pwd").is_ok());
        assert!(validator.validate("whoami").is_err());

        // Reload: completely different whitelist
        let updated =
            config_with_security(SecurityMode::Strict, vec![r"^whoami$", r"^date$"], vec![]);
        atomic_save(&config_path, &updated);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("ls").is_err(),
            "ls should be denied with new whitelist"
        );
        assert!(
            validator.validate("pwd").is_err(),
            "pwd should be denied with new whitelist"
        );
        assert!(
            validator.validate("whoami").is_ok(),
            "whoami should be allowed with new whitelist"
        );
        assert!(
            validator.validate("date").is_ok(),
            "date should be allowed with new whitelist"
        );
    }

    // ============== Blacklist hot-reload tests ==============

    #[tokio::test]
    async fn test_reload_adds_blacklist_pattern() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial = config_with_security(SecurityMode::Permissive, vec![], vec![r"rm\s+-rf"]);
        write_config_to_file(&config_path, &initial);

        let (_cfg, validator, _watcher) = setup_watcher_with_validator(&config_path, &initial);

        assert!(validator.validate("rm -rf /").is_err());
        assert!(
            validator.validate("mkfs.ext4 /dev/sda").is_ok(),
            "mkfs not blacklisted yet"
        );

        // Reload: add mkfs to blacklist
        let updated = config_with_security(
            SecurityMode::Permissive,
            vec![],
            vec![r"rm\s+-rf", r"mkfs\."],
        );
        atomic_save(&config_path, &updated);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("rm -rf /").is_err(),
            "rm -rf still blacklisted"
        );
        assert!(
            validator.validate("mkfs.ext4 /dev/sda").is_err(),
            "mkfs should be denied after blacklist reload"
        );
    }

    #[tokio::test]
    async fn test_reload_removes_blacklist_pattern() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial = config_with_security(
            SecurityMode::Permissive,
            vec![],
            vec![r"rm\s+-rf", r"mkfs\."],
        );
        write_config_to_file(&config_path, &initial);

        let (_cfg, validator, _watcher) = setup_watcher_with_validator(&config_path, &initial);

        assert!(validator.validate("rm -rf /").is_err());
        assert!(validator.validate("mkfs.ext4 /dev/sda").is_err());

        // Reload: remove mkfs from blacklist
        let updated = config_with_security(SecurityMode::Permissive, vec![], vec![r"rm\s+-rf"]);
        atomic_save(&config_path, &updated);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("rm -rf /").is_err(),
            "rm -rf still blacklisted"
        );
        assert!(
            validator.validate("mkfs.ext4 /dev/sda").is_ok(),
            "mkfs should be allowed after removal from blacklist"
        );
    }

    #[tokio::test]
    async fn test_reload_blacklist_overrides_whitelist() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        // Start: strict mode, "cat" whitelisted, no relevant blacklist
        let initial = config_with_security(SecurityMode::Strict, vec![r"^cat\b"], vec![]);
        write_config_to_file(&config_path, &initial);

        let (_cfg, validator, _watcher) = setup_watcher_with_validator(&config_path, &initial);

        assert!(
            validator.validate("cat /etc/shadow").is_ok(),
            "cat allowed initially"
        );

        // Reload: add blacklist for "cat /etc/shadow" specifically
        let updated = config_with_security(
            SecurityMode::Strict,
            vec![r"^cat\b"],
            vec![r"cat\s+/etc/shadow"],
        );
        atomic_save(&config_path, &updated);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("cat /etc/shadow").is_err(),
            "cat /etc/shadow should be denied by blacklist even though cat is whitelisted"
        );
        assert!(
            validator.validate("cat /etc/hostname").is_ok(),
            "cat /etc/hostname should still be allowed"
        );
    }

    // ============== Mode switching tests ==============

    #[tokio::test]
    async fn test_reload_strict_to_permissive() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial = config_with_security(SecurityMode::Strict, vec![r"^ls\b"], vec![]);
        write_config_to_file(&config_path, &initial);

        let (_cfg, validator, _watcher) = setup_watcher_with_validator(&config_path, &initial);

        assert!(validator.validate("ls").is_ok());
        assert!(
            validator.validate("whoami").is_err(),
            "not whitelisted in strict"
        );

        // Reload: switch to permissive
        let updated = config_with_security(SecurityMode::Permissive, vec![], vec![]);
        atomic_save(&config_path, &updated);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("whoami").is_ok(),
            "everything allowed in permissive"
        );
        assert!(
            validator.validate("anything goes").is_ok(),
            "arbitrary commands allowed in permissive"
        );
    }

    #[tokio::test]
    async fn test_reload_permissive_to_strict() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial = config_with_security(SecurityMode::Permissive, vec![], vec![]);
        write_config_to_file(&config_path, &initial);

        let (_cfg, validator, _watcher) = setup_watcher_with_validator(&config_path, &initial);

        assert!(
            validator.validate("anything").is_ok(),
            "permissive allows all"
        );

        // Reload: switch to strict with narrow whitelist
        let updated = config_with_security(SecurityMode::Strict, vec![r"^pwd$"], vec![]);
        atomic_save(&config_path, &updated);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("pwd").is_ok(),
            "pwd whitelisted in strict mode"
        );
        assert!(
            validator.validate("ls").is_err(),
            "ls not whitelisted, should be denied in strict mode"
        );
        assert!(
            validator.validate("anything").is_err(),
            "arbitrary commands denied in strict mode"
        );
    }

    // ============== Multiple consecutive reloads ==============

    #[tokio::test]
    async fn test_multiple_consecutive_reloads() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial = config_with_security(SecurityMode::Strict, vec![r"^ls\b"], vec![]);
        write_config_to_file(&config_path, &initial);

        let (_cfg, validator, _watcher) = setup_watcher_with_validator(&config_path, &initial);

        assert!(validator.validate("ls").is_ok());
        assert!(validator.validate("pwd").is_err());

        // Reload 1: add pwd
        let v1 = config_with_security(SecurityMode::Strict, vec![r"^ls\b", r"^pwd$"], vec![]);
        atomic_save(&config_path, &v1);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("pwd").is_ok(),
            "pwd allowed after reload 1"
        );

        // Reload 2: switch to permissive with blacklist
        let v2 = config_with_security(SecurityMode::Permissive, vec![], vec![r"rm\s+-rf"]);
        atomic_save(&config_path, &v2);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("anything").is_ok(),
            "arbitrary allowed after reload 2 (permissive)"
        );
        assert!(
            validator.validate("rm -rf /").is_err(),
            "rm -rf denied after reload 2 (blacklisted)"
        );

        // Reload 3: back to strict with different whitelist
        let v3 = config_with_security(SecurityMode::Strict, vec![r"^whoami$"], vec![]);
        atomic_save(&config_path, &v3);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("whoami").is_ok(),
            "whoami allowed after reload 3"
        );
        assert!(
            validator.validate("ls").is_err(),
            "ls denied after reload 3 (not in new whitelist)"
        );
        assert!(
            validator.validate("pwd").is_err(),
            "pwd denied after reload 3 (not in new whitelist)"
        );
    }

    // ============== Config content reloads ==============

    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn test_reload_updates_shared_config_hosts() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial = create_test_config();
        write_config_to_file(&config_path, &initial);

        let shared_config = Arc::new(RwLock::new(initial.clone()));
        let _watcher = ConfigWatcher::new(&config_path, Arc::clone(&shared_config)).unwrap();

        // Verify initial state
        {
            let cfg = shared_config.read().await;
            assert_eq!(cfg.hosts.len(), 1);
            assert!(cfg.hosts.contains_key("test-host"));
        }

        // Reload: add a second host
        let mut updated = initial;
        updated.hosts.insert(
            "new-host".to_string(),
            HostConfig {
                hostname: "10.0.0.2".to_string(),
                port: 2222,
                user: "deploy".to_string(),
                auth: AuthConfig::Agent,
                description: Some("Added by reload".to_string()),
                host_key_verification: HostKeyVerification::Off,
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
                shell: None,
                retry: None,
                protocol: crate::config::Protocol::default(),
                #[cfg(feature = "winrm")]
                winrm_use_tls: None,
                #[cfg(feature = "winrm")]
                winrm_accept_invalid_certs: None,
                #[cfg(feature = "winrm")]
                winrm_operation_timeout_secs: None,
                #[cfg(feature = "winrm")]
                winrm_max_envelope_size: None,
            },
        );
        atomic_save(&config_path, &updated);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let cfg = shared_config.read().await;
        assert_eq!(cfg.hosts.len(), 2, "should have 2 hosts after reload");
        assert!(cfg.hosts.contains_key("test-host"));
        assert!(cfg.hosts.contains_key("new-host"));
        assert_eq!(cfg.hosts["new-host"].port, 2222);
    }

    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn test_reload_updates_shared_config_security() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial = create_test_config();
        write_config_to_file(&config_path, &initial);

        let shared_config = Arc::new(RwLock::new(initial.clone()));
        let _watcher = ConfigWatcher::new(&config_path, Arc::clone(&shared_config)).unwrap();

        // Initial: standard mode (default), empty whitelist
        {
            let cfg = shared_config.read().await;
            assert_eq!(cfg.security.mode, SecurityMode::Standard);
            assert!(cfg.security.whitelist.is_empty());
        }

        // Reload: permissive mode with blacklist
        let mut updated = initial;
        updated.security.mode = SecurityMode::Permissive;
        updated.security.blacklist = vec![r"rm\s+-rf".to_string(), r"mkfs\.".to_string()];
        atomic_save(&config_path, &updated);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let cfg = shared_config.read().await;
        assert_eq!(
            cfg.security.mode,
            SecurityMode::Permissive,
            "mode should be permissive after reload"
        );
        assert_eq!(
            cfg.security.blacklist.len(),
            2,
            "should have 2 blacklist patterns"
        );
    }

    // ============== Debounce tests ==============

    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn test_debounce_rapid_saves() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial = create_test_config();
        write_config_to_file(&config_path, &initial);

        let shared_config = Arc::new(RwLock::new(initial.clone()));
        let _watcher = ConfigWatcher::new(&config_path, Arc::clone(&shared_config)).unwrap();

        // Rapid-fire 5 saves in quick succession (within debounce window)
        for i in 0..5 {
            let mut cfg = initial.clone();
            cfg.hosts.insert(
                format!("rapid-{i}"),
                HostConfig {
                    hostname: format!("10.0.0.{i}"),
                    port: 22,
                    user: "admin".to_string(),
                    auth: AuthConfig::Agent,
                    description: None,
                    host_key_verification: HostKeyVerification::Off,
                    proxy_jump: None,
                    socks_proxy: None,
                    sudo_password: None,
                    tags: Vec::new(),
                    os_type: OsType::Linux,
                    shell: None,
                    retry: None,
                    protocol: crate::config::Protocol::default(),
                    #[cfg(feature = "winrm")]
                    winrm_use_tls: None,
                    #[cfg(feature = "winrm")]
                    winrm_accept_invalid_certs: None,
                    #[cfg(feature = "winrm")]
                    winrm_operation_timeout_secs: None,
                    #[cfg(feature = "winrm")]
                    winrm_max_envelope_size: None,
                },
            );
            write_config_to_file(&config_path, &cfg);
            // No sleep between writes - rapid succession
        }

        // Wait for debounce + processing
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // The final state should have been loaded (last write wins)
        // We don't assert which intermediate state was captured, but the config
        // should be valid and not corrupted by concurrent reloads
        let cfg = shared_config.read().await;
        assert!(
            cfg.hosts.contains_key("test-host"),
            "original host should survive rapid reloads"
        );
    }

    // ============== Edge cases ==============

    #[tokio::test]
    async fn test_reload_empty_whitelist_strict_denies_all() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        // Start permissive
        let initial = config_with_security(SecurityMode::Permissive, vec![], vec![]);
        write_config_to_file(&config_path, &initial);

        let (_cfg, validator, _watcher) = setup_watcher_with_validator(&config_path, &initial);

        assert!(validator.validate("ls").is_ok());
        assert!(validator.validate("anything").is_ok());

        // Reload: strict mode with EMPTY whitelist = deny all
        let updated = config_with_security(SecurityMode::Strict, vec![], vec![]);
        atomic_save(&config_path, &updated);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("ls").is_err(),
            "empty whitelist in strict = deny all"
        );
        assert!(
            validator.validate("pwd").is_err(),
            "empty whitelist in strict = deny all"
        );
    }

    #[tokio::test]
    async fn test_reload_empty_blacklist_permissive_allows_all() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        // Start with blacklist
        let initial = config_with_security(
            SecurityMode::Permissive,
            vec![],
            vec![r"rm\s+-rf", r"mkfs\."],
        );
        write_config_to_file(&config_path, &initial);

        let (_cfg, validator, _watcher) = setup_watcher_with_validator(&config_path, &initial);

        assert!(validator.validate("rm -rf /").is_err());

        // Reload: clear all blacklist patterns
        let updated = config_with_security(SecurityMode::Permissive, vec![], vec![]);
        atomic_save(&config_path, &updated);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("rm -rf /").is_ok(),
            "empty blacklist in permissive = allow all"
        );
        assert!(
            validator.validate("mkfs.ext4 /dev/sda").is_ok(),
            "empty blacklist in permissive = allow all"
        );
    }

    // ============== with_notifications tests ==============

    #[tokio::test]
    async fn test_with_notifications_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let config = create_test_config();
        write_config_to_file(&config_path, &config);

        let shared_config = Arc::new(RwLock::new(config.clone()));
        let validator = Arc::new(CommandValidator::new(&config.security));
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let called_clone = Arc::clone(&called);
        let on_reload: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            called_clone.store(true, std::sync::atomic::Ordering::Relaxed);
        });

        let watcher = ConfigWatcher::with_notifications(
            &config_path,
            shared_config,
            Some(validator),
            on_reload,
        );

        assert!(watcher.is_ok());
        assert_eq!(watcher.unwrap().path(), config_path);
    }

    #[tokio::test]
    async fn test_with_notifications_nonexistent_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("missing.yaml");

        let config = Arc::new(RwLock::new(create_test_config()));
        let on_reload: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});

        let result = ConfigWatcher::with_notifications(&config_path, config, None, on_reload);
        assert!(result.is_err());
    }

    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn test_with_notifications_callback_invoked_on_change() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial = create_test_config();
        write_config_to_file(&config_path, &initial);

        let shared_config = Arc::new(RwLock::new(initial.clone()));
        let called = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let called_clone = Arc::clone(&called);
        let on_reload: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            called_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });

        let _watcher = ConfigWatcher::with_notifications(
            &config_path,
            Arc::clone(&shared_config),
            None,
            on_reload,
        )
        .unwrap();

        // Modify config file
        let mut updated = initial;
        updated.limits.command_timeout_seconds = 999;
        atomic_save(&config_path, &updated);

        // Wait for watcher to detect the change
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            called.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "on_reload callback should have been invoked"
        );

        // Verify config was updated
        let cfg = shared_config.read().await;
        assert_eq!(cfg.limits.command_timeout_seconds, 999);
    }

    // ============== DEBOUNCE_DURATION constant test ==============

    #[test]
    fn test_debounce_duration_value() {
        assert_eq!(DEBOUNCE_DURATION, Duration::from_millis(500));
    }

    // ============== should_process_event (pure core) ==============

    mod should_process {
        use notify::Event;
        use notify::event::{AccessKind, CreateKind, DataChange, EventKind, ModifyKind};

        use super::super::should_process_event;
        use super::*;

        fn modify_event(path: &Path) -> Event {
            Event::new(EventKind::Modify(ModifyKind::Data(DataChange::Content)))
                .add_path(path.to_path_buf())
        }

        /// Debounce state whose last reload is comfortably in the past.
        fn past_instant(now: Instant) -> Mutex<Instant> {
            Mutex::new(now.checked_sub(DEBOUNCE_DURATION * 2).unwrap_or(now))
        }

        #[test]
        fn accepts_modify_on_config_path() {
            let p = PathBuf::from("/etc/bridge/config.yaml");
            let now = Instant::now();
            assert!(should_process_event(
                &modify_event(&p),
                &p,
                &past_instant(now),
                now
            ));
        }

        #[test]
        fn accepts_create_for_atomic_saves() {
            let p = PathBuf::from("/etc/bridge/config.yaml");
            let ev = Event::new(EventKind::Create(CreateKind::File)).add_path(p.clone());
            let now = Instant::now();
            assert!(should_process_event(&ev, &p, &past_instant(now), now));
        }

        #[test]
        fn rejects_wrong_path() {
            let p = PathBuf::from("/etc/bridge/config.yaml");
            let other = PathBuf::from("/etc/bridge/other.yaml");
            let now = Instant::now();
            assert!(!should_process_event(
                &modify_event(&other),
                &p,
                &past_instant(now),
                now
            ));
        }

        #[test]
        fn rejects_access_events() {
            let p = PathBuf::from("/etc/bridge/config.yaml");
            let ev = Event::new(EventKind::Access(AccessKind::Read)).add_path(p.clone());
            let now = Instant::now();
            assert!(!should_process_event(&ev, &p, &past_instant(now), now));
        }

        #[test]
        fn debounces_inside_window() {
            let p = PathBuf::from("/etc/bridge/config.yaml");
            let start = Instant::now();
            let last = Mutex::new(start);
            let just_inside = start + DEBOUNCE_DURATION.saturating_sub(Duration::from_millis(1));
            assert!(!should_process_event(
                &modify_event(&p),
                &p,
                &last,
                just_inside
            ));
        }

        #[test]
        fn fires_at_exact_debounce_boundary() {
            // elapsed == DEBOUNCE_DURATION: strict `<` means the debounce
            // window is over, the event must be processed.
            let p = PathBuf::from("/etc/bridge/config.yaml");
            let start = Instant::now();
            let last = Mutex::new(start);
            assert!(should_process_event(
                &modify_event(&p),
                &p,
                &last,
                start + DEBOUNCE_DURATION
            ));
        }

        #[test]
        fn updates_last_reload_timestamp_on_acceptance() {
            let p = PathBuf::from("/etc/bridge/config.yaml");
            let now = Instant::now();
            let last = past_instant(now);
            assert!(should_process_event(&modify_event(&p), &p, &last, now));
            // Second event at the same instant: now inside the debounce window.
            assert!(!should_process_event(&modify_event(&p), &p, &last, now));
        }

        #[test]
        fn debounce_rejection_does_not_update_timestamp() {
            // A debounced event must not extend the window: an event exactly
            // at the boundary after a rejected mid-window event still fires.
            let p = PathBuf::from("/etc/bridge/config.yaml");
            let start = Instant::now();
            let last = Mutex::new(start);
            let mid = start + DEBOUNCE_DURATION / 2;
            assert!(!should_process_event(&modify_event(&p), &p, &last, mid));
            assert!(should_process_event(
                &modify_event(&p),
                &p,
                &last,
                start + DEBOUNCE_DURATION
            ));
        }
    }

    #[tokio::test]
    async fn test_reload_invalid_yaml_keeps_previous_validator_rules() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial = config_with_security(SecurityMode::Strict, vec![r"^ls\b"], vec![]);
        write_config_to_file(&config_path, &initial);

        let (_cfg, validator, _watcher) = setup_watcher_with_validator(&config_path, &initial);

        assert!(validator.validate("ls").is_ok());
        assert!(validator.validate("pwd").is_err());

        // Write invalid YAML - validator should keep previous rules
        fs::write(&config_path, "completely: invalid: yaml: [[[").unwrap();
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("ls").is_ok(),
            "validator should keep old rules on invalid YAML"
        );
        assert!(
            validator.validate("pwd").is_err(),
            "validator should keep old rules on invalid YAML"
        );
    }

    #[tokio::test]
    async fn test_reload_via_direct_write_not_just_atomic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let initial = config_with_security(SecurityMode::Strict, vec![r"^ls\b"], vec![]);
        write_config_to_file(&config_path, &initial);

        let (_cfg, validator, _watcher) = setup_watcher_with_validator(&config_path, &initial);

        assert!(validator.validate("pwd").is_err());

        // Direct write (not atomic save) - should also trigger reload via Modify event
        let updated = config_with_security(SecurityMode::Strict, vec![r"^ls\b", r"^pwd$"], vec![]);
        write_config_to_file(&config_path, &updated);
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            validator.validate("pwd").is_ok(),
            "direct write should also trigger hot reload"
        );
    }
}
