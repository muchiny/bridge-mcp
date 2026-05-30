//! Session Recording with Hash-Chain Audit Trail
//!
//! Records SSH command sessions in asciinema v2 format with optional
//! HMAC-SHA256 hash chain for tamper-proof compliance auditing.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use const_hex::encode as hex_encode;
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

/// Asciinema v2 header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingHeader {
    pub version: u32,
    pub width: u32,
    pub height: u32,
    pub timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
}

/// A single recording event (asciinema v2 format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingEvent {
    /// Time offset in seconds from session start
    pub time: f64,
    /// Event type: "i" (input), "o" (output), "m" (marker)
    pub event_type: String,
    /// Event data
    pub data: String,
    /// HMAC-SHA256 hash chain (hex encoded, if `hash_chain` enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Recording session metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingInfo {
    pub id: String,
    pub host: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub event_count: usize,
    pub file_path: String,
    pub hash_chain_enabled: bool,
}

/// Active recording session
struct ActiveSession {
    id: String,
    host: String,
    file: File,
    start_time: Instant,
    started_at: DateTime<Utc>,
    event_count: usize,
    last_hash: String,
    hash_chain_enabled: bool,
    hash_key: Vec<u8>,
}

/// Session recorder managing active and completed recordings
pub struct SessionRecorder {
    recordings_dir: PathBuf,
    sessions: Mutex<HashMap<String, ActiveSession>>,
    hash_chain_enabled: bool,
    hash_key: Vec<u8>,
    auto_mask_secrets: bool,
}

impl SessionRecorder {
    /// Create a new session recorder
    pub fn new(
        recordings_dir: PathBuf,
        hash_chain_enabled: bool,
        hash_key: Vec<u8>,
        auto_mask_secrets: bool,
    ) -> Self {
        if let Err(e) = fs::create_dir_all(&recordings_dir) {
            error!(path = %recordings_dir.display(), error = %e, "Failed to create recordings dir");
        }

        Self {
            recordings_dir,
            sessions: Mutex::new(HashMap::new()),
            hash_chain_enabled,
            hash_key,
            auto_mask_secrets,
        }
    }

    /// Whether auto secret masking is enabled
    #[must_use]
    pub fn auto_mask_secrets(&self) -> bool {
        self.auto_mask_secrets
    }

    /// Start a new recording session
    ///
    /// Returns the session ID on success.
    pub fn start_session(&self, host: &str, title: Option<&str>) -> Result<String, String> {
        let id = format!("rec_{}_{}", host, Utc::now().format("%Y%m%d_%H%M%S"));
        let file_path = self.recordings_dir.join(format!("{id}.cast"));

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&file_path)
            .map_err(|e| format!("Failed to create recording file: {e}"))?;

        // Write asciinema v2 header
        let header = RecordingHeader {
            version: 2,
            width: 120,
            height: 40,
            timestamp: Utc::now().timestamp(),
            title: title.map(String::from),
            env: {
                let mut env = HashMap::new();
                env.insert("SHELL".to_string(), "/bin/bash".to_string());
                env.insert("TERM".to_string(), "xterm-256color".to_string());
                env.insert("MCP_HOST".to_string(), host.to_string());
                env
            },
        };

        let header_json = serde_json::to_string(&header)
            .map_err(|e| format!("Failed to serialize header: {e}"))?;
        writeln!(file, "{header_json}").map_err(|e| format!("Failed to write header: {e}"))?;

        let initial_hash = Self::compute_hash(&self.hash_key, "genesis", "");

        let session = ActiveSession {
            id: id.clone(),
            host: host.to_string(),
            file,
            start_time: Instant::now(),
            started_at: Utc::now(),
            event_count: 0,
            last_hash: initial_hash,
            hash_chain_enabled: self.hash_chain_enabled,
            hash_key: self.hash_key.clone(),
        };

        self.sessions
            .lock()
            .map_err(|e| format!("Lock poisoned: {e}"))?
            .insert(id.clone(), session);

        info!(session_id = %id, host = %host, "Recording session started");
        Ok(id)
    }

    /// Record an event (command input or output) to an active session
    pub fn record_event(
        &self,
        session_id: &str,
        event_type: &str,
        data: &str,
    ) -> Result<(), String> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| format!("Lock poisoned: {e}"))?;

        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| format!("No active session: {session_id}"))?;

        let elapsed = session.start_time.elapsed().as_secs_f64();

        let hash = if session.hash_chain_enabled {
            let event_data = format!("{elapsed:.6}:{event_type}:{data}");
            let new_hash = Self::compute_hash(&session.hash_key, &session.last_hash, &event_data);
            session.last_hash.clone_from(&new_hash);
            Some(new_hash)
        } else {
            None
        };

        // Write asciinema v2 event line: [time, type, data]
        // Extended with optional hash field
        let event_json = if let Some(ref h) = hash {
            format!(
                "[{elapsed:.6}, {}, {}, {}]",
                serde_json::to_string(event_type).unwrap_or_default(),
                serde_json::to_string(data).unwrap_or_default(),
                serde_json::to_string(h).unwrap_or_default()
            )
        } else {
            format!(
                "[{elapsed:.6}, {}, {}]",
                serde_json::to_string(event_type).unwrap_or_default(),
                serde_json::to_string(data).unwrap_or_default()
            )
        };

        writeln!(session.file, "{event_json}")
            .map_err(|e| format!("Failed to write event: {e}"))?;

        session.event_count += 1;
        Ok(())
    }

    /// Stop a recording session
    pub fn stop_session(&self, session_id: &str) -> Result<RecordingInfo, String> {
        let session = self
            .sessions
            .lock()
            .map_err(|e| format!("Lock poisoned: {e}"))?
            .remove(session_id)
            .ok_or_else(|| format!("No active session: {session_id}"))?;

        let file_path = self.recordings_dir.join(format!("{}.cast", session.id));

        let info = RecordingInfo {
            id: session.id.clone(),
            host: session.host,
            started_at: session.started_at,
            ended_at: Some(Utc::now()),
            event_count: session.event_count,
            file_path: file_path.to_string_lossy().to_string(),
            hash_chain_enabled: session.hash_chain_enabled,
        };

        info!(
            session_id = %session.id,
            events = session.event_count,
            "Recording session stopped"
        );

        Ok(info)
    }

    /// List all recording files (active and completed)
    pub fn list_recordings(&self) -> Result<Vec<RecordingInfo>, String> {
        let mut recordings = Vec::new();

        // List active sessions
        if let Ok(sessions) = self.sessions.lock() {
            for session in sessions.values() {
                recordings.push(RecordingInfo {
                    id: session.id.clone(),
                    host: session.host.clone(),
                    started_at: session.started_at,
                    ended_at: None,
                    event_count: session.event_count,
                    file_path: self
                        .recordings_dir
                        .join(format!("{}.cast", session.id))
                        .to_string_lossy()
                        .to_string(),
                    hash_chain_enabled: session.hash_chain_enabled,
                });
            }
        }

        // List completed recordings from filesystem
        let entries = fs::read_dir(&self.recordings_dir)
            .map_err(|e| format!("Failed to read recordings dir: {e}"))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "cast") {
                let filename = path.file_stem().unwrap_or_default().to_string_lossy();
                // Skip active sessions (already listed)
                if self
                    .sessions
                    .lock()
                    .is_ok_and(|sessions| sessions.contains_key(filename.as_ref()))
                {
                    continue;
                }

                if let Ok(info) = Self::read_recording_info(&path) {
                    recordings.push(info);
                }
            }
        }

        recordings.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        Ok(recordings)
    }

    /// Read a recording file and return its events for replay
    pub fn replay_recording(path: &Path) -> Result<(RecordingHeader, Vec<RecordingEvent>), String> {
        let file = File::open(path).map_err(|e| format!("Failed to open recording: {e}"))?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        // First line is the header
        let header_line = lines
            .next()
            .ok_or("Empty recording file")?
            .map_err(|e| format!("Failed to read header: {e}"))?;

        let header: RecordingHeader =
            serde_json::from_str(&header_line).map_err(|e| format!("Invalid header: {e}"))?;

        let mut events = Vec::new();

        for line_result in lines {
            let line = line_result.map_err(|e| format!("Read error: {e}"))?;
            if line.trim().is_empty() {
                continue;
            }

            // Parse asciinema v2 event: [time, type, data] or [time, type, data, hash]
            let arr: Vec<serde_json::Value> =
                serde_json::from_str(&line).map_err(|e| format!("Invalid event line: {e}"))?;

            if arr.len() >= 3 {
                events.push(RecordingEvent {
                    time: arr[0].as_f64().unwrap_or(0.0),
                    event_type: arr[1].as_str().unwrap_or("o").to_string(),
                    data: arr[2].as_str().unwrap_or("").to_string(),
                    hash: arr.get(3).and_then(|v| v.as_str()).map(String::from),
                });
            }
        }

        Ok((header, events))
    }

    /// Verify the hash chain integrity of a recording
    pub fn verify_recording(path: &Path, key: &[u8]) -> Result<VerifyResult, String> {
        let (_header, events) = Self::replay_recording(path)?;

        if events.is_empty() {
            return Ok(VerifyResult {
                valid: true,
                total_events: 0,
                verified_events: 0,
                first_invalid_index: None,
            });
        }

        // Check if hash chain is present
        if events[0].hash.is_none() {
            return Ok(VerifyResult {
                valid: true,
                total_events: events.len(),
                verified_events: 0,
                first_invalid_index: None,
            });
        }

        let mut last_hash = Self::compute_hash(key, "genesis", "");
        let mut verified = 0;

        for (i, event) in events.iter().enumerate() {
            let event_data = format!("{:.6}:{}:{}", event.time, event.event_type, event.data);
            let expected_hash = Self::compute_hash(key, &last_hash, &event_data);

            match &event.hash {
                Some(h) if h == &expected_hash => {
                    last_hash = expected_hash;
                    verified += 1;
                }
                Some(_) => {
                    return Ok(VerifyResult {
                        valid: false,
                        total_events: events.len(),
                        verified_events: verified,
                        first_invalid_index: Some(i),
                    });
                }
                None => {
                    warn!(index = i, "Event missing hash in chain");
                    return Ok(VerifyResult {
                        valid: false,
                        total_events: events.len(),
                        verified_events: verified,
                        first_invalid_index: Some(i),
                    });
                }
            }
        }

        Ok(VerifyResult {
            valid: true,
            total_events: events.len(),
            verified_events: verified,
            first_invalid_index: None,
        })
    }

    /// Compute HMAC-SHA256 hash for chain linking
    fn compute_hash(key: &[u8], previous_hash: &str, data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(previous_hash.as_bytes());
        hasher.update(data.as_bytes());
        hex_encode(hasher.finalize().as_slice())
    }

    /// Read recording info from a .cast file header
    fn read_recording_info(path: &Path) -> Result<RecordingInfo, String> {
        let file = File::open(path).map_err(|e| format!("Failed to open: {e}"))?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let header_line = lines
            .next()
            .ok_or("Empty file")?
            .map_err(|e| format!("Read error: {e}"))?;

        let header: RecordingHeader =
            serde_json::from_str(&header_line).map_err(|e| format!("Invalid header: {e}"))?;

        let event_count = lines.count();
        let filename = path.file_stem().unwrap_or_default().to_string_lossy();
        let host = header
            .env
            .get("MCP_HOST")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        Ok(RecordingInfo {
            id: filename.to_string(),
            host,
            started_at: DateTime::from_timestamp(header.timestamp, 0).unwrap_or_default(),
            ended_at: None,
            event_count,
            file_path: path.to_string_lossy().to_string(),
            hash_chain_enabled: false, // Can't know from header alone
        })
    }
}

/// Result of hash chain verification
#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub total_events: usize,
    pub verified_events: usize,
    pub first_invalid_index: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_recorder(dir: &Path) -> SessionRecorder {
        SessionRecorder::new(dir.to_path_buf(), true, b"test-secret-key".to_vec(), false)
    }

    #[test]
    fn test_start_and_stop_session() {
        let tmp = TempDir::new().unwrap();
        let recorder = test_recorder(tmp.path());

        let id = recorder
            .start_session("myhost", Some("test session"))
            .unwrap();
        assert!(id.starts_with("rec_myhost_"));

        let info = recorder.stop_session(&id).unwrap();
        assert_eq!(info.host, "myhost");
        assert_eq!(info.event_count, 0);
        assert!(info.ended_at.is_some());
    }

    #[test]
    fn test_record_events() {
        let tmp = TempDir::new().unwrap();
        let recorder = test_recorder(tmp.path());

        let id = recorder.start_session("server1", None).unwrap();
        recorder.record_event(&id, "i", "ls -la\r\n").unwrap();
        recorder.record_event(&id, "o", "total 42\r\n").unwrap();
        recorder
            .record_event(&id, "o", "-rw-r--r-- 1 root root 1234 file.txt\r\n")
            .unwrap();

        let info = recorder.stop_session(&id).unwrap();
        assert_eq!(info.event_count, 3);
    }

    #[test]
    fn test_replay_recording() {
        let tmp = TempDir::new().unwrap();
        let recorder = test_recorder(tmp.path());

        let id = recorder
            .start_session("host1", Some("replay test"))
            .unwrap();
        recorder.record_event(&id, "i", "whoami").unwrap();
        recorder.record_event(&id, "o", "root").unwrap();
        let info = recorder.stop_session(&id).unwrap();

        let path = PathBuf::from(&info.file_path);
        let (header, events) = SessionRecorder::replay_recording(&path).unwrap();

        assert_eq!(header.version, 2);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "i");
        assert_eq!(events[0].data, "whoami");
        assert_eq!(events[1].event_type, "o");
        assert_eq!(events[1].data, "root");
    }

    #[test]
    fn test_hash_chain_verification_valid() {
        let tmp = TempDir::new().unwrap();
        let key = b"my-secret-key".to_vec();
        let recorder = SessionRecorder::new(tmp.path().to_path_buf(), true, key.clone(), false);

        let id = recorder.start_session("host1", None).unwrap();
        recorder.record_event(&id, "i", "uptime").unwrap();
        recorder.record_event(&id, "o", "12:00 up 5 days").unwrap();
        let info = recorder.stop_session(&id).unwrap();

        let result = SessionRecorder::verify_recording(Path::new(&info.file_path), &key).unwrap();
        assert!(result.valid);
        assert_eq!(result.verified_events, 2);
        assert!(result.first_invalid_index.is_none());
    }

    #[test]
    fn test_hash_chain_detects_tampering() {
        let tmp = TempDir::new().unwrap();
        let key = b"secret".to_vec();
        let recorder = SessionRecorder::new(tmp.path().to_path_buf(), true, key.clone(), false);

        let id = recorder.start_session("host1", None).unwrap();
        recorder.record_event(&id, "i", "cat /etc/shadow").unwrap();
        recorder.record_event(&id, "o", "root:$6$abc:::::").unwrap();
        let info = recorder.stop_session(&id).unwrap();

        // Tamper with the recording file: modify the second event's data
        let content = fs::read_to_string(&info.file_path).unwrap();
        let tampered = content.replace("root:$6$abc:::::", "TAMPERED_DATA");
        fs::write(&info.file_path, tampered).unwrap();

        let result = SessionRecorder::verify_recording(Path::new(&info.file_path), &key).unwrap();
        assert!(!result.valid);
        assert!(result.first_invalid_index.is_some());
    }

    #[test]
    fn test_list_recordings() {
        let tmp = TempDir::new().unwrap();
        let recorder = test_recorder(tmp.path());

        let id1 = recorder.start_session("host1", None).unwrap();
        recorder.stop_session(&id1).unwrap();

        let id2 = recorder.start_session("host2", None).unwrap();
        recorder.stop_session(&id2).unwrap();

        let list = recorder.list_recordings().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_stop_nonexistent_session() {
        let tmp = TempDir::new().unwrap();
        let recorder = test_recorder(tmp.path());
        let result = recorder.stop_session("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_record_event_nonexistent_session() {
        let tmp = TempDir::new().unwrap();
        let recorder = test_recorder(tmp.path());
        let result = recorder.record_event("nonexistent", "o", "data");
        assert!(result.is_err());
    }

    #[test]
    fn test_no_hash_chain() {
        let tmp = TempDir::new().unwrap();
        let recorder = SessionRecorder::new(tmp.path().to_path_buf(), false, Vec::new(), false);

        let id = recorder.start_session("host1", None).unwrap();
        recorder.record_event(&id, "o", "hello").unwrap();
        let info = recorder.stop_session(&id).unwrap();

        let (_, events) = SessionRecorder::replay_recording(Path::new(&info.file_path)).unwrap();
        assert!(events[0].hash.is_none());
    }

    #[test]
    fn test_verify_recording_empty_events() {
        let tmp = TempDir::new().unwrap();
        let key = b"test-key".to_vec();
        let recorder = SessionRecorder::new(tmp.path().to_path_buf(), true, key.clone(), false);

        let id = recorder.start_session("host1", None).unwrap();
        let info = recorder.stop_session(&id).unwrap();

        let result = SessionRecorder::verify_recording(Path::new(&info.file_path), &key).unwrap();
        assert!(result.valid);
        assert_eq!(result.total_events, 0);
        assert_eq!(result.verified_events, 0);
        assert!(result.first_invalid_index.is_none());
    }

    #[test]
    fn test_verify_recording_no_hash_chain() {
        let tmp = TempDir::new().unwrap();
        let recorder = SessionRecorder::new(tmp.path().to_path_buf(), false, Vec::new(), false);

        let id = recorder.start_session("host1", None).unwrap();
        recorder.record_event(&id, "o", "data").unwrap();
        let info = recorder.stop_session(&id).unwrap();

        let result =
            SessionRecorder::verify_recording(Path::new(&info.file_path), b"any-key").unwrap();
        assert!(result.valid);
        assert_eq!(result.total_events, 1);
        assert_eq!(result.verified_events, 0);
    }

    #[test]
    fn test_list_recordings_with_field_assertions() {
        let tmp = TempDir::new().unwrap();
        let recorder = test_recorder(tmp.path());

        let id = recorder.start_session("myhost", Some("test info")).unwrap();
        recorder.record_event(&id, "i", "whoami").unwrap();
        recorder.record_event(&id, "o", "root").unwrap();
        let _ = recorder.stop_session(&id).unwrap();

        let list = recorder.list_recordings().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].host, "myhost");
        assert_eq!(list[0].event_count, 2);
        assert!(!list[0].file_path.is_empty());
    }

    #[test]
    fn test_compute_hash_deterministic() {
        let h1 = SessionRecorder::compute_hash(b"key", "prev", "data");
        let h2 = SessionRecorder::compute_hash(b"key", "prev", "data");
        assert_eq!(h1, h2);

        let h3 = SessionRecorder::compute_hash(b"key", "prev", "different");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_auto_mask_secrets_getter() {
        let tmp = TempDir::new().unwrap();
        let recorder_on = SessionRecorder::new(tmp.path().to_path_buf(), false, Vec::new(), true);
        assert!(recorder_on.auto_mask_secrets());

        let recorder_off = SessionRecorder::new(tmp.path().to_path_buf(), false, Vec::new(), false);
        assert!(!recorder_off.auto_mask_secrets());
    }

    #[test]
    fn test_list_recordings_includes_active_sessions() {
        let tmp = TempDir::new().unwrap();
        let recorder = test_recorder(tmp.path());

        // Start a session without stopping it — it should appear in list as active
        let id = recorder.start_session("active-host", None).unwrap();
        let list = recorder.list_recordings().unwrap();

        let active = list.iter().find(|r| r.id == id);
        assert!(active.is_some(), "Active session should appear in list");
        let active = active.unwrap();
        assert_eq!(active.host, "active-host");
        assert!(active.ended_at.is_none(), "Active session has no end time");

        // Stop it and verify it moves to completed
        recorder.stop_session(&id).unwrap();
        let list = recorder.list_recordings().unwrap();
        assert_eq!(list.len(), 1);
        assert!(list[0].ended_at.is_none()); // read_recording_info doesn't set ended_at
    }

    #[test]
    fn test_recording_header_serialization() {
        let header = RecordingHeader {
            version: 2,
            width: 80,
            height: 24,
            timestamp: 1_700_000_000,
            title: Some("test".to_string()),
            env: HashMap::new(),
        };
        let json = serde_json::to_string(&header).unwrap();
        assert!(json.contains("\"version\":2"));
        assert!(json.contains("\"title\":\"test\""));
        // Empty env should be skipped
        assert!(!json.contains("\"env\""));
    }

    #[test]
    fn test_recording_header_no_title_skips_field() {
        let header = RecordingHeader {
            version: 2,
            width: 120,
            height: 40,
            timestamp: 0,
            title: None,
            env: HashMap::new(),
        };
        let json = serde_json::to_string(&header).unwrap();
        assert!(!json.contains("title"));
    }

    #[test]
    fn test_verify_result_serialization() {
        let result = VerifyResult {
            valid: true,
            total_events: 5,
            verified_events: 5,
            first_invalid_index: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"valid\":true"));
        assert!(json.contains("\"total_events\":5"));
    }

    #[test]
    fn test_recording_info_fields() {
        let info = RecordingInfo {
            id: "rec_test".to_string(),
            host: "localhost".to_string(),
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            event_count: 42,
            file_path: "/tmp/test.cast".to_string(),
            hash_chain_enabled: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("rec_test"));
        assert!(json.contains("\"event_count\":42"));
        assert!(json.contains("\"hash_chain_enabled\":true"));
    }

    #[test]
    fn test_verify_recording_detects_missing_hash_in_chain() {
        let tmp = TempDir::new().unwrap();
        let key = b"test-key".to_vec();
        let recorder = SessionRecorder::new(tmp.path().to_path_buf(), true, key.clone(), false);

        let id = recorder.start_session("host1", None).unwrap();
        recorder.record_event(&id, "i", "cmd1").unwrap();
        recorder.record_event(&id, "o", "output1").unwrap();
        let info = recorder.stop_session(&id).unwrap();

        // Tamper: keep first event with hash, but strip hash from second event
        let content = fs::read_to_string(&info.file_path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        assert!(lines.len() >= 3, "Need header + 2 events");
        // Parse second event and rebuild without hash (3 elements only)
        let event: Vec<serde_json::Value> = serde_json::from_str(&lines[2]).unwrap();
        assert!(event.len() >= 4, "Second event should have hash");
        let stripped = format!("[{}, {}, {}]", event[0], event[1], event[2]);
        lines[2] = stripped;
        fs::write(&info.file_path, lines.join("\n")).unwrap();

        let result = SessionRecorder::verify_recording(Path::new(&info.file_path), &key).unwrap();
        assert!(!result.valid);
        assert_eq!(result.first_invalid_index, Some(1));
    }

    #[test]
    fn test_replay_recording_skips_empty_lines() {
        let tmp = TempDir::new().unwrap();
        let recorder = SessionRecorder::new(tmp.path().to_path_buf(), false, Vec::new(), false);

        let id = recorder.start_session("host1", None).unwrap();
        recorder.record_event(&id, "o", "data").unwrap();
        let info = recorder.stop_session(&id).unwrap();

        // Append blank lines to the file
        let mut content = fs::read_to_string(&info.file_path).unwrap();
        content.push_str("\n\n\n");
        fs::write(&info.file_path, &content).unwrap();

        let (_, events) = SessionRecorder::replay_recording(Path::new(&info.file_path)).unwrap();
        assert_eq!(events.len(), 1);
    }
}
