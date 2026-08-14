//! SFTP Client for large file transfers
//!
//! This module provides SFTP-based file transfers using russh-sftp,
//! with streaming I/O for unlimited file sizes.

use std::io::SeekFrom;
use std::path::Path;

use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter};

use crate::error::{BridgeError, Result};

/// Validate that a path doesn't contain path traversal components.
fn validate_remote_path(path: &str) -> Result<()> {
    if path.split('/').any(|component| component == "..") {
        return Err(BridgeError::FileTransfer {
            reason: "Path traversal ('..') is not allowed in remote paths".to_string(),
        });
    }
    Ok(())
}

/// Default chunk size for streaming transfers (1 MB)
pub const DEFAULT_CHUNK_SIZE: u64 = 1024 * 1024;

/// Smallest chunk size a transfer will actually use (4 KB).
///
/// A zero chunk size used to make the copy loop exit immediately *after* the
/// remote handle had been opened with `TRUNCATE`, which emptied the remote file
/// and still reported success; `write_bytes` looped forever on it.
pub const MIN_CHUNK_SIZE: u64 = 4096;

/// Largest chunk size a transfer will actually use (64 MB).
///
/// The chunk size is used as a `Vec` allocation length; an unbounded value from
/// the request aborts the process through `handle_alloc_error`.
pub const MAX_CHUNK_SIZE: u64 = 64 * 1024 * 1024;

const _: () = {
    assert!(MIN_CHUNK_SIZE > 0);
    assert!(MIN_CHUNK_SIZE <= DEFAULT_CHUNK_SIZE);
    assert!(DEFAULT_CHUNK_SIZE <= MAX_CHUNK_SIZE);
    // A clamped chunk always fits a `usize` allocation, 32-bit targets included.
    assert!(MAX_CHUNK_SIZE <= u32::MAX as u64);
};

/// Clamp a caller-supplied chunk size into `MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE`.
///
/// Applied at every point of use rather than at construction, so all callers
/// (MCP handlers, CLI runner, future ones) are covered by one check.
#[must_use]
pub const fn clamp_chunk_size(chunk_size: u64) -> u64 {
    // `u64::clamp` is not const-stable in this MSRV.
    if chunk_size < MIN_CHUNK_SIZE {
        MIN_CHUNK_SIZE
    } else if chunk_size > MAX_CHUNK_SIZE {
        MAX_CHUNK_SIZE
    } else {
        chunk_size
    }
}

/// Transfer mode for file operations
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferMode {
    /// Overwrite the destination file (default)
    #[default]
    Overwrite,
    /// Append to the destination file
    Append,
    /// Resume an interrupted transfer
    Resume,
    /// Fail if the destination file exists
    FailIfExists,
}

impl TransferMode {
    /// Parse a transfer mode from a string
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "overwrite" => Some(Self::Overwrite),
            "append" => Some(Self::Append),
            "resume" => Some(Self::Resume),
            "fail_if_exists" | "fail-if-exists" => Some(Self::FailIfExists),
            _ => None,
        }
    }
}

/// Options for file transfers
#[derive(Debug, Clone)]
pub struct TransferOptions {
    /// Transfer mode
    pub mode: TransferMode,
    /// Chunk size for streaming (bytes)
    pub chunk_size: u64,
    /// Verify checksum after transfer
    pub verify_checksum: bool,
    /// Preserve file permissions
    pub preserve_permissions: bool,
}

impl TransferOptions {
    /// The chunk size actually used, clamped to a safe allocation range.
    ///
    /// See [`clamp_chunk_size`]; `chunk_size` itself is caller-supplied and
    /// deliberately left untouched so the request stays inspectable.
    #[must_use]
    pub const fn effective_chunk_size(&self) -> u64 {
        clamp_chunk_size(self.chunk_size)
    }
}

impl Default for TransferOptions {
    fn default() -> Self {
        Self {
            mode: TransferMode::default(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            verify_checksum: false,
            preserve_permissions: true,
        }
    }
}

/// Progress information during transfer
#[derive(Debug, Clone, Copy)]
pub struct TransferProgress {
    /// Bytes transferred so far
    pub bytes_transferred: u64,
    /// Total bytes to transfer
    pub total_bytes: u64,
    /// Progress percentage (0.0 - 100.0)
    pub percentage: f64,
}

/// Result of a file transfer
#[derive(Debug, Clone)]
pub struct TransferResult {
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Transfer rate in bytes per second
    pub bytes_per_second: f64,
    /// SHA256 checksum if verification was enabled
    pub checksum: Option<String>,
}

/// Entry in a remote directory listing
#[derive(Debug, Clone, Serialize)]
pub struct RemoteDirEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub permissions: Option<u32>,
}

/// Result of a directory transfer operation
#[derive(Debug, Clone, Serialize)]
pub struct DirectoryTransferResult {
    pub files_transferred: u64,
    pub bytes_transferred: u64,
    pub directories_created: u64,
    pub errors: Vec<String>,
    pub duration_ms: u64,
}

/// SFTP client wrapper for file transfers
pub struct SftpClient {
    session: SftpSession,
}

impl SftpClient {
    /// Create a new SFTP client from a session
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // SftpSession is not const-compatible
    pub fn new(session: SftpSession) -> Self {
        Self { session }
    }

    /// Upload a file to the remote host
    ///
    /// # Arguments
    /// * `local_path` - Path to the local file
    /// * `remote_path` - Destination path on the remote host
    /// * `options` - Transfer options
    /// * `progress_callback` - Optional callback for progress updates
    ///
    /// # Errors
    /// Returns an error if the transfer fails
    #[expect(
        clippy::too_many_lines,
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss
    )]
    pub async fn upload_file<F>(
        &self,
        local_path: &Path,
        remote_path: &str,
        options: &TransferOptions,
        mut progress_callback: Option<F>,
    ) -> Result<TransferResult>
    where
        F: FnMut(TransferProgress),
    {
        let start = std::time::Instant::now();
        validate_remote_path(remote_path)?;

        // Open local file and get metadata
        let local_file = File::open(local_path)
            .await
            .map_err(|e| BridgeError::FileTransfer {
                reason: format!("Cannot open local file: {e}"),
            })?;

        let metadata = local_file
            .metadata()
            .await
            .map_err(|e| BridgeError::FileTransfer {
                reason: format!("Cannot read file metadata: {e}"),
            })?;

        let file_size = metadata.len();

        // Determine starting offset for resume mode
        let start_offset = if options.mode == TransferMode::Resume {
            self.get_remote_file_size(remote_path).await.unwrap_or(0)
        } else {
            0
        };

        // Check if file already exists for FailIfExists mode
        if options.mode == TransferMode::FailIfExists
            && self
                .session
                .try_exists(remote_path)
                .await
                .map_err(sftp_error)?
        {
            return Err(BridgeError::FileTransfer {
                reason: format!("Remote file already exists: {remote_path}"),
            });
        }

        // Determine open flags based on mode
        let flags = match options.mode {
            TransferMode::Overwrite => OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            TransferMode::Append | TransferMode::Resume => {
                OpenFlags::CREATE | OpenFlags::APPEND | OpenFlags::WRITE
            }
            TransferMode::FailIfExists => OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
        };

        // Get local file permissions if needed
        let attrs = if options.preserve_permissions {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                let mut attrs = FileAttributes::empty();
                attrs.permissions = Some(mode);
                attrs
            }
            #[cfg(not(unix))]
            {
                FileAttributes::empty()
            }
        } else {
            FileAttributes::empty()
        };

        // Open remote file
        let mut remote_file = self
            .session
            .open_with_flags_and_attributes(remote_path, flags, attrs)
            .await
            .map_err(sftp_error)?;

        // Setup local file reader
        let mut local_file =
            File::open(local_path)
                .await
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Cannot open local file: {e}"),
                })?;

        // Seek to start offset for resume
        if start_offset > 0 {
            local_file
                .seek(SeekFrom::Start(start_offset))
                .await
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Cannot seek local file: {e}"),
                })?;
        }

        let chunk_size = options.effective_chunk_size() as usize;
        let mut reader = BufReader::with_capacity(chunk_size, local_file);
        let mut buffer = vec![0u8; chunk_size];
        let mut total_written = start_offset;

        // Note: Checksum is disabled for Resume/Append modes because we can only hash
        // the data being transferred, not the complete file on the remote server.
        // For Resume: the checksum would only cover the resumed portion
        // For Append: the remote file contains previous data we don't have access to
        let can_compute_full_checksum =
            options.mode == TransferMode::Overwrite || options.mode == TransferMode::FailIfExists;
        let mut hasher = if options.verify_checksum && can_compute_full_checksum {
            Some(Sha256::new())
        } else {
            None
        };

        // Stream the file
        loop {
            let n = reader
                .read(&mut buffer)
                .await
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Read error: {e}"),
                })?;

            if n == 0 {
                break;
            }

            let data = &buffer[..n];

            // Update checksum
            if let Some(ref mut h) = hasher {
                h.update(data);
            }

            // Write to remote
            remote_file
                .write_all(data)
                .await
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Write error: {e}"),
                })?;

            total_written += n as u64;

            // Progress callback
            if let Some(ref mut callback) = progress_callback {
                callback(TransferProgress {
                    bytes_transferred: total_written,
                    total_bytes: file_size,
                    percentage: if file_size > 0 {
                        (total_written as f64 / file_size as f64) * 100.0
                    } else {
                        100.0
                    },
                });
            }
        }

        // Ensure data is flushed
        remote_file
            .flush()
            .await
            .map_err(|e| BridgeError::FileTransfer {
                reason: format!("Flush error: {e}"),
            })?;

        // Close the remote file properly
        remote_file
            .shutdown()
            .await
            .map_err(|e| BridgeError::FileTransfer {
                reason: format!("Close error: {e}"),
            })?;

        let duration_ms = start.elapsed().as_millis() as u64;
        let bytes_transferred = total_written - start_offset;
        let bytes_per_second = if duration_ms > 0 {
            (bytes_transferred as f64 / duration_ms as f64) * 1000.0
        } else {
            0.0
        };

        let checksum = hasher.map(|h| const_hex::encode(h.finalize()));

        // Note: Checksum verification would require executing a command on the remote host
        // This is better handled at the handler level where we have SSH command execution

        Ok(TransferResult {
            bytes_transferred,
            duration_ms,
            bytes_per_second,
            checksum,
        })
    }

    /// Download a file from the remote host
    ///
    /// # Arguments
    /// * `remote_path` - Path to the remote file
    /// * `local_path` - Destination path on the local machine
    /// * `options` - Transfer options
    /// * `progress_callback` - Optional callback for progress updates
    ///
    /// # Errors
    /// Returns an error if the transfer fails
    #[expect(
        clippy::too_many_lines,
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss
    )]
    pub async fn download_file<F>(
        &self,
        remote_path: &str,
        local_path: &Path,
        options: &TransferOptions,
        mut progress_callback: Option<F>,
    ) -> Result<TransferResult>
    where
        F: FnMut(TransferProgress),
    {
        let start = std::time::Instant::now();
        validate_remote_path(remote_path)?;

        // Get remote file metadata
        let remote_metadata = self
            .session
            .metadata(remote_path)
            .await
            .map_err(sftp_error)?;

        let file_size = remote_metadata
            .size
            .ok_or_else(|| BridgeError::FileTransfer {
                reason: "Cannot determine remote file size".to_string(),
            })?;

        // Determine starting offset for resume mode
        let start_offset = if options.mode == TransferMode::Resume {
            if local_path.exists() {
                std::fs::metadata(local_path).map_or(0, |m| m.len())
            } else {
                0
            }
        } else {
            0
        };

        // Check if local file already exists for FailIfExists mode
        if options.mode == TransferMode::FailIfExists && local_path.exists() {
            return Err(BridgeError::FileTransfer {
                reason: format!("Local file already exists: {}", local_path.display()),
            });
        }

        // Open remote file for reading
        let mut remote_file = self.session.open(remote_path).await.map_err(sftp_error)?;

        // Seek remote file for resume
        if start_offset > 0 {
            remote_file
                .seek(SeekFrom::Start(start_offset))
                .await
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Cannot seek remote file: {e}"),
                })?;
        }

        // Open local file with appropriate mode
        let local_file = match options.mode {
            TransferMode::Overwrite => {
                File::create(local_path)
                    .await
                    .map_err(|e| BridgeError::FileTransfer {
                        reason: format!("Cannot create local file: {e}"),
                    })?
            }
            TransferMode::Append | TransferMode::Resume => tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(local_path)
                .await
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Cannot open local file: {e}"),
                })?,
            TransferMode::FailIfExists => tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(local_path)
                .await
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Cannot create local file: {e}"),
                })?,
        };

        let chunk_size = options.effective_chunk_size() as usize;
        let mut writer = BufWriter::with_capacity(chunk_size, local_file);
        let mut buffer = vec![0u8; chunk_size];
        let mut total_read = start_offset;

        // Note: Checksum is disabled for Resume/Append modes because we can only hash
        // the data being transferred, not the complete file.
        let can_compute_full_checksum =
            options.mode == TransferMode::Overwrite || options.mode == TransferMode::FailIfExists;
        let mut hasher = if options.verify_checksum && can_compute_full_checksum {
            Some(Sha256::new())
        } else {
            None
        };

        // Stream the file
        loop {
            let n = remote_file
                .read(&mut buffer)
                .await
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Read error: {e}"),
                })?;

            if n == 0 {
                break;
            }

            let data = &buffer[..n];

            // Update checksum
            if let Some(ref mut h) = hasher {
                h.update(data);
            }

            // Write to local
            writer
                .write_all(data)
                .await
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Write error: {e}"),
                })?;

            total_read += n as u64;

            // Progress callback
            if let Some(ref mut callback) = progress_callback {
                callback(TransferProgress {
                    bytes_transferred: total_read,
                    total_bytes: file_size,
                    percentage: if file_size > 0 {
                        (total_read as f64 / file_size as f64) * 100.0
                    } else {
                        100.0
                    },
                });
            }
        }

        // Ensure data is flushed
        writer
            .flush()
            .await
            .map_err(|e| BridgeError::FileTransfer {
                reason: format!("Flush error: {e}"),
            })?;

        // Preserve permissions if requested
        if options.preserve_permissions {
            #[cfg(unix)]
            if let Some(permissions) = remote_metadata.permissions {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(permissions);
                std::fs::set_permissions(local_path, perms).ok();
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        let bytes_transferred = total_read - start_offset;
        let bytes_per_second = if duration_ms > 0 {
            (bytes_transferred as f64 / duration_ms as f64) * 1000.0
        } else {
            0.0
        };

        let checksum = hasher.map(|h| const_hex::encode(h.finalize()));

        Ok(TransferResult {
            bytes_transferred,
            duration_ms,
            bytes_per_second,
            checksum,
        })
    }

    /// List entries in a remote directory
    ///
    /// # Errors
    /// Returns an error if the directory cannot be read.
    pub async fn read_dir(&self, path: &str) -> Result<Vec<RemoteDirEntry>> {
        validate_remote_path(path)?;
        let entries = self.session.read_dir(path).await.map_err(sftp_error)?;

        let mut result = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            let metadata = entry.metadata();
            let is_dir = entry.file_type().is_dir();
            result.push(RemoteDirEntry {
                path: format!("{path}/{name}"),
                name,
                is_dir,
                size: metadata.size,
                permissions: metadata.permissions,
            });
        }

        Ok(result)
    }

    /// Create a directory and all parent directories on the remote host
    ///
    /// # Errors
    /// Returns an error if a directory cannot be created and does not already exist.
    pub async fn mkdir_recursive(&self, path: &str) -> Result<()> {
        validate_remote_path(path)?;
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let mut current = String::new();

        // Preserve leading slash for absolute paths
        if path.starts_with('/') {
            current.push('/');
        }

        for (i, component) in components.iter().enumerate() {
            if (i > 0 || !path.starts_with('/')) && !current.is_empty() && !current.ends_with('/') {
                current.push('/');
            }
            current.push_str(component);

            // Try to create the directory, ignoring errors for existing dirs
            if let Err(_e) = self.session.create_dir(current.as_str()).await {
                // Check if it already exists; if not, propagate the error
                if !self
                    .session
                    .try_exists(current.as_str())
                    .await
                    .map_err(sftp_error)?
                {
                    return Err(BridgeError::FileTransfer {
                        reason: format!("Cannot create remote directory: {current}"),
                    });
                }
            }
        }

        Ok(())
    }

    /// Recursively upload a local directory to a remote path
    ///
    /// Uses a stack-based iterative approach to avoid deep recursion.
    ///
    /// # Errors
    /// Returns an error if the local directory cannot be read or if the transfer fails.
    #[expect(clippy::cast_possible_truncation)]
    pub async fn upload_directory(
        &self,
        local_path: &Path,
        remote_path: &str,
        exclude: &[String],
    ) -> Result<DirectoryTransferResult> {
        let start = std::time::Instant::now();
        validate_remote_path(remote_path)?;
        let mut files_transferred: u64 = 0;
        let mut bytes_transferred: u64 = 0;
        let mut directories_created: u64 = 0;
        let mut errors: Vec<String> = Vec::new();

        // Create the root remote directory
        self.mkdir_recursive(remote_path).await?;
        directories_created += 1;

        // Stack of (local_dir, remote_dir)
        let mut stack: Vec<(std::path::PathBuf, String)> =
            vec![(local_path.to_path_buf(), remote_path.to_string())];

        while let Some((local_dir, remote_dir)) = stack.pop() {
            let read_dir =
                std::fs::read_dir(&local_dir).map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Cannot read local directory {}: {e}", local_dir.display()),
                })?;

            for entry_result in read_dir {
                let entry = match entry_result {
                    Ok(e) => e,
                    Err(e) => {
                        errors.push(format!(
                            "Error reading entry in {}: {e}",
                            local_dir.display()
                        ));
                        continue;
                    }
                };

                let entry_path = entry.path();
                let file_name = entry.file_name().to_string_lossy().to_string();

                // Check exclude patterns (simple contains check)
                if exclude
                    .iter()
                    .any(|pat| entry_path.to_string_lossy().contains(pat.as_str()))
                {
                    continue;
                }

                let remote_entry_path = format!("{remote_dir}/{file_name}");

                let file_type = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(e) => {
                        errors.push(format!(
                            "Cannot read file type for {}: {e}",
                            entry_path.display()
                        ));
                        continue;
                    }
                };

                if file_type.is_dir() {
                    // Create remote directory and push to stack
                    if let Err(e) = self.mkdir_recursive(&remote_entry_path).await {
                        errors.push(format!(
                            "Cannot create remote directory {remote_entry_path}: {e}"
                        ));
                        continue;
                    }
                    directories_created += 1;
                    stack.push((entry_path, remote_entry_path));
                } else if file_type.is_file() {
                    let options = TransferOptions::default();
                    match self
                        .upload_file::<fn(TransferProgress)>(
                            &entry_path,
                            &remote_entry_path,
                            &options,
                            None,
                        )
                        .await
                    {
                        Ok(result) => {
                            files_transferred += 1;
                            bytes_transferred += result.bytes_transferred;
                        }
                        Err(e) => {
                            errors.push(format!("Failed to upload {}: {e}", entry_path.display()));
                        }
                    }
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(DirectoryTransferResult {
            files_transferred,
            bytes_transferred,
            directories_created,
            errors,
            duration_ms,
        })
    }

    /// Recursively download a remote directory to a local path
    ///
    /// Uses a stack-based iterative approach to avoid deep recursion.
    ///
    /// # Errors
    /// Returns an error if the remote directory cannot be read or if the transfer fails.
    #[expect(clippy::cast_possible_truncation)]
    pub async fn download_directory(
        &self,
        remote_path: &str,
        local_path: &Path,
        exclude: &[String],
    ) -> Result<DirectoryTransferResult> {
        let start = std::time::Instant::now();
        validate_remote_path(remote_path)?;
        let mut files_transferred: u64 = 0;
        let mut bytes_transferred: u64 = 0;
        let mut directories_created: u64 = 0;
        let mut errors: Vec<String> = Vec::new();

        // Create the root local directory
        std::fs::create_dir_all(local_path).map_err(|e| BridgeError::FileTransfer {
            reason: format!(
                "Cannot create local directory {}: {e}",
                local_path.display()
            ),
        })?;
        directories_created += 1;

        // Stack of (remote_dir, local_dir)
        let mut stack: Vec<(String, std::path::PathBuf)> =
            vec![(remote_path.to_string(), local_path.to_path_buf())];

        while let Some((remote_dir, local_dir)) = stack.pop() {
            let entries = self.read_dir(&remote_dir).await?;

            for entry in entries {
                // Check exclude patterns (simple contains check)
                if exclude.iter().any(|pat| entry.path.contains(pat.as_str())) {
                    continue;
                }

                let local_entry_path = local_dir.join(&entry.name);

                if entry.is_dir {
                    // Create local directory and push to stack
                    if let Err(e) = std::fs::create_dir_all(&local_entry_path) {
                        errors.push(format!(
                            "Cannot create local directory {}: {e}",
                            local_entry_path.display()
                        ));
                        continue;
                    }
                    directories_created += 1;
                    stack.push((entry.path, local_entry_path));
                } else {
                    let options = TransferOptions::default();
                    match self
                        .download_file::<fn(TransferProgress)>(
                            &entry.path,
                            &local_entry_path,
                            &options,
                            None,
                        )
                        .await
                    {
                        Ok(result) => {
                            files_transferred += 1;
                            bytes_transferred += result.bytes_transferred;
                        }
                        Err(e) => {
                            errors.push(format!("Failed to download {}: {e}", entry.path));
                        }
                    }
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(DirectoryTransferResult {
            files_transferred,
            bytes_transferred,
            directories_created,
            errors,
            duration_ms,
        })
    }

    /// Write in-memory bytes to a remote file via SFTP.
    ///
    /// Unlike [`upload_file`](Self::upload_file), this method writes directly from a byte
    /// slice without requiring a local file. Designed for `ssh_file_write` when content
    /// exceeds the shell argument size limit.
    ///
    /// # Errors
    ///
    /// Returns an error if the remote path contains traversal components or the
    /// SFTP write fails.
    #[expect(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    pub async fn write_bytes(
        &self,
        data: &[u8],
        remote_path: &str,
        append: bool,
        chunk_size: u64,
    ) -> Result<TransferResult> {
        let start = std::time::Instant::now();
        validate_remote_path(remote_path)?;

        let flags = if append {
            OpenFlags::CREATE | OpenFlags::APPEND | OpenFlags::WRITE
        } else {
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE
        };

        let mut remote_file = self
            .session
            .open_with_flags_and_attributes(remote_path, flags, FileAttributes::empty())
            .await
            .map_err(sftp_error)?;

        // Clamped: a zero chunk made this loop spin forever.
        let chunk = clamp_chunk_size(chunk_size) as usize;
        let mut offset = 0;

        while offset < data.len() {
            let end = (offset + chunk).min(data.len());
            remote_file
                .write_all(&data[offset..end])
                .await
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Write error: {e}"),
                })?;
            offset = end;
        }

        remote_file
            .flush()
            .await
            .map_err(|e| BridgeError::FileTransfer {
                reason: format!("Flush error: {e}"),
            })?;

        remote_file
            .shutdown()
            .await
            .map_err(|e| BridgeError::FileTransfer {
                reason: format!("Close error: {e}"),
            })?;

        let duration_ms = start.elapsed().as_millis() as u64;
        let bytes_transferred = data.len() as u64;
        let bytes_per_second = if duration_ms > 0 {
            (bytes_transferred as f64 / duration_ms as f64) * 1000.0
        } else {
            0.0
        };

        Ok(TransferResult {
            bytes_transferred,
            duration_ms,
            bytes_per_second,
            checksum: None,
        })
    }

    /// Get the size of a remote file
    async fn get_remote_file_size(&self, path: &str) -> Option<u64> {
        self.session.metadata(path).await.ok().and_then(|m| m.size)
    }

    /// Close the SFTP session
    ///
    /// # Errors
    ///
    /// Returns an error if the SFTP session cannot be closed cleanly.
    pub async fn close(self) -> Result<()> {
        self.session.close().await.map_err(sftp_error)
    }
}

/// Convert an SFTP error to a `BridgeError`
#[expect(clippy::needless_pass_by_value)]
fn sftp_error(e: russh_sftp::client::error::Error) -> BridgeError {
    BridgeError::Sftp {
        reason: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_mode_parse() {
        assert_eq!(
            TransferMode::parse("overwrite"),
            Some(TransferMode::Overwrite)
        );
        assert_eq!(TransferMode::parse("append"), Some(TransferMode::Append));
        assert_eq!(TransferMode::parse("resume"), Some(TransferMode::Resume));
        assert_eq!(
            TransferMode::parse("fail_if_exists"),
            Some(TransferMode::FailIfExists)
        );
        assert_eq!(
            TransferMode::parse("fail-if-exists"),
            Some(TransferMode::FailIfExists)
        );
        assert_eq!(
            TransferMode::parse("OVERWRITE"),
            Some(TransferMode::Overwrite)
        );
        assert_eq!(TransferMode::parse("invalid"), None);
    }

    #[test]
    fn test_transfer_mode_parse_mixed_case() {
        assert_eq!(
            TransferMode::parse("Overwrite"),
            Some(TransferMode::Overwrite)
        );
        assert_eq!(TransferMode::parse("APPEND"), Some(TransferMode::Append));
        assert_eq!(TransferMode::parse("Resume"), Some(TransferMode::Resume));
        assert_eq!(
            TransferMode::parse("FAIL_IF_EXISTS"),
            Some(TransferMode::FailIfExists)
        );
        assert_eq!(
            TransferMode::parse("Fail-If-Exists"),
            Some(TransferMode::FailIfExists)
        );
    }

    #[test]
    fn test_transfer_mode_parse_empty_and_whitespace() {
        assert_eq!(TransferMode::parse(""), None);
        assert_eq!(TransferMode::parse(" "), None);
        assert_eq!(TransferMode::parse("  overwrite  "), None); // No trim
    }

    #[test]
    fn test_transfer_mode_default() {
        let mode = TransferMode::default();
        assert_eq!(mode, TransferMode::Overwrite);
    }

    #[test]
    fn test_transfer_mode_serialization() {
        let modes = [
            (TransferMode::Overwrite, "\"overwrite\""),
            (TransferMode::Append, "\"append\""),
            (TransferMode::Resume, "\"resume\""),
            (TransferMode::FailIfExists, "\"fail_if_exists\""),
        ];

        for (mode, expected) in modes {
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn test_transfer_mode_deserialization() {
        let test_cases = [
            ("\"overwrite\"", TransferMode::Overwrite),
            ("\"append\"", TransferMode::Append),
            ("\"resume\"", TransferMode::Resume),
            ("\"fail_if_exists\"", TransferMode::FailIfExists),
        ];

        for (json, expected) in test_cases {
            let mode: TransferMode = serde_json::from_str(json).unwrap();
            assert_eq!(mode, expected);
        }
    }

    #[test]
    fn test_transfer_options_default() {
        let options = TransferOptions::default();
        assert_eq!(options.mode, TransferMode::Overwrite);
        assert_eq!(options.chunk_size, DEFAULT_CHUNK_SIZE);
        assert!(!options.verify_checksum);
        assert!(options.preserve_permissions);
    }

    #[test]
    fn test_transfer_options_custom() {
        let options = TransferOptions {
            mode: TransferMode::Resume,
            chunk_size: 512 * 1024,
            verify_checksum: true,
            preserve_permissions: false,
        };
        assert_eq!(options.mode, TransferMode::Resume);
        assert_eq!(options.chunk_size, 512 * 1024);
        assert!(options.verify_checksum);
        assert!(!options.preserve_permissions);
    }

    #[test]
    fn test_transfer_progress() {
        let progress = TransferProgress {
            bytes_transferred: 500,
            total_bytes: 1000,
            percentage: 50.0,
        };
        assert_eq!(progress.bytes_transferred, 500);
        assert_eq!(progress.total_bytes, 1000);
        assert!((progress.percentage - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_transfer_progress_edge_cases() {
        // Empty file (0 bytes)
        let empty = TransferProgress {
            bytes_transferred: 0,
            total_bytes: 0,
            percentage: 100.0, // Should be 100% for empty files
        };
        assert_eq!(empty.bytes_transferred, 0);
        assert!((empty.percentage - 100.0).abs() < f64::EPSILON);

        // Just started
        let start = TransferProgress {
            bytes_transferred: 0,
            total_bytes: 1000,
            percentage: 0.0,
        };
        assert!((start.percentage - 0.0).abs() < f64::EPSILON);

        // Completed
        let complete = TransferProgress {
            bytes_transferred: 1000,
            total_bytes: 1000,
            percentage: 100.0,
        };
        assert!((complete.percentage - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_transfer_progress_large_file() {
        // 10 GB file
        let progress = TransferProgress {
            bytes_transferred: 5_000_000_000,
            total_bytes: 10_000_000_000,
            percentage: 50.0,
        };
        assert_eq!(progress.bytes_transferred, 5_000_000_000);
        assert_eq!(progress.total_bytes, 10_000_000_000);
    }

    #[test]
    fn test_transfer_result() {
        let result = TransferResult {
            bytes_transferred: 1024 * 1024, // 1 MB
            duration_ms: 1000,              // 1 second
            bytes_per_second: 1024.0 * 1024.0,
            checksum: Some("abc123".to_string()),
        };

        assert_eq!(result.bytes_transferred, 1024 * 1024);
        assert_eq!(result.duration_ms, 1000);
        assert!((result.bytes_per_second - 1024.0 * 1024.0).abs() < 1.0);
        assert_eq!(result.checksum, Some("abc123".to_string()));
    }

    #[test]
    fn test_transfer_result_no_checksum() {
        let result = TransferResult {
            bytes_transferred: 500,
            duration_ms: 10,
            bytes_per_second: 50000.0,
            checksum: None,
        };

        assert!(result.checksum.is_none());
    }

    #[test]
    fn test_transfer_result_zero_duration() {
        // Instant transfer (less than 1ms)
        let result = TransferResult {
            bytes_transferred: 100,
            duration_ms: 0,
            bytes_per_second: 0.0, // Can't calculate rate with 0 duration
            checksum: None,
        };

        assert_eq!(result.duration_ms, 0);
        assert!((result.bytes_per_second - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_default_chunk_size() {
        assert_eq!(DEFAULT_CHUNK_SIZE, 1024 * 1024); // 1 MB
    }

    #[test]
    fn test_transfer_mode_equality() {
        assert_eq!(TransferMode::Overwrite, TransferMode::Overwrite);
        assert_eq!(TransferMode::Append, TransferMode::Append);
        assert_eq!(TransferMode::Resume, TransferMode::Resume);
        assert_eq!(TransferMode::FailIfExists, TransferMode::FailIfExists);

        assert_ne!(TransferMode::Overwrite, TransferMode::Append);
        assert_ne!(TransferMode::Resume, TransferMode::FailIfExists);
    }

    #[test]
    fn test_transfer_mode_clone() {
        let mode = TransferMode::Resume;
        let cloned = mode;
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_transfer_options_clone() {
        let options = TransferOptions {
            mode: TransferMode::Append,
            chunk_size: 2048,
            verify_checksum: true,
            preserve_permissions: false,
        };
        let cloned = options.clone();
        assert_eq!(options.mode, cloned.mode);
        assert_eq!(options.chunk_size, cloned.chunk_size);
        assert_eq!(options.verify_checksum, cloned.verify_checksum);
        assert_eq!(options.preserve_permissions, cloned.preserve_permissions);
    }

    #[test]
    fn test_transfer_progress_clone() {
        let progress = TransferProgress {
            bytes_transferred: 100,
            total_bytes: 200,
            percentage: 50.0,
        };
        let cloned = progress;
        assert_eq!(progress.bytes_transferred, cloned.bytes_transferred);
        assert_eq!(progress.total_bytes, cloned.total_bytes);
    }

    #[test]
    fn test_transfer_result_clone() {
        let result = TransferResult {
            bytes_transferred: 1000,
            duration_ms: 100,
            bytes_per_second: 10000.0,
            checksum: Some("hash".to_string()),
        };
        let cloned = result.clone();
        assert_eq!(result.bytes_transferred, cloned.bytes_transferred);
        assert_eq!(result.checksum, cloned.checksum);
    }

    #[test]
    fn test_transfer_mode_debug() {
        let mode = TransferMode::FailIfExists;
        let debug_str = format!("{mode:?}");
        assert!(debug_str.contains("FailIfExists"));
    }

    #[test]
    fn test_transfer_options_debug() {
        let options = TransferOptions::default();
        let debug_str = format!("{options:?}");
        assert!(debug_str.contains("TransferOptions"));
        assert!(debug_str.contains("Overwrite"));
    }

    #[test]
    fn test_transfer_progress_debug() {
        let progress = TransferProgress {
            bytes_transferred: 100,
            total_bytes: 200,
            percentage: 50.0,
        };
        let debug_str = format!("{progress:?}");
        assert!(debug_str.contains("TransferProgress"));
    }

    #[test]
    fn test_transfer_result_debug() {
        let result = TransferResult {
            bytes_transferred: 1000,
            duration_ms: 100,
            bytes_per_second: 10000.0,
            checksum: None,
        };
        let debug_str = format!("{result:?}");
        assert!(debug_str.contains("TransferResult"));
    }

    // ============== TransferMode Additional Tests ==============

    #[test]
    fn test_transfer_mode_parse_whitespace_variants() {
        // No trimming should happen
        assert_eq!(TransferMode::parse(" overwrite"), None);
        assert_eq!(TransferMode::parse("overwrite "), None);
        assert_eq!(TransferMode::parse("\toverwrite"), None);
    }

    #[test]
    fn test_transfer_mode_parse_special_chars() {
        assert_eq!(TransferMode::parse("over-write"), None);
        assert_eq!(TransferMode::parse("over_write"), None);
        assert_eq!(TransferMode::parse("overwrite!"), None);
    }

    #[test]
    fn test_transfer_mode_parse_numbers() {
        assert_eq!(TransferMode::parse("1"), None);
        assert_eq!(TransferMode::parse("0"), None);
        assert_eq!(TransferMode::parse("123"), None);
    }

    #[test]
    fn test_transfer_mode_copy() {
        let mode1 = TransferMode::Resume;
        let mode2 = mode1; // Copy
        assert_eq!(mode1, mode2);
    }

    // ============== TransferOptions Edge Cases ==============

    #[test]
    fn test_transfer_options_minimal_chunk() {
        let options = TransferOptions {
            mode: TransferMode::Overwrite,
            chunk_size: 1, // 1 byte
            verify_checksum: false,
            preserve_permissions: false,
        };
        assert_eq!(options.chunk_size, 1);
    }

    #[test]
    fn test_transfer_options_large_chunk() {
        let options = TransferOptions {
            mode: TransferMode::Overwrite,
            chunk_size: u64::MAX,
            verify_checksum: true,
            preserve_permissions: true,
        };
        assert_eq!(options.chunk_size, u64::MAX);
    }

    #[test]
    fn test_transfer_options_all_modes() {
        for mode in [
            TransferMode::Overwrite,
            TransferMode::Append,
            TransferMode::Resume,
            TransferMode::FailIfExists,
        ] {
            let options = TransferOptions {
                mode,
                chunk_size: DEFAULT_CHUNK_SIZE,
                verify_checksum: false,
                preserve_permissions: true,
            };
            assert_eq!(options.mode, mode);
        }
    }

    // ============== TransferProgress Edge Cases ==============

    #[test]
    fn test_transfer_progress_exact_half() {
        let progress = TransferProgress {
            bytes_transferred: 500,
            total_bytes: 1000,
            percentage: 50.0,
        };
        assert!((progress.percentage - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_transfer_progress_max_values() {
        let progress = TransferProgress {
            bytes_transferred: u64::MAX,
            total_bytes: u64::MAX,
            percentage: 100.0,
        };
        assert_eq!(progress.bytes_transferred, u64::MAX);
        assert_eq!(progress.total_bytes, u64::MAX);
    }

    #[test]
    fn test_transfer_progress_negative_percentage() {
        // This shouldn't happen in practice but tests the struct handling
        let progress = TransferProgress {
            bytes_transferred: 0,
            total_bytes: 100,
            percentage: -1.0, // Invalid but struct allows it
        };
        assert!(progress.percentage < 0.0);
    }

    #[test]
    fn test_transfer_progress_over_100_percent() {
        // Possible if bytes_transferred > total_bytes (shouldn't happen)
        let progress = TransferProgress {
            bytes_transferred: 150,
            total_bytes: 100,
            percentage: 150.0,
        };
        assert!(progress.percentage > 100.0);
    }

    // ============== TransferResult Edge Cases ==============

    #[test]
    fn test_transfer_result_infinite_speed() {
        let result = TransferResult {
            bytes_transferred: 1000,
            duration_ms: 0,
            bytes_per_second: f64::INFINITY,
            checksum: None,
        };
        assert!(result.bytes_per_second.is_infinite());
    }

    #[test]
    fn test_transfer_result_nan_speed() {
        let result = TransferResult {
            bytes_transferred: 0,
            duration_ms: 0,
            bytes_per_second: f64::NAN,
            checksum: None,
        };
        assert!(result.bytes_per_second.is_nan());
    }

    #[test]
    fn test_transfer_result_long_checksum() {
        let long_checksum = "a".repeat(256);
        let result = TransferResult {
            bytes_transferred: 100,
            duration_ms: 10,
            bytes_per_second: 10000.0,
            checksum: Some(long_checksum.clone()),
        };
        assert_eq!(result.checksum.unwrap().len(), 256);
    }

    #[test]
    fn test_transfer_result_empty_checksum() {
        let result = TransferResult {
            bytes_transferred: 100,
            duration_ms: 10,
            bytes_per_second: 10000.0,
            checksum: Some(String::new()),
        };
        assert_eq!(result.checksum.unwrap(), "");
    }

    #[test]
    fn test_transfer_result_realistic_speed() {
        // 1 GB in 10 seconds = 100 MB/s
        let result = TransferResult {
            bytes_transferred: 1_073_741_824,
            duration_ms: 10_000,
            bytes_per_second: 107_374_182.4,
            checksum: None,
        };
        assert!((result.bytes_per_second - 107_374_182.4).abs() < 1.0);
    }

    // ============== DEFAULT_CHUNK_SIZE Tests ==============

    #[test]
    fn test_default_chunk_size_is_power_of_two() {
        assert!(DEFAULT_CHUNK_SIZE.is_power_of_two());
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_default_chunk_size_in_reasonable_range() {
        // Between 64KB and 16MB
        assert!(DEFAULT_CHUNK_SIZE >= 64 * 1024);
        assert!(DEFAULT_CHUNK_SIZE <= 16 * 1024 * 1024);
    }

    // ============== Serialization Round-trip Tests ==============

    #[test]
    fn test_transfer_mode_roundtrip() {
        for mode in [
            TransferMode::Overwrite,
            TransferMode::Append,
            TransferMode::Resume,
            TransferMode::FailIfExists,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let deserialized: TransferMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, deserialized);
        }
    }

    #[test]
    fn test_transfer_mode_yaml_compatibility() {
        // TransferMode uses snake_case for serialization
        let overwrite: TransferMode = serde_json::from_str("\"overwrite\"").unwrap();
        assert_eq!(overwrite, TransferMode::Overwrite);

        let fail: TransferMode = serde_json::from_str("\"fail_if_exists\"").unwrap();
        assert_eq!(fail, TransferMode::FailIfExists);
    }

    #[test]
    fn test_transfer_mode_invalid_json() {
        let result: std::result::Result<TransferMode, _> = serde_json::from_str("\"invalid_mode\"");
        assert!(result.is_err());
    }

    // ============== RemoteDirEntry Tests ==============

    #[test]
    fn test_remote_dir_entry_serialization() {
        let entry = RemoteDirEntry {
            name: "test.txt".to_string(),
            path: "/home/user/test.txt".to_string(),
            is_dir: false,
            size: Some(1024),
            permissions: Some(0o644),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("test.txt"));
        assert!(json.contains("1024"));
        assert!(json.contains("false"));
    }

    #[test]
    fn test_remote_dir_entry_with_none_fields() {
        let entry = RemoteDirEntry {
            name: "dir".to_string(),
            path: "/tmp/dir".to_string(),
            is_dir: true,
            size: None,
            permissions: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"size\":null"));
        assert!(json.contains("\"permissions\":null"));
        assert!(json.contains("\"is_dir\":true"));
    }

    #[test]
    fn test_remote_dir_entry_debug() {
        let entry = RemoteDirEntry {
            name: "file".to_string(),
            path: "/file".to_string(),
            is_dir: false,
            size: Some(0),
            permissions: Some(0o755),
        };
        let debug_str = format!("{entry:?}");
        assert!(debug_str.contains("RemoteDirEntry"));
    }

    #[test]
    fn test_remote_dir_entry_clone() {
        let entry = RemoteDirEntry {
            name: "a.txt".to_string(),
            path: "/a.txt".to_string(),
            is_dir: false,
            size: Some(42),
            permissions: None,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.name, entry.name);
        assert_eq!(cloned.size, entry.size);
    }

    // ============== DirectoryTransferResult Tests ==============

    #[test]
    fn test_directory_transfer_result_serialization() {
        let result = DirectoryTransferResult {
            files_transferred: 10,
            bytes_transferred: 1024 * 1024,
            directories_created: 3,
            errors: vec!["error1".to_string(), "error2".to_string()],
            duration_ms: 5000,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"files_transferred\":10"));
        assert!(json.contains("error1"));
        assert!(json.contains("5000"));
    }

    #[test]
    fn test_directory_transfer_result_empty() {
        let result = DirectoryTransferResult {
            files_transferred: 0,
            bytes_transferred: 0,
            directories_created: 0,
            errors: vec![],
            duration_ms: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"errors\":[]"));
    }

    #[test]
    fn test_directory_transfer_result_debug() {
        let result = DirectoryTransferResult {
            files_transferred: 1,
            bytes_transferred: 100,
            directories_created: 0,
            errors: vec![],
            duration_ms: 10,
        };
        let debug_str = format!("{result:?}");
        assert!(debug_str.contains("DirectoryTransferResult"));
    }

    #[test]
    fn test_directory_transfer_result_clone() {
        let result = DirectoryTransferResult {
            files_transferred: 5,
            bytes_transferred: 500,
            directories_created: 2,
            errors: vec!["err".to_string()],
            duration_ms: 100,
        };
        let cloned = result.clone();
        assert_eq!(cloned.files_transferred, 5);
        assert_eq!(cloned.errors.len(), 1);
    }

    #[test]
    fn test_validate_remote_path_rejects_traversal() {
        assert!(validate_remote_path("/home/../etc/passwd").is_err());
        assert!(validate_remote_path("../../../etc/shadow").is_err());
        assert!(validate_remote_path("/tmp/foo/../../etc").is_err());
    }

    #[test]
    fn test_validate_remote_path_accepts_valid() {
        assert!(validate_remote_path("/home/user/file.txt").is_ok());
        assert!(validate_remote_path("/tmp/backup").is_ok());
        assert!(validate_remote_path("relative/path/file").is_ok());
        assert!(validate_remote_path("/path/with...dots").is_ok());
    }

    // ============== validate_remote_path Additional Edge Cases ==============

    #[test]
    fn test_validate_remote_path_single_dot() {
        // Single dot (current dir) is allowed
        assert!(validate_remote_path("/home/./user").is_ok());
        assert!(validate_remote_path("./file.txt").is_ok());
    }

    #[test]
    fn test_validate_remote_path_root() {
        assert!(validate_remote_path("/").is_ok());
    }

    #[test]
    fn test_validate_remote_path_empty() {
        assert!(validate_remote_path("").is_ok());
    }

    #[test]
    fn test_validate_remote_path_only_dotdot() {
        assert!(validate_remote_path("..").is_err());
    }

    #[test]
    fn test_validate_remote_path_dotdot_at_end() {
        assert!(validate_remote_path("/home/user/..").is_err());
    }

    #[test]
    fn test_validate_remote_path_triple_dots_ok() {
        // "..." is not ".." so it should be allowed
        assert!(validate_remote_path("/home/.../file").is_ok());
    }

    #[test]
    fn test_validate_remote_path_dotdot_in_filename_ok() {
        // "..foo" is not ".." so it should be allowed
        assert!(validate_remote_path("/home/..hidden/file").is_ok());
        assert!(validate_remote_path("/home/foo../bar").is_ok());
    }

    #[test]
    fn test_validate_remote_path_error_message() {
        let err = validate_remote_path("/etc/../shadow").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("traversal"));
    }

    #[test]
    fn test_validate_remote_path_consecutive_slashes() {
        // Consecutive slashes produce empty components which are fine
        assert!(validate_remote_path("/home//user").is_ok());
    }

    #[test]
    fn test_validate_remote_path_unicode() {
        assert!(validate_remote_path("/home/用户/文件.txt").is_ok());
    }

    #[test]
    fn test_validate_remote_path_spaces() {
        assert!(validate_remote_path("/home/my folder/my file.txt").is_ok());
    }

    // ============== TransferMode Serde Additional Tests ==============

    #[test]
    fn test_transfer_mode_deserialize_wrong_type() {
        let result: std::result::Result<TransferMode, _> = serde_json::from_str("42");
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer_mode_deserialize_null() {
        let result: std::result::Result<TransferMode, _> = serde_json::from_str("null");
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer_mode_deserialize_empty_string() {
        let result: std::result::Result<TransferMode, _> = serde_json::from_str("\"\"");
        assert!(result.is_err());
    }

    // ============== TransferOptions Validation Tests ==============

    #[test]
    fn test_transfer_options_zero_chunk_size() {
        let options = TransferOptions {
            mode: TransferMode::Overwrite,
            chunk_size: 0,
            verify_checksum: false,
            preserve_permissions: false,
        };
        assert_eq!(options.chunk_size, 0);
    }

    #[test]
    fn test_transfer_options_all_flags_true() {
        let options = TransferOptions {
            mode: TransferMode::Overwrite,
            chunk_size: DEFAULT_CHUNK_SIZE,
            verify_checksum: true,
            preserve_permissions: true,
        };
        assert!(options.verify_checksum);
        assert!(options.preserve_permissions);
    }

    #[test]
    fn test_transfer_options_all_flags_false() {
        let options = TransferOptions {
            mode: TransferMode::Overwrite,
            chunk_size: DEFAULT_CHUNK_SIZE,
            verify_checksum: false,
            preserve_permissions: false,
        };
        assert!(!options.verify_checksum);
        assert!(!options.preserve_permissions);
    }

    // ============== TransferProgress Calculation Tests ==============

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn test_transfer_progress_percentage_calculation() {
        // Verify the percentage formula used in upload/download code
        let total: u64 = 1000;
        let transferred: u64 = 333;
        let percentage = if total > 0 {
            (transferred as f64 / total as f64) * 100.0
        } else {
            100.0
        };
        let progress = TransferProgress {
            bytes_transferred: transferred,
            total_bytes: total,
            percentage,
        };
        assert!((progress.percentage - 33.3).abs() < 0.1);
    }

    #[test]
    fn test_transfer_progress_zero_total_bytes_gives_100_percent() {
        // When total is 0, percentage should be 100.0 (empty file complete)
        let total: u64 = 0;
        let percentage = if total > 0 { 0.0 } else { 100.0 };
        let progress = TransferProgress {
            bytes_transferred: 0,
            total_bytes: total,
            percentage,
        };
        assert!((progress.percentage - 100.0).abs() < f64::EPSILON);
    }

    // ============== TransferResult Rate Calculation Tests ==============

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn test_transfer_result_rate_calculation() {
        // Verify the rate formula used in upload/download code
        let bytes_transferred: u64 = 10_000_000;
        let duration_ms: u64 = 2000;
        let bytes_per_second = if duration_ms > 0 {
            (bytes_transferred as f64 / duration_ms as f64) * 1000.0
        } else {
            0.0
        };
        let result = TransferResult {
            bytes_transferred,
            duration_ms,
            bytes_per_second,
            checksum: None,
        };
        assert!((result.bytes_per_second - 5_000_000.0).abs() < 1.0);
    }

    #[test]
    fn test_transfer_result_zero_duration_rate() {
        let duration_ms: u64 = 0;
        let bytes_per_second = if duration_ms > 0 { 1000.0 } else { 0.0 };
        let result = TransferResult {
            bytes_transferred: 1000,
            duration_ms,
            bytes_per_second,
            checksum: None,
        };
        assert!((result.bytes_per_second - 0.0).abs() < f64::EPSILON);
    }

    // ============== DirectoryTransferResult Additional Tests ==============

    #[test]
    fn test_directory_transfer_result_with_many_errors() {
        let errors: Vec<String> = (0..100).map(|i| format!("error {i}")).collect();
        let result = DirectoryTransferResult {
            files_transferred: 50,
            bytes_transferred: 5000,
            directories_created: 10,
            errors: errors.clone(),
            duration_ms: 1000,
        };
        assert_eq!(result.errors.len(), 100);
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("error 99"));
    }

    #[test]
    fn test_directory_transfer_result_large_values() {
        let result = DirectoryTransferResult {
            files_transferred: u64::MAX,
            bytes_transferred: u64::MAX,
            directories_created: u64::MAX,
            errors: vec![],
            duration_ms: u64::MAX,
        };
        assert_eq!(result.files_transferred, u64::MAX);
    }

    // ── chunk_size clamping (AUDIT-2026-08 B2) ───────────────
    //
    // `chunk_size` arrives unvalidated from the MCP request and reaches
    // `vec![0u8; n]`. Zero silently truncated the remote file (the handle is
    // already open with TRUNCATE) and reported success; `u64::MAX` aborted the
    // process through `handle_alloc_error`. `write_bytes` looped forever on 0.
    // Clamping happens at the point of use so every construction site is
    // covered, including the CLI runner.

    #[test]
    fn test_clamp_chunk_size_rejects_zero() {
        assert_eq!(clamp_chunk_size(0), MIN_CHUNK_SIZE);
    }

    #[test]
    fn test_clamp_chunk_size_raises_tiny_values() {
        assert_eq!(clamp_chunk_size(1), MIN_CHUNK_SIZE);
        assert_eq!(clamp_chunk_size(MIN_CHUNK_SIZE - 1), MIN_CHUNK_SIZE);
    }

    #[test]
    fn test_clamp_chunk_size_caps_huge_values() {
        assert_eq!(clamp_chunk_size(u64::MAX), MAX_CHUNK_SIZE);
        assert_eq!(clamp_chunk_size(MAX_CHUNK_SIZE + 1), MAX_CHUNK_SIZE);
    }

    #[test]
    fn test_clamp_chunk_size_passes_through_sane_values() {
        assert_eq!(clamp_chunk_size(DEFAULT_CHUNK_SIZE), DEFAULT_CHUNK_SIZE);
        assert_eq!(clamp_chunk_size(MIN_CHUNK_SIZE), MIN_CHUNK_SIZE);
        assert_eq!(clamp_chunk_size(MAX_CHUNK_SIZE), MAX_CHUNK_SIZE);
    }

    #[test]
    fn test_transfer_options_effective_chunk_size_is_clamped() {
        let zero = TransferOptions {
            chunk_size: 0,
            ..Default::default()
        };
        assert_eq!(zero.effective_chunk_size(), MIN_CHUNK_SIZE);

        let huge = TransferOptions {
            chunk_size: u64::MAX,
            ..Default::default()
        };
        assert_eq!(huge.effective_chunk_size(), MAX_CHUNK_SIZE);
    }
}
