//! Integration tests for `SftpClient` against the in-process mock SFTP
//! server defined in `tests/ssh_mock_server.rs`.
//!
//! The mock SFTP backend stores all paths under a `tempfile::TempDir`,
//! so a client request for `/foo` lands at `<root>/foo`. This is enough
//! to exercise the streaming `upload_file` / `download_file` paths plus
//! the directory helpers (`mkdir_recursive`, `read_dir`,
//! `upload_directory`).

#![allow(clippy::cast_possible_truncation)]

#[path = "ssh_mock_server.rs"]
mod helpers;

use std::path::Path;

use bridge_mcp::error::BridgeError;
use bridge_mcp::ssh::{SshClient, TransferOptions, TransferProgress};
use helpers::{MockSshServerBuilder, mock_host_config, mock_limits};

/// Produce a `(client, sftp_root)` pair connected to a fresh mock server.
/// Returns the server handle so the caller can keep it alive for the
/// duration of the test.
async fn connected_sftp() -> (
    SshClient,
    helpers::MockServerHandle,
    std::sync::Arc<tempfile::TempDir>,
) {
    let (addr, server, root) = MockSshServerBuilder::new().start().await;
    let host = mock_host_config(addr, "tester", "testpass");
    let limits = mock_limits();
    let client = SshClient::connect("mock", &host, &limits)
        .await
        .expect("connect");
    (client, server, root)
}

#[tokio::test]
async fn upload_then_download_round_trips_bytes() {
    let (client, _server, root) = connected_sftp().await;
    let sftp = client.sftp_session().await.expect("sftp_session");

    // Source file with deterministic content.
    let local_dir = tempfile::tempdir().expect("local tempdir");
    let local_path = local_dir.path().join("src.txt");
    let payload = b"hello sftp world\n".repeat(64);
    std::fs::write(&local_path, &payload).expect("write local");

    let opts = TransferOptions::default();
    let result = sftp
        .upload_file::<fn(TransferProgress)>(&local_path, "/up.txt", &opts, None)
        .await
        .expect("upload");
    assert_eq!(result.bytes_transferred as usize, payload.len());

    // Verify it actually landed on the server's filesystem.
    let server_path = root.path().join("up.txt");
    assert!(server_path.exists(), "remote file not created");
    let on_disk = std::fs::read(&server_path).expect("read server file");
    assert_eq!(on_disk, payload);

    // Now download to a different local path.
    let download_path = local_dir.path().join("dst.txt");
    let download_result = sftp
        .download_file::<fn(TransferProgress)>(
            "/up.txt",
            &download_path,
            &TransferOptions::default(),
            None,
        )
        .await
        .expect("download");
    assert_eq!(download_result.bytes_transferred as usize, payload.len());
    let downloaded = std::fs::read(&download_path).expect("read downloaded");
    assert_eq!(downloaded, payload);
}

#[tokio::test]
async fn read_dir_lists_uploaded_entry() {
    let (client, _server, root) = connected_sftp().await;
    let sftp = client.sftp_session().await.expect("sftp_session");

    // Pre-populate the server-side dir.
    std::fs::write(root.path().join("a.txt"), b"a").expect("seed a");
    std::fs::write(root.path().join("b.txt"), b"bb").expect("seed b");

    let entries = sftp.read_dir("/").await.expect("read_dir");
    let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"a.txt"), "missing a.txt in {names:?}");
    assert!(names.contains(&"b.txt"), "missing b.txt in {names:?}");

    // Sizes are populated from the filesystem.
    let a = entries.iter().find(|e| e.name == "a.txt").expect("entry a");
    assert_eq!(a.size, Some(1));
    assert!(!a.is_dir);
}

#[tokio::test]
async fn mkdir_recursive_creates_full_chain() {
    let (client, _server, root) = connected_sftp().await;
    let sftp = client.sftp_session().await.expect("sftp_session");

    sftp.mkdir_recursive("/a/b/c")
        .await
        .expect("mkdir_recursive");

    // Each level should now exist on the server's filesystem.
    assert!(root.path().join("a").is_dir());
    assert!(root.path().join("a/b").is_dir());
    assert!(root.path().join("a/b/c").is_dir());

    // And read_dir on the parent reports the child.
    let entries = sftp.read_dir("/a/b").await.expect("read_dir");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "c");
    assert!(entries[0].is_dir);
}

#[tokio::test]
async fn upload_directory_walks_local_tree() {
    let (client, _server, root) = connected_sftp().await;
    let sftp = client.sftp_session().await.expect("sftp_session");

    // Build a small local tree:
    //   <local>/tree/
    //     ├── a.txt   "alpha"
    //     ├── nested/
    //     │   └── b.txt  "beta"
    let local_dir = tempfile::tempdir().expect("local tempdir");
    let tree = local_dir.path().join("tree");
    std::fs::create_dir(&tree).expect("mkdir tree");
    std::fs::write(tree.join("a.txt"), b"alpha").expect("write a");
    std::fs::create_dir(tree.join("nested")).expect("mkdir nested");
    std::fs::write(tree.join("nested/b.txt"), b"beta").expect("write b");

    let result = sftp
        .upload_directory(&tree, "/dst", &[])
        .await
        .expect("upload_directory");

    assert!(
        result.errors.is_empty(),
        "errors during upload: {:?}",
        result.errors
    );
    assert_eq!(result.files_transferred, 2);
    assert!(result.directories_created >= 2);

    let dst_a = root.path().join("dst/a.txt");
    let dst_b = root.path().join("dst/nested/b.txt");
    assert_eq!(std::fs::read(&dst_a).expect("read a"), b"alpha");
    assert_eq!(std::fs::read(&dst_b).expect("read b"), b"beta");
}

#[tokio::test]
async fn upload_file_with_missing_local_source_returns_io_like_error() {
    let (client, _server, _root) = connected_sftp().await;
    let sftp = client.sftp_session().await.expect("sftp_session");

    let missing = Path::new("/this/path/does/not/exist/abcdef.bin");
    let opts = TransferOptions::default();
    let err = sftp
        .upload_file::<fn(TransferProgress)>(missing, "/should-not-land.bin", &opts, None)
        .await
        .expect_err("should fail with missing local source");

    // The SFTP layer wraps std::io::Error into BridgeError::FileTransfer
    // (see `src/ssh/sftp.rs::upload_file`). We assert on that variant.
    match err {
        BridgeError::FileTransfer { reason } => {
            assert!(
                reason.contains("local file") || reason.contains("Cannot open"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected FileTransfer error, got {other:?}"),
    }
}

#[tokio::test]
async fn write_bytes_creates_file_with_exact_content() {
    let (client, _server, root) = connected_sftp().await;
    let sftp = client.sftp_session().await.expect("sftp_session");

    let payload: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
    let _result = sftp
        .write_bytes(&payload, "/blob.bin", false, 1024)
        .await
        .expect("write_bytes");

    let on_disk = std::fs::read(root.path().join("blob.bin")).expect("read");
    assert_eq!(on_disk, payload);
}
