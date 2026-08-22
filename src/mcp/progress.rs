//! MCP Progress Reporter
//!
//! Sends `notifications/progress` to the client during tool execution.
//! Only active when the client provides a `progressToken` in `_meta`.

use serde_json::Value;
use tokio::sync::mpsc;

use super::protocol::{JsonRpcNotification, WriterMessage};

/// Reports progress to the MCP client via `notifications/progress`.
///
/// Fire-and-forget: if the channel is full or closed, notifications are silently dropped.
pub struct ProgressReporter {
    token: Value,
    tx: mpsc::Sender<WriterMessage>,
    total: Option<u64>,
}

impl ProgressReporter {
    /// Create a new progress reporter.
    ///
    /// - `token`: the `progressToken` from the client's `_meta`
    /// - `tx`: writer channel clone for sending notifications
    /// - `total`: optional total number of steps (enables percentage display)
    #[must_use]
    pub fn new(token: Value, tx: mpsc::Sender<WriterMessage>, total: Option<u64>) -> Self {
        Self { token, tx, total }
    }

    /// Send a progress notification.
    ///
    /// - `progress`: current step (0-based or 1-based, must be <= total if set)
    /// - `message`: optional human-readable status message
    pub fn report(&self, progress: u64, message: Option<&str>) {
        let notification =
            JsonRpcNotification::progress(&self.token, progress, self.total, message);
        let _ = self.tx.try_send(WriterMessage::Notification(notification));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_sends_notification() {
        let (tx, mut rx) = mpsc::channel(10);
        let reporter = ProgressReporter::new(Value::String("tok-1".to_string()), tx, Some(3));

        reporter.report(1, Some("Connecting..."));

        let msg = rx.try_recv().unwrap();
        match msg {
            WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/progress");
                let params = n.params.unwrap();
                assert_eq!(params["progressToken"], "tok-1");
                assert_eq!(params["progress"], 1);
                assert_eq!(params["total"], 3);
                assert_eq!(params["message"], "Connecting...");
            }
            WriterMessage::Response(_) => panic!("Expected notification"),
        }
    }

    #[test]
    fn test_report_without_total() {
        let (tx, mut rx) = mpsc::channel(10);
        let reporter = ProgressReporter::new(Value::String("tok-2".to_string()), tx, None);

        reporter.report(5, None);

        let msg = rx.try_recv().unwrap();
        match msg {
            WriterMessage::Notification(n) => {
                let params = n.params.unwrap();
                assert_eq!(params["progress"], 5);
                assert!(params.get("total").is_none() || params["total"].is_null());
                assert!(params.get("message").is_none() || params["message"].is_null());
            }
            WriterMessage::Response(_) => panic!("Expected notification"),
        }
    }

    #[test]
    fn test_noop_when_channel_closed() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let reporter = ProgressReporter::new(Value::String("tok-3".to_string()), tx, Some(2));
        // Should not panic
        reporter.report(1, Some("test"));
    }

    #[test]
    fn test_integer_token() {
        let (tx, mut rx) = mpsc::channel(10);
        let reporter = ProgressReporter::new(Value::Number(42.into()), tx, Some(10));

        reporter.report(7, Some("Almost done"));

        let msg = rx.try_recv().unwrap();
        match msg {
            WriterMessage::Notification(n) => {
                let params = n.params.unwrap();
                assert_eq!(params["progressToken"], 42);
            }
            WriterMessage::Response(_) => panic!("Expected notification"),
        }
    }
}
