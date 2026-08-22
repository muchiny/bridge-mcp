//! MCP Logger
//!
//! Sends structured log messages to the MCP client via `notifications/message`.
//! Level-filtered: messages below the current minimum level are dropped.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use serde_json::Value;
use tokio::sync::mpsc;

use super::protocol::{JsonRpcNotification, LogLevel, WriterMessage};

/// MCP Logger that sends `notifications/message` to the client.
///
/// Fire-and-forget: if the channel is full or closed, messages are silently dropped.
pub struct McpLogger {
    min_level: Arc<AtomicU8>,
    tx: mpsc::Sender<WriterMessage>,
}

impl McpLogger {
    /// Create a new logger with the given minimum level and writer channel.
    #[must_use]
    pub fn new(min_level: Arc<AtomicU8>, tx: mpsc::Sender<WriterMessage>) -> Self {
        Self { min_level, tx }
    }

    /// Update the minimum log level.
    pub fn set_level(&self, level: LogLevel) {
        self.min_level.store(level.severity(), Ordering::Relaxed);
    }

    /// Send a log message if it meets the minimum level.
    pub fn log(&self, level: LogLevel, logger: &str, data: impl Into<Value>) {
        if level.severity() < self.min_level.load(Ordering::Relaxed) {
            return;
        }
        let data = data.into();
        let notification = JsonRpcNotification::log_message(level, logger, &data);
        let _ = self.tx.try_send(WriterMessage::Notification(notification));
    }

    /// Log a debug message.
    pub fn debug(&self, logger: &str, msg: &str) {
        self.log(LogLevel::Debug, logger, Value::String(msg.to_string()));
    }

    /// Log an info message.
    pub fn info(&self, logger: &str, msg: &str) {
        self.log(LogLevel::Info, logger, Value::String(msg.to_string()));
    }

    /// Log a warning message.
    pub fn warning(&self, logger: &str, msg: &str) {
        self.log(LogLevel::Warning, logger, Value::String(msg.to_string()));
    }

    /// Log an error message.
    pub fn error(&self, logger: &str, msg: &str) {
        self.log(LogLevel::Error, logger, Value::String(msg.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_logger() -> (McpLogger, mpsc::Receiver<WriterMessage>) {
        let (tx, rx) = mpsc::channel(100);
        let min_level = Arc::new(AtomicU8::new(LogLevel::Warning.severity()));
        (McpLogger::new(min_level, tx), rx)
    }

    #[test]
    fn test_set_level() {
        let (logger, _rx) = create_test_logger();
        logger.set_level(LogLevel::Debug);
        assert_eq!(
            logger.min_level.load(Ordering::Relaxed),
            LogLevel::Debug.severity()
        );
    }

    #[test]
    fn test_filters_below_level() {
        let (logger, mut rx) = create_test_logger();
        // Default level is Warning, so Info should be filtered
        logger.info("test", "should be filtered");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_sends_at_level() {
        let (logger, mut rx) = create_test_logger();
        // Warning should pass (same as min level)
        logger.warning("test", "should pass");
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_sends_above_level() {
        let (logger, mut rx) = create_test_logger();
        // Error > Warning, should pass
        logger.error("test", "should pass");
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_noop_when_channel_closed() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx); // Close the receiver
        let min_level = Arc::new(AtomicU8::new(LogLevel::Debug.severity()));
        let logger = McpLogger::new(min_level, tx);
        // Should not panic
        logger.error("test", "channel closed");
    }

    /// `replace McpLogger::debug with ()` collapses the helper to a
    /// no-op. Default min level is `Warning`, so a `debug()` call is
    /// already filtered — to detect the mutation, lower the level to
    /// `Debug` first and verify a notification lands on the channel.
    #[test]
    fn test_debug_emits_when_level_allows() {
        let (logger, mut rx) = create_test_logger();
        logger.set_level(LogLevel::Debug);
        logger.debug("ssh", "trace details");
        let msg = rx
            .try_recv()
            .expect("debug must emit a notification when min level is Debug");
        match msg {
            WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/message");
                let params = n.params.unwrap();
                assert_eq!(params["level"], "debug");
                assert_eq!(params["logger"], "ssh");
                assert_eq!(params["data"], "trace details");
            }
            WriterMessage::Response(_) => panic!("Expected notification"),
        }
    }

    #[test]
    fn test_log_with_json_data() {
        let (logger, mut rx) = create_test_logger();
        logger.set_level(LogLevel::Debug);
        logger.log(
            LogLevel::Info,
            "ssh",
            serde_json::json!({"host": "web1", "action": "connect"}),
        );
        let msg = rx.try_recv().unwrap();
        match msg {
            WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/message");
                let params = n.params.unwrap();
                assert_eq!(params["level"], "info");
                assert_eq!(params["logger"], "ssh");
                assert_eq!(params["data"]["host"], "web1");
            }
            WriterMessage::Response(_) => panic!("Expected notification"),
        }
    }
}
