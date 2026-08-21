//! Opt-in notification subscriptions (MCP 2026-07-28,
//! `basic/patterns/subscriptions`).
//!
//! Modern MCP replaced "the server may notify whenever it likes" with an
//! explicit opt-in: the client issues `subscriptions/listen` naming the
//! notification types it wants, and the server MUST NOT deliver a type no
//! live subscription asked for. Before this module, `spawn_config_watcher`
//! broadcast `tools/list_changed` + `resources/list_changed` to every live
//! session unconditionally.
//!
//! The registry is transport-agnostic on purpose: an entry is an id, a
//! filter, and the writer channel of whichever session created it, so a
//! stdio session and an HTTP session register through the same call.
//!
//! Scope: request-scoped notifications do NOT belong here.
//! `notifications/progress` correlates to one in-flight request through
//! its `progressToken` and is absent from the spec's exhaustive opt-in
//! list, so it keeps flowing on the session channel directly.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use super::protocol::{JsonRpcNotification, WriterMessage};

/// The three list-changed notification types a client can opt into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationTopic {
    /// `notifications/tools/list_changed`
    ToolsListChanged,
    /// `notifications/prompts/list_changed`
    PromptsListChanged,
    /// `notifications/resources/list_changed`
    ResourcesListChanged,
}

impl NotificationTopic {
    /// JSON-RPC method name delivered for this topic.
    #[must_use]
    pub fn method(self) -> &'static str {
        match self {
            Self::ToolsListChanged => "notifications/tools/list_changed",
            Self::PromptsListChanged => "notifications/prompts/list_changed",
            Self::ResourcesListChanged => "notifications/resources/list_changed",
        }
    }
}

/// `params.notifications` of a `subscriptions/listen` request — the
/// exhaustive opt-in filter defined by the 2026-07-28 spec.
///
/// Unknown members are ignored rather than rejected: a later revision
/// adding a fifth notification type must not break this server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionFilter {
    #[serde(default)]
    pub tools_list_changed: bool,
    #[serde(default)]
    pub prompts_list_changed: bool,
    #[serde(default)]
    pub resources_list_changed: bool,
    #[serde(default)]
    pub resource_subscriptions: Vec<String>,
}

impl SubscriptionFilter {
    /// True when this subscription opted into `topic`.
    #[must_use]
    pub fn wants_topic(&self, topic: NotificationTopic) -> bool {
        match topic {
            NotificationTopic::ToolsListChanged => self.tools_list_changed,
            NotificationTopic::PromptsListChanged => self.prompts_list_changed,
            NotificationTopic::ResourcesListChanged => self.resources_list_changed,
        }
    }

    /// True when this subscription named `uri` in `resourceSubscriptions`.
    #[must_use]
    pub fn wants_resource(&self, uri: &str) -> bool {
        self.resource_subscriptions.iter().any(|u| u == uri)
    }

    /// True when the client asked for nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.tools_list_changed
            && !self.prompts_list_changed
            && !self.resources_list_changed
            && self.resource_subscriptions.is_empty()
    }

    /// Drop resource URIs whose scheme no handler serves.
    ///
    /// The acknowledgement must echo "the subset of supported
    /// notification types", not a copy of the request: a client that
    /// subscribes to `ssh://prod/etc/passwd` has to learn from the ack
    /// that nothing will ever arrive for it.
    #[must_use]
    pub fn restricted_to_schemes(mut self, schemes: &[&str]) -> Self {
        self.resource_subscriptions.retain(|uri| {
            uri.split_once("://")
                .is_some_and(|(scheme, _)| schemes.contains(&scheme))
        });
        self
    }
}

/// `params` of a `subscriptions/listen` request.
///
/// `notifications` has no serde default, so a request omitting it is a
/// deserialization error and the handler answers `-32602`.
#[derive(Debug, Clone, Deserialize)]
pub struct SubscriptionsListenParams {
    pub notifications: SubscriptionFilter,
}

/// One live subscription.
///
/// `id` is the JSON-RPC `id` of the `subscriptions/listen` request that
/// created it (`RequestId = string | number`), never a server-minted
/// value — MCP 2026-07-28 makes the subscription id and the request id
/// the same thing, so clients can demultiplex a shared stdio pipe.
struct Entry {
    id: Value,
    filter: SubscriptionFilter,
    tx: mpsc::Sender<WriterMessage>,
}

/// Server-wide registry of live subscriptions.
///
/// Cloning is cheap (two `Arc`s). `std::sync::Mutex` is deliberate: no
/// `.await` happens inside any critical section, and the publish path is
/// called from non-async contexts such as the config-watcher callback.
#[derive(Default, Clone)]
pub struct SubscriptionRegistry {
    entries: Arc<std::sync::Mutex<Vec<Entry>>>,
}

impl SubscriptionRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a subscription under the JSON-RPC `id` of the
    /// `subscriptions/listen` request that opened it.
    ///
    /// The registry deliberately mints NOTHING: MCP 2026-07-28 states the
    /// subscription id "is not an independent identifier space" — it is
    /// byte-for-byte the request id, and every notification on the stream
    /// carries it so a client can correlate on a shared channel.
    pub fn register(&self, id: Value, filter: SubscriptionFilter, tx: mpsc::Sender<WriterMessage>) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.push(Entry { id, filter, tx });
        }
    }

    /// Drop every subscription created over `tx` (session teardown).
    /// Returns how many were removed.
    pub fn remove_for_tx(&self, tx: &mpsc::Sender<WriterMessage>) -> usize {
        let Ok(mut entries) = self.entries.lock() else {
            return 0;
        };
        let before = entries.len();
        entries.retain(|e| !e.tx.same_channel(tx));
        before - entries.len()
    }

    /// Number of live subscriptions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |e| e.len())
    }

    /// True when no subscription is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot of the filter registered under `id`.
    #[must_use]
    pub fn filter_of(&self, id: &Value) -> Option<SubscriptionFilter> {
        let entries = self.entries.lock().ok()?;
        entries
            .iter()
            .find(|e| &e.id == id)
            .map(|e| e.filter.clone())
    }

    /// Every distinct resource URI some live subscription is watching,
    /// sorted and deduplicated.
    #[must_use]
    pub fn subscribed_resource_uris(&self) -> Vec<String> {
        let Ok(entries) = self.entries.lock() else {
            return Vec::new();
        };
        let mut uris: Vec<String> = entries
            .iter()
            .flat_map(|e| e.filter.resource_subscriptions.iter().cloned())
            .collect();
        drop(entries);
        uris.sort();
        uris.dedup();
        uris
    }

    /// Deliver a list-changed notification to the subscriptions that
    /// asked for `topic` — and to nobody else. Returns the delivery count.
    pub fn publish_topic(&self, topic: NotificationTopic) -> usize {
        let targets = self.targets(|f| f.wants_topic(topic));
        self.deliver(&targets, |id| {
            JsonRpcNotification::for_subscription(topic.method(), id)
        })
    }

    /// Deliver `notifications/resources/updated` for `uri` to the
    /// subscriptions that named it. Returns the delivery count.
    pub fn publish_resource_updated(&self, uri: &str) -> usize {
        let targets = self.targets(|f| f.wants_resource(uri));
        self.deliver(&targets, |id| {
            JsonRpcNotification::resources_updated(uri, id)
        })
    }

    fn targets<P>(&self, predicate: P) -> Vec<(Value, mpsc::Sender<WriterMessage>)>
    where
        P: Fn(&SubscriptionFilter) -> bool,
    {
        let Ok(entries) = self.entries.lock() else {
            return Vec::new();
        };
        entries
            .iter()
            .filter(|e| predicate(&e.filter))
            .map(|e| (e.id.clone(), e.tx.clone()))
            .collect()
    }

    /// Fire-and-forget delivery. A full channel drops the message (the
    /// client refreshes on demand); a closed channel prunes the entry so
    /// dead subscriptions cannot accumulate.
    fn deliver<F>(&self, targets: &[(Value, mpsc::Sender<WriterMessage>)], make: F) -> usize
    where
        F: Fn(&Value) -> JsonRpcNotification,
    {
        let mut delivered = 0;
        let mut dead = Vec::new();
        for (id, tx) in targets {
            match tx.try_send(WriterMessage::Notification(make(id))) {
                Ok(()) => delivered += 1,
                Err(TrySendError::Closed(_)) => dead.push(id.clone()),
                Err(TrySendError::Full(_)) => {}
            }
        }
        if !dead.is_empty()
            && let Ok(mut entries) = self.entries.lock()
        {
            entries.retain(|e| !dead.contains(&e.id));
        }
        delivered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    use crate::mcp::protocol::{META_SUBSCRIPTION_ID, WriterMessage};

    fn ch() -> (mpsc::Sender<WriterMessage>, mpsc::Receiver<WriterMessage>) {
        mpsc::channel::<WriterMessage>(8)
    }

    fn tools_only() -> SubscriptionFilter {
        SubscriptionFilter {
            tools_list_changed: true,
            ..SubscriptionFilter::default()
        }
    }

    #[test]
    fn filter_deserializes_the_spec_example() {
        let params: SubscriptionsListenParams = serde_json::from_value(serde_json::json!({
            "notifications": {
                "toolsListChanged": true,
                "resourceSubscriptions": ["file:///project/config.json"]
            }
        }))
        .expect("the 2026-07-28 spec example must parse");
        assert!(params.notifications.tools_list_changed);
        assert!(!params.notifications.prompts_list_changed);
        assert!(!params.notifications.resources_list_changed);
        assert_eq!(
            params.notifications.resource_subscriptions,
            vec!["file:///project/config.json".to_string()]
        );
    }

    #[test]
    fn unknown_notification_members_are_ignored_not_rejected() {
        let params: SubscriptionsListenParams = serde_json::from_value(serde_json::json!({
            "notifications": { "somethingFromTheFuture": true }
        }))
        .expect("a future notification type must not break parsing");
        assert!(params.notifications.is_empty());
    }

    #[test]
    fn publish_topic_reaches_only_subscribers_of_that_topic() {
        let reg = SubscriptionRegistry::new();
        let (tx_tools, mut rx_tools) = ch();
        let (tx_res, mut rx_res) = ch();

        reg.register(serde_json::json!(1), tools_only(), tx_tools);
        reg.register(
            serde_json::json!(2),
            SubscriptionFilter {
                resources_list_changed: true,
                ..SubscriptionFilter::default()
            },
            tx_res,
        );

        assert_eq!(reg.publish_topic(NotificationTopic::ToolsListChanged), 1);

        match rx_tools.try_recv().expect("tools subscriber receives") {
            WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/tools/list_changed");
            }
            _ => panic!("expected a Notification"),
        }
        assert!(
            rx_res.try_recv().is_err(),
            "a resources-only subscriber MUST NOT receive tools/list_changed"
        );
    }

    #[test]
    fn resource_updated_only_for_named_uris() {
        let reg = SubscriptionRegistry::new();
        let (tx, mut rx) = ch();
        let id = serde_json::json!("sub-a");
        reg.register(
            id.clone(),
            SubscriptionFilter {
                resource_subscriptions: vec!["history://recent".to_string()],
                ..SubscriptionFilter::default()
            },
            tx,
        );

        assert_eq!(reg.publish_resource_updated("health://server"), 0);
        assert!(
            rx.try_recv().is_err(),
            "an unrequested URI MUST NOT be delivered"
        );

        assert_eq!(reg.publish_resource_updated("history://recent"), 1);
        match rx.try_recv().expect("subscribed URI is delivered") {
            WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/resources/updated");
                let params = n.params.expect("params present");
                assert_eq!(params["uri"], "history://recent");
                assert_eq!(params["_meta"][META_SUBSCRIPTION_ID], id);
            }
            _ => panic!("expected a Notification"),
        }
    }

    #[test]
    fn remove_for_tx_drops_every_subscription_of_that_session() {
        let reg = SubscriptionRegistry::new();
        let (tx_a, _rx_a) = ch();
        let (tx_b, _rx_b) = ch();
        reg.register(serde_json::json!(1), tools_only(), tx_a.clone());
        reg.register(
            serde_json::json!(2),
            SubscriptionFilter {
                prompts_list_changed: true,
                ..SubscriptionFilter::default()
            },
            tx_a.clone(),
        );
        reg.register(serde_json::json!(3), tools_only(), tx_b);

        assert_eq!(reg.len(), 3);
        assert_eq!(reg.remove_for_tx(&tx_a), 2);
        assert_eq!(reg.len(), 1);

        // FIND-036's guarantee, carried over from the deleted per-session
        // `resources/subscribe` map: the survivor must be B's. A count
        // alone would be satisfied by dropping B and keeping one of A's.
        assert!(reg.filter_of(&serde_json::json!(1)).is_none());
        assert!(reg.filter_of(&serde_json::json!(2)).is_none());
        assert!(
            reg.filter_of(&serde_json::json!(3)).is_some(),
            "tearing down session A must not touch session B"
        );
    }

    #[test]
    fn closed_channels_are_pruned_on_publish() {
        let reg = SubscriptionRegistry::new();
        let (tx, rx) = ch();
        reg.register(serde_json::json!(1), tools_only(), tx);
        drop(rx);

        assert_eq!(reg.publish_topic(NotificationTopic::ToolsListChanged), 0);
        assert_eq!(reg.len(), 0, "a dead subscription must be pruned");
    }

    #[test]
    fn restricted_to_schemes_drops_unservable_uris() {
        let f = SubscriptionFilter {
            resource_subscriptions: vec![
                "history://recent".to_string(),
                "ssh://prod/etc/passwd".to_string(),
            ],
            ..SubscriptionFilter::default()
        }
        .restricted_to_schemes(&["history", "health"]);
        assert_eq!(
            f.resource_subscriptions,
            vec!["history://recent".to_string()]
        );
    }

    #[test]
    fn subscribed_resource_uris_is_sorted_and_deduped() {
        let reg = SubscriptionRegistry::new();
        let (tx1, _rx1) = ch();
        let (tx2, _rx2) = ch();
        reg.register(
            serde_json::json!(1),
            SubscriptionFilter {
                resource_subscriptions: vec!["history://recent".to_string()],
                ..SubscriptionFilter::default()
            },
            tx1,
        );
        reg.register(
            serde_json::json!(2),
            SubscriptionFilter {
                resource_subscriptions: vec![
                    "history://recent".to_string(),
                    "health://server".to_string(),
                ],
                ..SubscriptionFilter::default()
            },
            tx2,
        );
        assert_eq!(
            reg.subscribed_resource_uris(),
            vec![
                "health://server".to_string(),
                "history://recent".to_string()
            ]
        );
    }

    #[test]
    fn filter_of_returns_the_registered_filter() {
        let reg = SubscriptionRegistry::new();
        let (tx, _rx) = ch();
        let id = serde_json::json!(42);
        reg.register(id.clone(), tools_only(), tx);
        assert_eq!(reg.filter_of(&id), Some(tools_only()));
        assert_eq!(reg.filter_of(&serde_json::json!(1042)), None);
    }

    /// MCP 2026-07-28: the subscription id is not an independent
    /// identifier space — it is byte-for-byte the JSON-RPC `id` of the
    /// `subscriptions/listen` request. A STRING id must survive as a
    /// string, which a server-minted `u64` could never represent.
    #[test]
    fn registered_id_is_the_request_id_verbatim_including_strings() {
        let reg = SubscriptionRegistry::new();
        let (tx, mut rx) = ch();
        let id = serde_json::json!("listen-7f3a");
        reg.register(
            id.clone(),
            SubscriptionFilter {
                resource_subscriptions: vec!["history://recent".to_string()],
                ..SubscriptionFilter::default()
            },
            tx,
        );

        assert_eq!(reg.publish_resource_updated("history://recent"), 1);
        match rx.try_recv().expect("subscriber receives") {
            WriterMessage::Notification(n) => {
                let params = n.params.expect("params present");
                assert_eq!(
                    params["_meta"][META_SUBSCRIPTION_ID], id,
                    "the correlation id must be the request id verbatim"
                );
            }
            _ => panic!("expected a Notification"),
        }
    }
}
