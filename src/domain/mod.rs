//! Domain module - Core business logic
//!
//! This module contains the use cases and domain entities that
//! represent the core business logic of the MCP SSH Bridge.

pub mod data_reduction;
pub mod diff;
pub mod history;
#[cfg(feature = "jq")]
pub mod jq_filter;
pub mod output_cache;
pub mod output_kind;
pub mod output_truncator;
pub mod runbook;
pub mod task_store;
pub mod use_cases;
pub mod yaml;
#[cfg(feature = "jq")]
pub mod yq_filter;

pub use history::{CommandHistory, HistoryConfig, HistoryEntry};
pub use output_cache::OutputCache;
pub use task_store::TaskStore;
pub use use_cases::database::{DatabaseCommandBuilder, DatabaseType};
pub use use_cases::execute_command::{
    ExecuteCommandRequest, ExecuteCommandResponse, ExecuteCommandUseCase,
};
pub use use_cases::tunnel::{TunnelDirection, TunnelInfo, TunnelManager};
