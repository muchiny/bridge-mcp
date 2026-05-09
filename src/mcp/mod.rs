pub mod apps;
pub mod client_requester;
pub mod completion_provider;
pub mod elicitation;
pub mod history;
mod instructions;
pub mod logger;
pub mod meta_tools;
pub mod pending_requests;
pub mod progress;
pub mod prompt_registry;
pub mod prompts;
pub mod protocol;
pub mod registry;
pub mod resource_registry;
pub mod resources;
pub mod sampling;
mod server;
pub mod session_capabilities;
pub mod session_context;
pub mod standard_tool;
pub mod tool_handlers;
pub mod transport;

pub use history::{CommandHistory, HistoryConfig, HistoryEntry};
pub use logger::McpLogger;
pub use prompt_registry::{PromptRegistry, create_default_prompt_registry};
pub use protocol::*;
pub use registry::{ToolRegistry, create_default_registry};
pub use resource_registry::{ResourceRegistry, create_default_resource_registry};
pub use server::McpServer;

// Re-export utils functions for fuzzing
#[doc(hidden)]
pub use tool_handlers::utils::{shell_escape, validate_path};
