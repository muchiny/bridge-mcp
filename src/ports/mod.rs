//! Ports module - Trait definitions for hexagonal architecture
//!
//! This module contains the trait definitions (ports) that define
//! the boundaries between the domain logic and external adapters.

pub mod completions;
mod connector;
mod executor;
mod executor_router;
mod prompts;
pub mod protocol;
mod resources;
mod ssh;
mod tools;

pub use completions::CompletionProvider;
pub use connector::{SshClientTrait, SshConnector};
pub use executor::RemoteExecutor;
pub use executor_router::ExecutorRouter;
pub use prompts::PromptHandler;
pub use protocol::{
    AppAction, AppContent, EmbeddedResource, PromptArgument, PromptContent, PromptMessage,
    ResourceContent, ResourceDefinition, ToolAnnotations, ToolCallResult, ToolContent,
};
pub use resources::ResourceHandler;
pub use ssh::{CommandOutput, SshExecutor};
pub use tools::{MrtrSlot, ToolContext, ToolHandler, ToolSchema};

#[cfg(test)]
pub use connector::mock::{MockSshClient, MockSshConnector};

#[cfg(test)]
pub use tools::mock;
