//! MCP Resource Handlers
//!
//! This module contains resource handler implementations that
//! expose remote data through the MCP Resources primitive.

mod file_resource;
mod health_resource;
mod history_resource;
mod log_resource;
mod metrics_resource;
mod services_resource;

pub use file_resource::FileResourceHandler;
pub use health_resource::HealthResourceHandler;
pub use history_resource::HistoryResourceHandler;
pub use log_resource::LogResourceHandler;
pub use metrics_resource::MetricsResourceHandler;
pub use services_resource::ServicesResourceHandler;

// The (parser, command builder) pairs, for `fuzz_resource_uri`.
//
// `ResourceHandler::read` is unusable from a fuzz target: it needs a
// `ToolContext` whose mock is `#[cfg(test)]`, it opens a real SSH connection,
// and it never returns the command it built. Exposing the parser AND the
// builder lets a target assert the property that matters — the path the parser
// kept reaches the command as one word — against the same code production
// runs, with no re-derivation of the path from the URI text.
#[doc(hidden)]
pub use file_resource::{FileUri, file_read_command, parse_file_uri};
#[doc(hidden)]
pub use history_resource::parse_relative_duration;
#[doc(hidden)]
pub use log_resource::{LogUri, log_tail_command, parse_log_uri};
