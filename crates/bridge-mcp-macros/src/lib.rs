//! Proc-macro helpers for `bridge-mcp` tool handlers.
//!
//! The `#[mcp_tool(...)]` attribute macro attaches to a unit struct
//! (typically the `XxxHandler` or `XxxTool` empty struct that the
//! handler files already define) and:
//!
//! 1. Leaves the original item unchanged — the struct definition is
//!    emitted verbatim.
//! 2. Appends a static `inventory::submit!` call that registers a
//!    `ToolRegistryEntry` carrying the tool's name, group,
//!    annotation kind, and a factory closure that returns
//!    `Arc<dyn ToolHandler>` for that handler type.
//!
//! The parent crate (`bridge-mcp`) defines `ToolRegistryEntry`
//! and `ToolAnnotationKind` and runs `inventory::collect!` so every
//! `#[mcp_tool]`-annotated type is gathered into a single static
//! table at compile time. `create_filtered_registry()`,
//! `tool_group()` and `tool_annotations()` walk that table to build
//! their lookups instead of the old 340-arm match statements.
//!
//! # Example
//!
//! ```ignore
//! use bridge_mcp_macros::mcp_tool;
//! use std::sync::Arc;
//! use bridge_mcp::ports::ToolHandler;
//!
//! #[mcp_tool(name = "ssh_exec", group = "core", annotation = "mutating")]
//! pub struct SshExecHandler;
//!
//! // ... impl ToolHandler for SshExecHandler { ... } stays as-is
//! ```
//!
//! The macro re-emits `pub struct SshExecHandler;` untouched and
//! appends a registration block to the same file.

use proc_macro::TokenStream;
use quote::quote;
use syn::{Expr, ExprLit, Lit, MetaNameValue, Token, parse_macro_input, punctuated::Punctuated};

/// Parse arguments of the form `name = "…", group = "…", annotation = "…"`.
struct McpToolArgs {
    name: String,
    group: String,
    annotation: String,
}

impl syn::parse::Parse for McpToolArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let pairs: Punctuated<MetaNameValue, Token![,]> = Punctuated::parse_terminated(input)?;

        let mut name: Option<String> = None;
        let mut group: Option<String> = None;
        let mut annotation: Option<String> = None;

        for pair in pairs {
            let key = pair
                .path
                .get_ident()
                .map(ToString::to_string)
                .unwrap_or_default();
            let value = extract_string_literal(&pair.value)
                .ok_or_else(|| syn::Error::new_spanned(&pair.value, "expected a string literal"))?;
            match key.as_str() {
                "name" => name = Some(value),
                "group" => group = Some(value),
                "annotation" => annotation = Some(value),
                other => {
                    return Err(syn::Error::new_spanned(
                        &pair.path,
                        format!("unknown #[mcp_tool] argument: {other}"),
                    ));
                }
            }
        }

        let name = name.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "missing `name = \"...\"`")
        })?;
        let group = group.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "missing `group = \"...\"`")
        })?;
        let annotation = annotation.unwrap_or_else(|| "read_only".to_string());

        // Validate annotation kind at compile time so typos are caught
        // right at the macro site instead of during registry lookup.
        match annotation.as_str() {
            "read_only" | "mutating" | "mutating_idempotent" | "destructive" => {}
            other => {
                return Err(syn::Error::new(
                    proc_macro2::Span::call_site(),
                    format!(
                        "invalid annotation `{other}` — expected one of: read_only, mutating, mutating_idempotent, destructive"
                    ),
                ));
            }
        }

        Ok(Self {
            name,
            group,
            annotation,
        })
    }
}

fn extract_string_literal(expr: &Expr) -> Option<String> {
    if let Expr::Lit(ExprLit {
        lit: Lit::Str(s), ..
    }) = expr
    {
        Some(s.value())
    } else {
        None
    }
}

/// Attach name / group / annotation metadata to a tool handler type.
///
/// Generates an `inventory::submit!` registration alongside the
/// struct so `mcp::registry::create_filtered_registry()` can build
/// its handler map from a compile-time table.
///
/// The factory produced by this macro is `|| Arc::new(Struct)`.
/// Use this for direct `impl ToolHandler for Struct` handlers where
/// the struct is a unit type that can be constructed by name.
/// For handlers wrapped in `StandardToolHandler<T>`, use the
/// companion [`mcp_standard_tool`] attribute instead.
#[proc_macro_attribute]
pub fn mcp_tool(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand_mcp_tool(attr, item, /* wrap_in_standard_tool */ false)
}

/// Attach name / group / annotation metadata to a `StandardTool`
/// marker type (the empty struct referenced by a type alias like
/// `type SshDockerPsHandler = StandardToolHandler<DockerPsTool>`).
///
/// The generated factory produces
/// `Arc::new(StandardToolHandler::<Marker>::new())` so the
/// registered value is the wrapper handler, not the raw marker.
#[proc_macro_attribute]
pub fn mcp_standard_tool(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand_mcp_tool(attr, item, /* wrap_in_standard_tool */ true)
}

fn expand_mcp_tool(attr: TokenStream, item: TokenStream, wrap_standard: bool) -> TokenStream {
    let args = parse_macro_input!(attr as McpToolArgs);

    // Parse just enough of the item to extract the type name and
    // re-emit it verbatim.
    let input = parse_macro_input!(item as syn::Item);

    let struct_name = match &input {
        syn::Item::Struct(s) => s.ident.clone(),
        _ => {
            return syn::Error::new_spanned(
                &input,
                "#[mcp_tool]/#[mcp_standard_tool] can only be applied to a struct",
            )
            .to_compile_error()
            .into();
        }
    };

    let name_lit = args.name;
    let group_lit = args.group;
    let annotation_ident = match args.annotation.as_str() {
        "read_only" => quote! { ::bridge_mcp::mcp::registry::ToolAnnotationKind::ReadOnly },
        "mutating" => quote! { ::bridge_mcp::mcp::registry::ToolAnnotationKind::Mutating },
        "mutating_idempotent" => {
            quote! { ::bridge_mcp::mcp::registry::ToolAnnotationKind::MutatingIdempotent }
        }
        "destructive" => {
            quote! { ::bridge_mcp::mcp::registry::ToolAnnotationKind::Destructive }
        }
        _ => unreachable!(),
    };

    let factory_expr = if wrap_standard {
        quote! {
            || ::std::sync::Arc::new(
                ::bridge_mcp::mcp::standard_tool::StandardToolHandler::<#struct_name>::new()
            ) as ::std::sync::Arc<dyn ::bridge_mcp::ports::ToolHandler>
        }
    } else {
        quote! {
            || ::std::sync::Arc::new(#struct_name)
                as ::std::sync::Arc<dyn ::bridge_mcp::ports::ToolHandler>
        }
    };

    let expanded = quote! {
        #input

        ::bridge_mcp::inventory::submit! {
            ::bridge_mcp::mcp::registry::ToolRegistryEntry {
                name: #name_lit,
                group: #group_lit,
                annotation_kind: #annotation_ident,
                factory: #factory_expr,
            }
        }
    };

    expanded.into()
}
