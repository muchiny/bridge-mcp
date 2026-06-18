//! Benchmarks for tool registry operations
//!
//! Run with: `cargo bench --bench registry_bench`

use bridge_mcp::config::ToolGroupsConfig;
use bridge_mcp::mcp::registry::create_filtered_registry;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn benchmark_registry_lookup(c: &mut Criterion) {
    let tool_groups = ToolGroupsConfig::default();
    let registry = create_filtered_registry(&tool_groups);

    c.bench_function("registry: lookup ssh_exec (core tool)", |b| {
        b.iter(|| registry.get(black_box("ssh_exec")));
    });

    c.bench_function("registry: lookup ssh_k8s_get (kubernetes tool)", |b| {
        b.iter(|| registry.get(black_box("ssh_k8s_get")));
    });

    c.bench_function(
        "registry: lookup ssh_win_service_status (windows tool)",
        |b| {
            b.iter(|| registry.get(black_box("ssh_win_service_status")));
        },
    );

    c.bench_function("registry: lookup nonexistent tool", |b| {
        b.iter(|| registry.get(black_box("nonexistent_tool")));
    });
}

fn benchmark_registry_list(c: &mut Criterion) {
    let tool_groups = ToolGroupsConfig::default();
    let registry = create_filtered_registry(&tool_groups);

    c.bench_function("registry: list_tools (337 tools)", |b| {
        b.iter(|| registry.list_tools());
    });
}

fn benchmark_registry_creation(c: &mut Criterion) {
    let tool_groups = ToolGroupsConfig::default();

    c.bench_function("registry: create_filtered_registry (337 tools)", |b| {
        b.iter(|| create_filtered_registry(black_box(&tool_groups)));
    });
}

criterion_group!(
    benches,
    benchmark_registry_lookup,
    benchmark_registry_list,
    benchmark_registry_creation,
);
criterion_main!(benches);
