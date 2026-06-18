//! Benchmarks for output sanitization
//!
//! Run with: `cargo bench --bench sanitizer_bench`

use bridge_mcp::config::SanitizeConfig;
use bridge_mcp::security::Sanitizer;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn create_sanitizer() -> Sanitizer {
    Sanitizer::from_config(&SanitizeConfig::default())
}

fn generate_clean_output(size: usize) -> String {
    "INFO: Server started successfully on port 8080\n"
        .repeat(size / 50 + 1)
        .chars()
        .take(size)
        .collect()
}

fn generate_sensitive_output(size: usize) -> String {
    let base = concat!(
        "Connection established\n",
        "Auth: ghp_1234567890abcdef1234567890abcdef12345678\n",
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
        "password: s3cr3t_passw0rd!\n",
        "INFO: Processing request\n",
    );
    base.repeat(size / base.len() + 1)
        .chars()
        .take(size)
        .collect()
}

fn benchmark_sanitization(c: &mut Criterion) {
    let sanitizer = create_sanitizer();

    // Clean output (fast path - no matches, Cow::Borrowed)
    let clean_small = generate_clean_output(1_024);
    let clean_medium = generate_clean_output(100 * 1_024);
    let clean_large = generate_clean_output(1_024 * 1_024);

    c.bench_function("sanitize: clean 1KB (no-op fast path)", |b| {
        b.iter(|| sanitizer.sanitize(black_box(&clean_small)));
    });
    c.bench_function("sanitize: clean 100KB (no-op fast path)", |b| {
        b.iter(|| sanitizer.sanitize(black_box(&clean_medium)));
    });
    c.bench_function("sanitize: clean 1MB (no-op fast path)", |b| {
        b.iter(|| sanitizer.sanitize(black_box(&clean_large)));
    });

    // Sensitive output (slow path - patterns detected, replacement applied)
    let sensitive_small = generate_sensitive_output(1_024);
    let sensitive_medium = generate_sensitive_output(100 * 1_024);
    let sensitive_large = generate_sensitive_output(1_024 * 1_024);

    c.bench_function("sanitize: sensitive 1KB (pattern replacement)", |b| {
        b.iter(|| sanitizer.sanitize(black_box(&sensitive_small)));
    });
    c.bench_function("sanitize: sensitive 100KB (pattern replacement)", |b| {
        b.iter(|| sanitizer.sanitize(black_box(&sensitive_medium)));
    });
    c.bench_function("sanitize: sensitive 1MB (pattern replacement)", |b| {
        b.iter(|| sanitizer.sanitize(black_box(&sensitive_large)));
    });
}

fn benchmark_sanitizer_creation(c: &mut Criterion) {
    let config = SanitizeConfig::default();

    c.bench_function("sanitizer creation (default patterns)", |b| {
        b.iter(|| Sanitizer::from_config(black_box(&config)));
    });
}

criterion_group!(
    benches,
    benchmark_sanitization,
    benchmark_sanitizer_creation
);
criterion_main!(benches);
