//! Benchmarks for command validation
//!
//! Run with: cargo bench

use bridge_mcp::config::{SanitizeConfig, SecurityConfig, SecurityMode};
use bridge_mcp::security::CommandValidator;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn create_test_config() -> SecurityConfig {
    SecurityConfig {
        mode: SecurityMode::Permissive,
        whitelist: vec![],
        blacklist: vec![
            r"rm\s+-rf\s+/".to_string(),
            r"mkfs\.".to_string(),
            r"dd\s+if=".to_string(),
            r"chmod\s+777".to_string(),
            r"curl.*\|\s*sh".to_string(),
            r"wget.*\|\s*sh".to_string(),
        ],
        sanitize_patterns: vec![],
        sanitize: SanitizeConfig::default(),
        ..SecurityConfig::default()
    }
}

fn create_strict_config() -> SecurityConfig {
    SecurityConfig {
        mode: SecurityMode::Strict,
        whitelist: vec![
            r"^ls\b".to_string(),
            r"^pwd$".to_string(),
            r"^whoami$".to_string(),
            r"^cat\s+".to_string(),
            r"^grep\s+".to_string(),
            r"^docker\s+".to_string(),
            r"^kubectl\s+".to_string(),
        ],
        blacklist: vec![r"rm\s+-rf".to_string()],
        sanitize_patterns: vec![],
        sanitize: SanitizeConfig::default(),
        ..SecurityConfig::default()
    }
}

fn benchmark_validation(c: &mut Criterion) {
    let permissive_config = create_test_config();
    let permissive_validator = CommandValidator::new(&permissive_config);

    let strict_config = create_strict_config();
    let strict_validator = CommandValidator::new(&strict_config);

    // Simple command benchmarks
    c.bench_function("permissive: simple command (ls -la)", |b| {
        b.iter(|| permissive_validator.validate(black_box("ls -la")));
    });

    c.bench_function("strict: simple command (ls -la)", |b| {
        b.iter(|| strict_validator.validate(black_box("ls -la")));
    });

    // Complex command benchmarks
    c.bench_function("permissive: complex command (docker run)", |b| {
        b.iter(|| {
            permissive_validator.validate(black_box(
                "docker run --rm -v /data:/data alpine sh -c 'echo test'",
            ))
        });
    });

    c.bench_function("strict: complex command (docker run)", |b| {
        b.iter(|| {
            strict_validator.validate(black_box(
                "docker run --rm -v /data:/data alpine sh -c 'echo test'",
            ))
        });
    });

    // Blacklisted command (should fail quickly)
    c.bench_function("permissive: blacklisted command (rm -rf /)", |b| {
        b.iter(|| permissive_validator.validate(black_box("rm -rf /")));
    });

    // Not in whitelist (strict mode rejection)
    c.bench_function("strict: unlisted command (rm file.txt)", |b| {
        b.iter(|| strict_validator.validate(black_box("rm file.txt")));
    });
}

fn benchmark_validator_creation(c: &mut Criterion) {
    let config = create_strict_config();

    c.bench_function("validator creation (7 patterns)", |b| {
        b.iter(|| CommandValidator::new(black_box(&config)));
    });
}

criterion_group!(benches, benchmark_validation, benchmark_validator_creation);
criterion_main!(benches);
