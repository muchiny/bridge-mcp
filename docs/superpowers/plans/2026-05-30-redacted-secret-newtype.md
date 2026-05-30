# RedactedSecret Newtype — Secret Leak Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every in-memory credential structurally impossible to leak through `Debug`, `Display`, or `Serialize`, while keeping zeroize-on-drop — by replacing scattered `Zeroizing<String>` / `String` secret fields with a single `RedactedSecret` newtype.

**Architecture:** Introduce one in-crate newtype `RedactedSecret(Zeroizing<String>)` in `src/config/secret.rs` with hand-written `Debug` → `"[REDACTED]"`, `Serialize` → `"[REDACTED]"`, transparent `Deserialize` (reads a plain string), and `Deref<Target = str>` so existing call sites (`.as_str()`, `&secret` → `&str` coercion) compile unchanged. Swap the six credential fields across `config/types.rs` to use it. Add one defensive `Bearer` sanitizer pattern as an independent hardening.

**Tech Stack:** Rust 2024 (MSRV 1.94), `serde`, `zeroize = "1"` (already a dependency), `regex` (sanitizer). No new crates.

---

## Background — Findings This Plan Fixes

From the audit (verified against `zeroize-1.8.2/src/lib.rs:622` and `:725`):

- **F1 — Debug leak (real, latent):** `zeroize::Zeroizing` derives `Debug` (forwards inner value). `AuthConfig`, `SocksProxyConfig`, `HostConfig` all `#[derive(Debug)]` and contain secrets → any `{:?}` prints the password in cleartext (`Zeroizing("hunter2")`). No current call site triggers it; fix is regression-proofing for a security tool.
- **F2 — Serialize leak (real, latent):** `Zeroizing` impls `Serialize` (forwards inner value). The config types derive `Serialize`. No production path serializes a full `Config` (only the round-trip unit tests at `types.rs:1464-1484` do), but the derive is a live footgun.
- **F3 — AWX token not protected:** `AwxConfig::token: String` (`types.rs:59`) — plain `String`, neither zeroized nor redacted, inconsistent with the five other secret fields.
- **F4 — No `Bearer` redaction pattern:** opaque (non-JWT) bearer tokens in command output rely solely on the entropy detector (on by default). If an operator sets `entropy_detection: false`, opaque bearer tokens leak. A literal pattern closes that gap cheaply.

**Explicitly out of scope (do NOT change):** the `secrecy` crate migration (rejected — new dependency, large blast radius), and F5 (heuristic false-negatives — inherent, no code action).

## File Structure

- **Create** `src/config/secret.rs` — the `RedactedSecret` newtype + its trait impls + unit tests. One responsibility: a leak-proof, zeroizing string secret.
- **Modify** `src/config/mod.rs` — declare `mod secret;` and re-export `RedactedSecret`.
- **Modify** `src/config/types.rs` — swap six field types to `RedactedSecret`; update the secret-bearing unit tests; add a `Debug`-doesn't-leak regression test.
- **Modify** `src/ssh/client.rs:452` — SOCKS proxy password call site: pass `.as_str()` explicitly (defensive against a generic tokio_socks signature). All other SSH call sites compile unchanged via `Deref` coercion.
- **Modify** `src/security/sanitizer.rs` — add one `Bearer` pattern definition + a test (F4, independent).

The AWX call sites (`&awx.token` in ~16 handlers) compile unchanged: the use-case functions take `token: &str`, and `&RedactedSecret` deref-coerces to `&str`.

---

### Task 1: `RedactedSecret` newtype

**Files:**
- Create: `src/config/secret.rs`
- Modify: `src/config/mod.rs`

- [ ] **Step 1: Write the failing tests**

Create `src/config/secret.rs` with only the test module first (the type does not exist yet — this must fail to compile, which counts as a failing test):

```rust
//! `RedactedSecret`: a string credential that zeroizes on drop and is
//! structurally incapable of leaking through `Debug`, `Display`, or
//! `Serialize`. Use it for every in-memory secret (passwords, passphrases,
//! API tokens) instead of `String` or bare `Zeroizing<String>`.

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "hunter2-super-secret";

    #[test]
    fn debug_does_not_leak() {
        let s = RedactedSecret::from(SECRET);
        let rendered = format!("{s:?}");
        assert!(!rendered.contains(SECRET), "Debug leaked the secret: {rendered}");
        assert_eq!(rendered, "[REDACTED]");
    }

    #[test]
    fn serialize_does_not_leak() {
        let s = RedactedSecret::from(SECRET);
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains(SECRET), "Serialize leaked the secret: {json}");
        assert_eq!(json, "\"[REDACTED]\"");
    }

    #[test]
    fn deserialize_reads_plain_string() {
        let s: RedactedSecret = serde_json::from_str("\"hunter2-super-secret\"").unwrap();
        assert_eq!(s.as_str(), SECRET);
    }

    #[test]
    fn deref_and_as_str_expose_value_for_use() {
        let s = RedactedSecret::from(SECRET);
        // Deref<Target = str> lets it coerce where &str is expected.
        let via_deref: &str = &s;
        assert_eq!(via_deref, SECRET);
        assert_eq!(s.as_str(), SECRET);
        assert_eq!(s.len(), SECRET.len()); // str method via Deref
    }

    #[test]
    fn clone_is_independent() {
        let a = RedactedSecret::from(SECRET);
        let b = a.clone();
        assert_eq!(a.as_str(), b.as_str());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib config::secret 2>&1 | tail -20`
Expected: compile error — `cannot find type RedactedSecret in this scope` (the type is not defined yet).

- [ ] **Step 3: Implement the newtype**

Insert this above the `#[cfg(test)]` module in `src/config/secret.rs`:

```rust
use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// A string secret that is wiped from memory on drop and never reveals its
/// contents through `Debug`, `Display`, or `Serialize`.
///
/// Access the underlying value explicitly with [`RedactedSecret::as_str`] or
/// via `Deref<Target = str>` (so `&secret` coerces to `&str` at call sites).
#[derive(Clone)]
pub struct RedactedSecret(Zeroizing<String>);

impl RedactedSecret {
    /// Wrap an owned `String` as a redacted, zeroizing secret.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrow the secret as `&str` for use at an authentication boundary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for RedactedSecret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for RedactedSecret {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl Deref for RedactedSecret {
    type Target = str;

    fn deref(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for RedactedSecret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for RedactedSecret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::new(String::deserialize(deserializer)?))
    }
}
```

- [ ] **Step 4: Wire the module into the config crate**

In `src/config/mod.rs`, add `mod secret;` after the existing `mod` lines and re-export the type. The block at the top becomes:

```rust
mod loader;
pub mod secret;
pub mod ssh_config;
pub mod types;
mod watcher;

pub use loader::{default_config_path, load_config};
pub use secret::RedactedSecret;
pub use types::*;
pub use watcher::ConfigWatcher;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib config::secret 2>&1 | tail -20`
Expected: PASS — `debug_does_not_leak`, `serialize_does_not_leak`, `deserialize_reads_plain_string`, `deref_and_as_str_expose_value_for_use`, `clone_is_independent` all green.

- [ ] **Step 6: Lint**

Run: `cargo clippy --lib 2>&1 | tail -20`
Expected: no warnings on `src/config/secret.rs`.

- [ ] **Step 7: Commit**

```bash
git add src/config/secret.rs src/config/mod.rs
git commit -m "feat(config): add RedactedSecret newtype (leak-proof zeroizing secret)"
```

---

### Task 2: Swap config credential fields to `RedactedSecret`

**Files:**
- Modify: `src/config/types.rs` (field declarations: `AuthConfig::Password.password`, `AuthConfig::Key.passphrase`, `AuthConfig::Ntlm.password`, `HostConfig.sudo_password`, `SocksProxyConfig.password`; the import; the secret-bearing tests)
- Modify: `src/ssh/client.rs:452` (SOCKS password call site)

- [ ] **Step 1: Write the failing regression test**

In the `tests` module of `src/config/types.rs`, add a new test that proves `Debug` on a host no longer leaks the password:

```rust
    #[test]
    fn host_config_debug_does_not_leak_password() {
        let auth = AuthConfig::Password {
            password: RedactedSecret::from("topsecret-pw"),
        };
        let rendered = format!("{auth:?}");
        assert!(
            !rendered.contains("topsecret-pw"),
            "AuthConfig Debug leaked the password: {rendered}"
        );
    }
```

Also update the existing serialize test `test_auth_config_password_serialization` (around `types.rs:1477`) to assert redaction instead of leakage:

```rust
    #[test]
    fn test_auth_config_password_serialization() {
        let auth = AuthConfig::Password {
            password: RedactedSecret::from("secret123"),
        };
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("\"type\":\"password\""));
        assert!(!json.contains("secret123"), "password leaked in serialization");
        assert!(json.contains("[REDACTED]"));
    }
```

And update the `passphrase` construction in `test_auth_config_key_serialization` (around `types.rs:1462`) so it compiles against the new type:

```rust
        let auth = AuthConfig::Key {
            path: "/path/to/key".to_string(),
            passphrase: Some(RedactedSecret::from("secret")),
        };
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib config::types 2>&1 | tail -25`
Expected: compile error — `RedactedSecret` not in scope in `types.rs` and/or `AuthConfig::Password.password` still expects `Zeroizing<String>`. This is the failing state.

- [ ] **Step 3: Swap the field types and import**

In `src/config/types.rs`, change the import line 4 from:

```rust
use zeroize::Zeroizing;
```

to:

```rust
use crate::config::secret::RedactedSecret;
```

(Remove the `zeroize::Zeroizing` import if no other use remains in the file. If `cargo build` later reports it still used elsewhere, keep both lines.)

Then change each secret field declaration:

- `HostConfig::sudo_password` (≈line 256):
  ```rust
  pub sudo_password: Option<RedactedSecret>,
  ```
- `SocksProxyConfig::password` (≈line 465):
  ```rust
  pub password: Option<RedactedSecret>,
  ```
- `AuthConfig::Key::passphrase` (≈line 497):
  ```rust
  passphrase: Option<RedactedSecret>,
  ```
- `AuthConfig::Password::password` (≈line 501):
  ```rust
  password: RedactedSecret,
  ```
- `AuthConfig::Ntlm::password` (≈line 506, under `#[cfg(feature = "winrm")]`):
  ```rust
  password: RedactedSecret,
  ```

- [ ] **Step 4: Fix the SOCKS call site**

In `src/ssh/client.rs`, the SOCKS branch around line 452 passes `pass` (now `&RedactedSecret`) into `tokio_socks`. Make the `&str` explicit so it is robust against a generic signature. Change the password argument from `pass` to `pass.as_str()`:

```rust
        if let (Some(user), Some(pass)) = (&socks.username, &socks.password) {
            tokio_socks::tcp::Socks5Stream::connect_with_password(
                proxy_addr.as_str(),
                target_addr,
                user,
                pass.as_str(),
            )
            .await
            .map_err(map_err)?
```

(The `AuthConfig::Key` passphrase site at `client.rs:545` — `passphrase.as_ref().map(|s| s.as_str())` — and the `auth_with_password` site already work: `as_str()` exists on `RedactedSecret` and `&RedactedSecret` coerces to `&str`. No change needed there.)

- [ ] **Step 5: Build to find any remaining call sites**

Run: `cargo build --lib --all-features 2>&1 | tail -30`
Expected: clean build. If the compiler flags a construction site (e.g. a test building `AuthConfig::Password { password: Zeroizing::new(...) }` or `sudo_password: Some("x".to_string())`), fix it to `RedactedSecret::from(...)`. The `--all-features` flag ensures the `winrm`/`socks` `#[cfg]` paths compile.

- [ ] **Step 6: Run the config + ssh tests to verify they pass**

Run: `cargo test --lib config:: 2>&1 | tail -25`
Expected: PASS — including `host_config_debug_does_not_leak_password`, `test_auth_config_password_serialization` (now asserts redaction), and all deserialization round-trip tests (deserialize still reads plain YAML/JSON strings).

Run: `cargo test --lib ssh::client 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 7: Lint**

Run: `cargo clippy --lib --all-features 2>&1 | tail -20`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add src/config/types.rs src/ssh/client.rs
git commit -m "refactor(config): use RedactedSecret for SSH/SOCKS/sudo credentials (fixes F1/F2 leak)"
```

---

### Task 3: Protect the AWX OAuth token (F3)

**Files:**
- Modify: `src/config/types.rs` (`AwxConfig::token`, ≈line 59)

- [ ] **Step 1: Write the failing test**

In the `tests` module of `src/config/types.rs`, add:

```rust
    #[test]
    fn awx_token_is_redacted_in_debug() {
        let awx = AwxConfig {
            ssh_host: "h".to_string(),
            url: "https://awx".to_string(),
            token: RedactedSecret::from("awx-oauth-token-123"),
            api_timeout: 30,
            verify_ssl: true,
        };
        let rendered = format!("{awx:?}");
        assert!(
            !rendered.contains("awx-oauth-token-123"),
            "AwxConfig Debug leaked the token: {rendered}"
        );
    }
```

(If `AwxConfig` has additional fields, match the actual struct definition at `types.rs:51` — keep every field, only `token` uses `RedactedSecret`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib config::types::tests::awx_token_is_redacted_in_debug 2>&1 | tail -15`
Expected: compile error — `token` field still expects `String`.

- [ ] **Step 3: Swap the field type**

In `src/config/types.rs`, change `AwxConfig::token` (≈line 59) from:

```rust
    pub token: String,
```

to:

```rust
    pub token: RedactedSecret,
```

- [ ] **Step 4: Build to confirm call sites coerce**

Run: `cargo build --lib --all-features 2>&1 | tail -20`
Expected: clean build. The ~16 handlers passing `&awx.token` to use-case functions taking `token: &str` deref-coerce automatically. If any AWX test constructs `AwxConfig { token: "...".to_string(), .. }`, change it to `token: "...".into()`.

- [ ] **Step 5: Run AWX + config tests to verify they pass**

Run: `cargo test --lib awx 2>&1 | tail -20 && cargo test --lib config::types 2>&1 | tail -15`
Expected: PASS — including `awx_token_is_redacted_in_debug`.

- [ ] **Step 6: Commit**

```bash
git add src/config/types.rs
git commit -m "fix(config): wrap AwxConfig token in RedactedSecret (fixes F3 — zeroize + redact)"
```

---

### Task 4: Add `Bearer` sanitizer pattern (F4, independent)

**Files:**
- Modify: `src/security/sanitizer.rs` (pattern definitions + a test)

- [ ] **Step 1: Write the failing test**

In the `tests` module of `src/security/sanitizer.rs`, add:

```rust
    #[test]
    fn test_bearer_opaque_token_redacted() {
        let sanitizer = Sanitizer::with_defaults();
        let input = "curl -H 'Authorization: Bearer A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6'";
        let out = sanitizer.sanitize(input);
        assert!(
            !out.contains("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"),
            "opaque bearer token leaked: {out}"
        );
        assert!(out.contains("[BEARER_TOKEN_REDACTED]"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib security::sanitizer::tests::test_bearer_opaque_token_redacted 2>&1 | tail -15`
Expected: FAIL — `assert!(out.contains("[BEARER_TOKEN_REDACTED]"))` fails (no such pattern; entropy detector either substitutes a different marker or, if disabled, leaves the token).

- [ ] **Step 3: Add the pattern definition**

In `src/security/sanitizer.rs`, locate the TIER 1 "Highly Specific Patterns" block (around line 417, where `ghp_` / GitHub patterns are defined as `PatternDef` entries). Add a new entry alongside them, matching the existing `PatternDef` struct shape used in that file:

```rust
        // Authorization: Bearer <opaque-token> — closes the gap when the
        // entropy detector is disabled. Placed in TIER 1 so it runs before
        // the generic token patterns.
        PatternDef {
            name: "bearer_token",
            pattern: r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}",
            replacement: "Bearer [BEARER_TOKEN_REDACTED]",
        },
```

Use the exact field names of the local `PatternDef` struct (check the surrounding entries — they may be `name` / `pattern` / `replacement` or a tuple; match what is already there). The replacement keeps the literal `Bearer ` prefix and redacts only the token so the line stays readable.

If the sanitizer keeps a "keyword pre-filter" list (Aho-Corasick literals, around line 290), confirm `"bearer"` is already present (it is, at `sanitizer.rs:297`) so the pattern is reached.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --lib security::sanitizer::tests::test_bearer_opaque_token_redacted 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Run the full sanitizer suite (guard against pattern regressions)**

Run: `cargo test --lib security::sanitizer 2>&1 | tail -25`
Expected: PASS — in particular the existing `test_pattern_count` (asserts `>= 50` builtin patterns) still holds, and the JWT bearer test `sanitizer.rs:1239` still passes (JWT pattern is more specific and ordered before this one, or both redact — verify the JWT test still asserts its `[JWT_TOKEN_REDACTED]` marker; if the new pattern now wins on JWT input, relax that test to assert "no cleartext token" rather than the specific marker).

- [ ] **Step 6: Lint + commit**

Run: `cargo clippy --lib 2>&1 | tail -15`
Expected: no warnings.

```bash
git add src/security/sanitizer.rs
git commit -m "feat(security): redact opaque Authorization: Bearer tokens (fixes F4)"
```

---

### Task 5: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Run the quick CI gate**

Run: `make ci 2>&1 | tail -40`
Expected: `fmt-check`, `lint`, `test`, `audit`, `typos` all green. (Per WSL safety rules, this uses default parallelism — do not raise `-j`.)

- [ ] **Step 2: Confirm no secret type still derives a leaking Debug/Serialize**

Run: `grep -rn 'Zeroizing<String>' src/ --include='*.rs'`
Expected: no matches in `config/types.rs` field declarations (only — if any — inside `secret.rs` as the newtype's inner type). Any remaining hit is a missed secret field; wrap it in `RedactedSecret`.

- [ ] **Step 3: Commit any formatting fixups**

```bash
cargo fmt
git diff --quiet || git commit -am "style: rustfmt after RedactedSecret migration"
```

---

## Self-Review

**Spec coverage:**
- F1 (Debug leak) → Task 1 (`debug_does_not_leak`) + Task 2 (`host_config_debug_does_not_leak_password`). ✓
- F2 (Serialize leak) → Task 1 (`serialize_does_not_leak`) + Task 2 (updated `test_auth_config_password_serialization`). ✓
- F3 (AWX token) → Task 3. ✓
- F4 (Bearer) → Task 4. ✓
- F5 → intentionally out of scope (documented above). ✓

**Type consistency:** `RedactedSecret::new`, `::from`, `::as_str`, `Deref<Target = str>`, `Serialize`→`"[REDACTED]"`, `Debug`→`"[REDACTED]"` are defined in Task 1 and used identically in Tasks 2–3. Field types swapped consistently (`Option<RedactedSecret>` for optional secrets, `RedactedSecret` for required ones).

**Placeholder scan:** all code steps contain concrete code; line numbers are marked `≈` because they drift, with an anchoring symbol name for each. The only deliberately conditional step is the `PatternDef` field-name match in Task 4 Step 3 (the local struct shape must be read from the file) — anchored to the GitHub-pattern block.

**Risk notes for the executor:**
- Deserialization is unchanged in behavior (still reads a plain YAML/JSON string), so existing config files and round-trip *deserialize* tests keep working. Only *serialize* output changes (now redacted) — that is the intended fix.
- Build with `--all-features` at least once (Task 2 Step 5) to compile the `winrm` (`Ntlm`) and `socks` `#[cfg]` paths.
