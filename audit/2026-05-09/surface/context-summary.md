# Audit 2026-05-09 — Architectural Context Summary (Phase B+C, audit-context-building)

**Project:** `mcp-ssh-bridge` (Rust 2024, MCP SSH bridge)
**Branch:** `security/audit-2026-05-09`
**Skill:** `audit-context-building:audit-context-building` (trailofbits, v1.1.0)
**Mode:** Pure context building — no findings, no severities, no PoCs.
**Output target rationale:** Phase 1 orientation + Phase 2 ultra-granular function analysis on the 6 highest-risk surfaces. Each subagent ran the full per-function microstructure checklist (Purpose / Inputs+Assumptions / Outputs+Effects / Block-by-Block / Cross-Function Dependencies / Open questions) under skill resources `OUTPUT_REQUIREMENTS.md` and `COMPLETENESS_CHECKLIST.md`.

## Phase 1 — Initial Orientation

### Top-level src/ modules (19 dirs)

`cli`, `cloud_exec`, `config`, `daemon`, `domain`, `error.rs`, `k8s_exec`, `lib.rs`, `main.rs`, `mcp`, `metrics.rs`, `ports`, `psrp`, `security`, `serial_port`, `ssh`, `ssm`, `telemetry.rs`, `telnet`, `winrm`

### Security / SSH / MCP density (LOC, top 20)

| Module | LOC |
|---|---|
| src/mcp/server.rs | 4204 |
| src/security/sanitizer.rs | 2012 |
| src/ssh/sftp.rs | 1793 |
| src/ssh/client.rs | 1633 |
| src/ssh/session.rs | 1476 |
| src/security/audit.rs | 1168 |
| src/ssh/pool.rs | 1015 |
| src/security/validator.rs | 932 |
| src/ssh/retry.rs | 927 |
| src/mcp/transport/http.rs | 900 |
| src/security/recording.rs | 791 |
| src/mcp/transport/oauth.rs | 499 |
| src/domain/runbook.rs | 429 |
| src/ssh/known_hosts.rs | 397 |
| src/security/entropy.rs | 386 |
| src/security/rate_limiter.rs | 383 |
| src/security/rbac.rs | 305 |
| src/mcp/transport/stdio.rs | 283 |
| src/mcp/transport/unix_socket.rs | 263 |

### MCP tool handler distribution (357 total)

| group prefix | count |
|---|---|
| ssh_win_* | 44 |
| ssh_net_* | 14 |
| ssh_awx_* | 13 |
| ssh_docker_* | 11 |
| ssh_service_* | 9 |
| ssh_k8s_* | 9 |
| ssh_ansible_* | 9 |
| ssh_hyperv_* | 8 |
| ssh_file_* | 8 |
| ssh_storage_* | 7 |
| ssh_helm_* | 7 |
| ssh_git_* | 7 |
| ssh_esxi_* | 7 |
| ssh_podman_* | 6 |
| ssh_iis_* | 6 |
| ... (60 other groups, see audit/2026-05-09/surface/entry-points.md to be produced in Task 6) |

### Architecture confirmed (per project CLAUDE.md hexagonal layout)

- **Adapters**: `src/mcp/` (JSON-RPC), `src/ssh/` (russh), `src/winrm/`, `src/psrp/`, `src/telnet/`, `src/serial_port/`, `src/k8s_exec/`, `src/cloud_exec/`, `src/ssm/`, `src/config/` (serde-saphyr YAML)
- **Ports** (traits): `src/ports/` — `executor.rs`, `executor_router.rs`, `protocol.rs`, `tools.rs`, `prompts.rs`, `resources.rs`, `completions.rs`, `connector.rs`, `ssh.rs`
- **Domain**: `src/domain/use_cases/` (65 modules, command builders), `src/domain/runbook.rs`, `src/security/`

---

## Phase 2 — Ultra-Granular Function Analysis (6 high-risk surfaces)

The six analysed surfaces below were selected because they are the smallest possible cut that covers (a) the validator gate, (b) both Vuln 8/9 patched surfaces, (c) the JWT auth path, (d) SSH host-key + auth, and (e) the YAML loader flagged in Task 4 context7 drift findings. Each section is self-contained and uses line:number citations.


---


---

## `src/security/validator.rs` — Ultra-Granular Function Context

**File:** `/home/muchini/mcp-ssh-bridge/src/security/validator.rs`
**LOC:** 932 (232 production, 700 test)
**Module path:** `crate::security::validator` — re-exported as `crate::security::CommandValidator`
**Relevant commit context:** fix `868d3b7` added `normalize_for_blacklist_match` to prevent `${IFS}`/`$'\t'`/line-continuation bypass of whitespace-expecting blacklist regexes.

---

## Architectural Overview (Pre-Function Context)

`CommandValidator` sits at the innermost gate of all command-execution paths. The call graph is:

```
MCP JSON-RPC client (untrusted)
  → McpServer::handle_tools_call
    → ToolContext (DI container, tools.rs)
      → ExecuteCommandUseCase::execute          (user-facing ssh_exec / ssh_session_exec)
          → CommandValidator::validate()         ← primary gate
      → ExecuteCommandUseCase::validate_builtin  (specialized tool handlers)
          → CommandValidator::validate_builtin() ← secondary gate (whitelist-exempt)
```

The `CommandValidator` is held inside `Arc<CommandValidator>` in `ToolContext` (tools.rs L64), created once at server startup from a `SecurityConfig`, and shared via `Arc::clone` to every handler. It can be hot-reloaded via `reload()` while handlers hold concurrent read locks.

---

## Function 1: `normalize_for_blacklist_match` (L55–L63)

### 1. Purpose

Translates shell-level whitespace-encoding tricks into plain ASCII spaces before the blacklist regex runs. Without this layer, blacklist patterns that match on literal whitespace between tokens (e.g., `rm\s+-rf`) can be defeated by substituting `${IFS}`, `$'\t'`, `$'\n'`, or a line-continuation sequence that a POSIX shell will silently collapse. The function was introduced by the fix referenced as `868d3b7` and corresponds to the `validate_blocks_*` test group (L839–L893).

### 2. Inputs and Assumptions

| Parameter | Type | Trust Level |
|---|---|---|
| `input` | `&str` | Untrusted — derived from MCP client command field after `.trim()` at L142/L203 |

**Assumptions:**
1. `input` has already been `.trim()`-ed by the caller (`validate` L142, `validate_builtin` L203); leading/trailing whitespace removal happened before normalization.
2. The function operates on the UTF-8 string value as-is; it does not escape, decode URL encoding, or handle any other encoding layer.
3. The caller is responsible for running blacklist regexes against the returned `String`, not the original input.
4. The set of shell expansion tokens to collapse is currently fixed to: `\\\n`, `${IFS}`, `$IFS`, `$'\t'`, `$'\n'`, `$' '`. No other expansions (e.g., `$'\r'`, `$'\x09'`, tab literals) are handled.
5. The function makes no assumptions about whether the input is a single command or a semicolon/pipe-chained compound command; it normalizes the entire string uniformly.
6. The returned `String` is ephemeral — used only for the blacklist regex match; it is never stored, logged, or returned to the caller.

### 3. Outputs and Effects

- Returns an owned `String` with the specified sequences replaced by a single ASCII space (`' '`).
- No state mutation (pure function with no side effects).
- No external interactions.
- The original `input` is not modified (immutable borrow).
- The whitelist match in `validate()` L174 still runs against the raw (pre-normalization) input, preserving strict-mode equality semantics.

### 4. Block-by-Block Analysis

**L56: `let mut s = input.replace("\\\n", " ");`**
- **What:** Replaces every occurrence of a literal backslash followed by a newline (line continuation) with a space.
- **Why here:** Line continuation must be resolved first because `\<NL>` is a two-character token; none of the subsequent substitutions can overlap with it.
- **Assumptions:** `input` may contain embedded newlines (test `test_command_with_newlines` L558 confirms newlines are legal). The `\<NL>` sequence is exactly the POSIX definition of line continuation when inside a shell command.
- **Depends on:** Nothing prior; this is the first transformation.
- **First Principles:** In POSIX sh, `rm \<NL>-rf /` is lexically identical to `rm -rf /`. If the blacklist pattern reads `rm\s+-rf\s+/`, the literal `\<NL>` without normalization would not match `\s+` because regex `.` by default does not cross lines and `\s` would match `\n` but not `\<NL>` as a unit — the backslash would break the token. Replacement with a space makes the compound token visible to the regex.

**L57: `s = s.replace("${IFS}", " ").replace("$IFS", " ");`**
- **What:** Replaces `${IFS}` then `$IFS` with a space.
- **Why here:** Applied after line-continuation so that `$IFS` embedded inside a continuation sequence is handled correctly. The longer token `${IFS}` is matched first — if `$IFS` were first, `${IFS}` could partially match but the `{` and `}` would remain.
- **Assumptions:** Only the default IFS character (space) is modeled. Custom IFS assignments (`IFS=:`) are not intercepted at this layer; the validator has no shell evaluation context, so custom IFS is out of scope.
- **5 Whys (why is IFS handled here and not upstream?):**
  1. Why not block `${IFS}` in a dedicated pattern? Because pattern count grows combinatorially with every evasion permutation.
  2. Why not forbid `$` in all commands? That would block legitimate variable references in strict-mode whitelisted scripts.
  3. Why not shell-parse the command? Shell parsing is contextual and would require embedding a POSIX lexer.
  4. Why is normalization before the regex sufficient? Because the blacklist regex only needs to match the token sequence, not the exact whitespace encoding.
  5. Why does `$IFS` come second? To avoid the edge case where `"$IFS"` matches inside `"${IFS}"` before the braces are consumed.

**L58–L61: ANSI-C quoted whitespace replacements**
- **What:** Replaces `$'\t'`, `$'\n'`, `$' '` with a space.
- **Why here:** `$'...'` is bash-specific ANSI-C quoting (also supported by zsh, ksh). These three escape sequences expand to horizontal tab, newline, and space respectively at shell runtime; they are semantically identical to whitespace between command tokens.
- **Assumptions:** Only the three whitespace-valued sequences are targeted. Other `$'...'` sequences (e.g., `$'\x41'` = 'A', `$'\u0041'`) are NOT collapsed; those are handled by the caller's blacklist patterns if relevant. This is a deliberate, bounded normalization scope.
- **Depends on:** `s` produced by the prior two substitutions.
- **5 Hows (how could a character get through this normalization):**
  1. A tab literal embedded directly in the command string (ASCII 0x09) — `\s` in the regex does match literal tabs, so the blacklist would still fire.
  2. `$'\x09'` (hex-encoded tab) — NOT normalized; unclear whether default blacklist patterns cover it. Need to inspect.
  3. `$'\011'` (octal-encoded tab) — NOT normalized; same uncertainty.
  4. `${IFS:-" "}` (default-value expansion of IFS) — NOT normalized; would arrive to the regex as literal `${IFS:-" "}`.
  5. Unicode zero-width space (U+200B) — NOT normalized; regex `\s` does not match Unicode whitespace by default in the `regex` crate.

### 5. Cross-Function Dependencies

- Called exclusively by `validate()` L155 and `validate_builtin()` L213.
- No external calls.
- The `regex` crate's `Regex::is_match` at L165 and L221 depends on the output of this function to perform the semantic match.

**Invariants:**
1. The returned string is always at least as long as zero characters (empty input would produce empty output, but callers already gate on non-empty at L145/L205).
2. Every byte of the original input is either preserved as-is or replaced by ASCII 0x20.
3. The transformation is idempotent for all currently handled token types (applying it twice produces the same result).

---

## Function 2: `CompiledPatterns::compile` (L19–L42)

### 1. Purpose

Transforms a `SecurityConfig` (raw string vectors of regex patterns) into a `CompiledPatterns` struct containing ready-to-use `Regex` objects. This amortizes compilation cost: each regex is compiled once at startup (or at reload), not on every validation call. Invalid patterns are silently skipped with an error log, avoiding server startup failures due to a misconfigured blacklist entry.

### 2. Inputs and Assumptions

| Parameter | Type | Trust Level |
|---|---|---|
| `config` | `&SecurityConfig` | Trusted — originates from YAML config, validated at load time |

**Assumptions:**
1. `config.whitelist` and `config.blacklist` are `Vec<String>` slices of POSIX-compatible regex patterns; the `regex` crate is the compiler — not PCRE, not POSIX ERE.
2. An invalid regex pattern produces a `tracing::error` log and is silently excluded from the compiled set (L23–L25, L30–L32). The remaining valid patterns still apply.
3. The `config.mode` field is copied (`Copy` trait via `#[derive(Clone, Copy)]` on `SecurityMode`) — no shared reference retained after construction.
4. The `whitelist` and `blacklist` vectors may be empty; both empty is a valid configuration (produces permissive-with-no-whitelist behavior depending on mode).
5. Compilation is synchronous and may block for pathologically complex regex patterns (ReDoS risk is borne by the regex compiler, not the runtime matcher in most engines; however, `regex` crate uses a DFA-based engine with bounded compile time).
6. No pattern deduplication occurs — the same pattern string appearing twice will produce two `Regex` objects and will be matched twice per command.

### 3. Outputs and Effects

- Returns a `CompiledPatterns` struct owning the compiled `Regex` objects and the current `SecurityMode`.
- Side effect: `tracing::error!` calls for each invalid pattern (L24, L32).
- No state mutation at the caller level.
- No external I/O.

### 4. Block-by-Block Analysis

**L20–L25: whitelist compilation loop**
- **What:** Iterates `config.whitelist`, compiles each, pushes valid regexes.
- **Why here:** Whitelist must be compiled before the struct is returned; lazy compilation would require locking per call.
- **Assumptions:** `Regex::new` is infallible for any syntactically valid regex; any error is a user config error.
- **Depends on:** `config.whitelist` being a well-formed slice (guaranteed by serde deserialization from YAML).

**L27–L34: blacklist compilation loop**
- **What:** Same as whitelist loop, for the blacklist vector.
- **Why here:** Same rationale. Both lists are compiled in separate loops, not interleaved, to maintain structural clarity in the output struct.
- **First Principles:** If blacklist compilation failed hard (panic or error propagation), a misconfigured pattern would prevent the server from starting. The silent-skip design trades correctness-of-intention (operator meant to block X but misspelled the regex) for availability (server stays up). The `tracing::error` provides the observable signal, but only if log output is being monitored.

### 5. Cross-Function Dependencies

- Called by `CommandValidator::new()` L104 and `CommandValidator::reload()` L113.
- The `Regex` type comes from the `regex` crate — no adversarial external call; `Regex::new` is an in-process compile step.

**Invariants:**
1. The number of compiled patterns in `whitelist` is at most `config.whitelist.len()` and at least 0.
2. The number of compiled patterns in `blacklist` is at most `config.blacklist.len()` and at least 0.
3. `mode` is always a valid `SecurityMode` variant (Copy of the config field).

---

## Function 3: `CommandValidator::new` (L101–L106)

### 1. Purpose

Constructor. Takes a `SecurityConfig` reference, compiles all patterns immediately, and wraps the result in an `RwLock` for concurrent access.

### 2. Inputs and Assumptions

**Assumptions:**
1. Called once at server startup from `ToolContext::new()` — at this point `Config` is fully loaded and validated.
2. The `#[must_use]` attribute (L101) prevents callers from silently discarding the validator.
3. `RwLock::new` is infallible in Rust's standard library.
4. The resulting `CommandValidator` will be wrapped in `Arc` at the call site (tools.rs L529, L583, etc.) to enable shared ownership across handler tasks.
5. `SecurityConfig::default()` (used in all test factories: tools.rs L529, L583, L639, L678) produces `SecurityMode::Standard` and the 35-pattern default blacklist (`default_blacklist()` in types.rs L638–L686). All test contexts created via `create_test_context*` factories therefore use Standard mode with the full default blacklist, not an empty config.

### 3. Outputs and Effects

- Returns a `CommandValidator` value.
- Triggers `CompiledPatterns::compile` which may emit `tracing::error` for invalid patterns.

### 4. Block-by-Block Analysis

**L103–L105: struct literal construction**
- **What:** Wraps compiled patterns in `RwLock<CompiledPatterns>`.
- **Why here:** `RwLock` allows multiple concurrent readers (validation calls) and exclusive writers (reload calls). This is the correct synchronization primitive for read-heavy, write-rare workloads.
- **Assumptions:** No async context at construction time; `RwLock` here is `std::sync::RwLock`, not `tokio::sync::RwLock`. This is consistent — the validator's `validate()` and `validate_builtin()` methods are synchronous (not `async`).
- **5 Hows (how is thread safety achieved):**
  1. Concurrent `validate()` calls each call `self.patterns.read()` — multiple readers, no writer → all proceed simultaneously.
  2. A concurrent `reload()` calls `self.patterns.write()` — all readers block until the write lock is released.
  3. Lock poisoning after a `validate()` panic is handled by `unwrap_or_else(PoisonError::into_inner)` at L161 and L217 — the stale pre-panic state is used rather than propagating an unrecoverable error.
  4. `Arc<CommandValidator>` ensures the `RwLock` itself is not dropped while any handler holds a clone.
  5. Reload atomicity: `CompiledPatterns::compile` runs outside the write lock (L113), then the write lock is acquired for the swap (L115) — minimizing lock hold time.

### 5. Cross-Function Dependencies

- Calls `CompiledPatterns::compile`.
- Called by tools.rs mock factories (L529, L583, L639, L678) and production wiring in the MCP server startup path (not visible in the four read files; unclear — need to inspect `src/mcp/server.rs` or `src/main.rs`).

**Invariants:**
1. Post-construction, `self.patterns.read()` always succeeds unless a prior thread panicked inside `validate()`.
2. The compiled state is immediately usable; no deferred initialization.
3. The `RwLock` is never in a permanently poisoned state in normal operation (panics in `validate()` would have to be deliberately induced — `#![forbid(unsafe_code)]` and no panicking operations in the hot path).

---

## Function 4: `CommandValidator::reload` (L112–L128)

### 1. Purpose

Hot-replaces the compiled pattern set without stopping the server or invalidating existing `Arc<CommandValidator>` references. Called by the `ConfigWatcher` subsystem when the YAML config file changes on disk, or by `ssh_config_set` tool handler.

### 2. Inputs and Assumptions

**Assumptions:**
1. `config` is a freshly loaded, validated `SecurityConfig` — assumed to come from the same YAML loader that validated it at startup.
2. The caller ensures `config` represents a coherent new state; there is no diff validation against the existing state.
3. Concurrent `validate()` calls proceed without blocking during the `compile()` phase (L113) because compilation runs before the write lock is acquired.
4. If the write lock is poisoned (L124), the reload is silently skipped; an error is logged but the in-memory state remains at the pre-reload configuration.
5. The reload is non-transactional: if the process crashes between `compile()` and the `write()` swap, the old config remains active with no partial state left behind (Rust's ownership model guarantees `new_patterns` is either fully swapped or dropped).
6. There is no rate limit on reload calls; a malicious `ssh_config_set` invocation could repeatedly trigger reloads to cause CPU load from repeated regex compilations.

### 3. Outputs and Effects

- Swaps `self.patterns` under `write()` lock.
- Emits `tracing::info` on success (L116–L122) with mode and pattern counts — these counts include only successfully compiled patterns, not the raw config counts. Unclear: need to inspect whether the log messages report `config.whitelist.len()` (raw) or `new_patterns.whitelist.len()` (compiled). The code at L119–L120 uses `config.whitelist.len()` and `config.blacklist.len()` — raw counts, which may be higher than compiled counts when invalid patterns exist.
- Emits `tracing::error` on lock-poison failure (L125–L127).

### 4. Block-by-Block Analysis

**L113: `let new_patterns = CompiledPatterns::compile(config);`**
- **What:** Compiles the new pattern set outside the lock.
- **Why here:** Expensive regex compilation must not hold the write lock. This is the double-checked-locking-equivalent optimization: compile first, swap atomically.
- **Depends on:** `config` being valid; compilation may silently drop patterns.

**L114–L127: write-lock acquisition and swap**
- **What:** Acquires exclusive lock, replaces `*guard` with `new_patterns`.
- **Why here:** The `*guard = new_patterns` assignment is the only mutation; keeping it inside the lock scope minimizes the critical section.
- **Assumptions:** `PoisonError` is treated as non-recoverable at the logger level — the reload is abandoned, preserving old state.
- **First Principles:** Swap-under-write-lock is the only correct approach here. An alternative (atomic pointer swap) would require `unsafe` code, violating `#![forbid(unsafe_code)]`. The `RwLock` swap is safe and correct.

### 5. Cross-Function Dependencies

- Calls `CompiledPatterns::compile`.
- Called by config watcher (unclear location — need to inspect config/watcher.rs).
- Concurrent with `validate()` and `validate_builtin()` — validated by `test_concurrent_validate_during_reload` (L896–L931).

**Invariants:**
1. At any point, `self.patterns` contains a fully consistent `CompiledPatterns` — never a partially updated state.
2. If `compile()` drops invalid patterns, the reload log may report counts inconsistent with the active compiled pattern count.
3. After a failed reload (lock poison), the validator continues operating on the pre-reload config — no indication to callers that reload failed.

---

## Function 5: `CommandValidator::validate` (L141–L190)

### 1. Purpose

The primary command gate for all user-facing execution paths: `ssh_exec`, `ssh_session_exec`, and any other tool that submits raw user-controlled command strings. It enforces all three modes (Permissive, Standard, Strict), applies the IFS/ANSI-C normalization before the blacklist check, and applies the whitelist against the **raw** (unnormalized) input in strict/standard modes.

### 2. Inputs and Assumptions

**Assumptions:**
1. `command` is completely untrusted — it originates from the MCP client JSON payload, deserialized from `serde_json::Value` and passed without further sanitization to this function.
2. The caller (typically `ExecuteCommandUseCase::execute`) does not pre-validate or truncate the command string; this function is the first and only semantic gate before execution.
3. The `patterns` lock is not poisoned in normal operation; the `unwrap_or_else(PoisonError::into_inner)` at L161 is a safety net for abnormal exits from concurrent validation threads.
4. `#[expect(clippy::significant_drop_tightening)]` at L140 suppresses a lint that would move the lock drop point earlier — the current drop point is at the end of the match block (L173–L187), which is the correct scope.
5. The default `SecurityMode` is `Standard` (types.rs L634) — meaning the whitelist check at L173 runs by default in all production configurations that have not overridden the mode.
6. `SecurityConfig::default().whitelist` is an empty `Vec` (types.rs L515) — meaning in `Standard` mode with no explicit whitelist configured, `validate()` denies **all** commands. Only `validate_builtin()` paths succeed. This is the effective default posture, confirmed by test `test_standard_mode_empty_whitelist_blocks_raw_exec` (L769–L777).

### 3. Outputs and Effects

- Returns `Ok(())` if the command passes all applicable checks.
- Returns `Err(BridgeError::CommandDenied { reason })` for any of three rejection conditions:
  1. Empty (post-trim) command (L146–L149).
  2. Blacklist pattern match on normalized command (L164–L169).
  3. No whitelist match on raw command in strict/standard mode (L174–L186).
- No state mutation.
- The `reason` string in `BridgeError::CommandDenied` includes the matched pattern string for blacklist rejections, and the mode name for whitelist rejections. The matched pattern string is the `{pattern}` Display of the compiled `Regex` — it is the original pattern text, which can be read from logs.

### 4. Block-by-Block Analysis

**L142: `let raw = command.trim();`**
- **What:** Strips leading/trailing ASCII whitespace.
- **Why here:** Before any other check, to avoid false positives from surrounding whitespace and to canonicalize the empty-command check.
- **Assumptions:** `.trim()` uses Rust's Unicode whitespace definition; this may strip more than POSIX `IFS` would. The returned slice `raw` borrows from `command`.

**L145–L149: empty-command rejection**
- **What:** Rejects commands that are empty or whitespace-only after trim.
- **Why here:** An empty command would trivially pass all regex checks (no pattern matches empty string by accident); explicit rejection prevents ambiguous empty-string executions.
- **Assumptions:** A command that is purely whitespace post-trim is semantically empty. Test `test_whitespace_only_command_rejected` (L817–L824) confirms this.

**L155: normalization call**
- **What:** Calls `normalize_for_blacklist_match(raw)` to produce `normalized_for_match`.
- **Why here:** Must occur before the lock acquisition to keep the critical section minimal. The normalized string is local; no lock is held during normalization.
- **Assumptions:** `raw` is the trimmed input. The normalization does not affect whitelist matching (which uses `raw`, not `normalized_for_match`).

**L157–L161: read-lock acquisition**
- **What:** Acquires a shared read lock on `self.patterns`.
- **Why here:** Lock is acquired after normalization (cheap CPU work done outside lock) and held through both the blacklist and whitelist checks to ensure they see a consistent pattern set.
- **Assumptions:** `PoisonError::into_inner` recovers the guard from a poisoned lock — this permits validation to continue with the pre-panic pattern state. This is a deliberate resilience choice over failing closed.

**L163–L169: blacklist check (always applies)**
- **What:** Iterates all compiled blacklist regexes; if any matches the normalized command, returns `CommandDenied`.
- **Why here:** Blacklist is checked first, before the whitelist. This ensures a whitelisted command that also matches a blacklist pattern is rejected. Test `test_blacklist_overrides_whitelist` (L280–L291) encodes this invariant.
- **Assumptions:** `pattern.is_match(&normalized_for_match)` uses the full-text match (not anchored); a pattern can match anywhere in the command string. The default blacklist patterns use `(?i)` for case-insensitive matching (types.rs L640–L686).
- **5 Whys (why normalized string, not raw, for blacklist):** Because the fix `868d3b7` determined that `rm${IFS}-rf${IFS}/` would not be caught by `rm\s+-rf\s+/` without normalization. Raw matching allows evasion; normalized matching restores the intent of whitespace-based pattern tokens.

**L172–L187: whitelist check (strict/standard mode only)**
- **What:** In `Strict` or `Standard` mode, checks whether any compiled whitelist pattern matches the **raw** command. Denies if no match.
- **Why here:** Applied after blacklist — a command must clear both gates in strict/standard mode.
- **Assumptions:** The whitelist check runs against `raw` (pre-normalization), NOT against `normalized_for_match`. This means a command using `${IFS}` may still fail the whitelist check even if it would survive a normalized blacklist check. The asymmetry is intentional (doc comment at L152–L154: "strict-mode whitelisting still requires byte-for-byte equality").
- **5 Hows (how does a command pass strict mode):**
  1. The raw command (post-trim) must match at least one whitelist regex.
  2. Whitelist patterns use `Regex::is_match` — anchored matching requires explicit `^`/`$` in the pattern.
  3. Test `test_whitelist_exact_match` (L649–L658) shows that `^ls$` allows only exactly `ls`, not `ls -la`.
  4. Test `test_whitelist_prefix_match` (L661–L669) shows that `^ls\b` allows `ls` and `ls -la` but not `lsblk`.
  5. Whitelist patterns have no normalization applied; `ls${IFS}-la` would not match the pattern `^ls\b` in strict mode, even though after normalization it reads as `ls -la`.

### 5. Cross-Function Dependencies

- Calls `normalize_for_blacklist_match` (L155).
- Called by `ExecuteCommandUseCase::execute` (inferred from architecture; the use case L165 delegates to `self.validator.validate_builtin` for the builtin path — the `validate()` path is called at the `ssh_exec` handler level).
- Shares `self.patterns` with `validate_builtin()` and `reload()`.

**Invariants:**
1. Blacklist always runs, regardless of mode — test `test_validate_builtin_still_checks_blacklist` (L723–L731) and `test_standard_mode_blacklist_overrides_whitelist` (L780–L789) confirm this for both `validate` and `validate_builtin`.
2. Whitelist runs only in `Strict` or `Standard` mode — in `Permissive` mode, the `if matches!(...)` at L173 short-circuits.
3. The command that reaches the SSH executor has been confirmed to not match any blacklist pattern and (in strict/standard mode) to match at least one whitelist pattern.

---

## Function 6: `CommandValidator::validate_builtin` (L201–L230)

### 1. Purpose

A reduced-gate variant of `validate()` intended exclusively for tool handlers that construct commands internally through domain builders (e.g., `ssh_docker_ps` builds `docker ps --format ...`, not arbitrary user input). It skips the whitelist check unconditionally, applying only the blacklist and empty-command checks. This enables specialized tools to function in Strict and Standard modes without requiring every internally generated command to appear in the operator's whitelist.

### 2. Inputs and Assumptions

**Assumptions:**
1. `command` is **trusted at construction** — it was assembled by a domain builder function (e.g., `build_docker_command`, `build_k8s_command`) that concatenates fixed strings and operator-controlled config values, not raw MCP client input. This is a design assumption, not enforced by the type system.
2. User-controlled parameters (e.g., container names, service names) may still appear as substrings of the command string if the domain builder embeds them without full escaping. The blacklist is therefore not merely a formality — it is the only runtime gate against an argument that unexpectedly contains a blacklisted token.
3. The trust assumption is documented in L193–L196 of the doc comment: "specialized tool handlers that build commands internally via trusted domain command builders".
4. There is no mechanism to verify at the call site that the command was indeed constructed by a domain builder; calling `validate_builtin` on a raw user command would silently skip the whitelist check.
5. The `#[expect(clippy::significant_drop_tightening)]` attribute at L201 suppresses the same lint as in `validate()`.
6. Empty command detection (L205–L208) is identical to `validate()` — both produce the same error variant and message.

### 3. Outputs and Effects

- Returns `Ok(())` if command is non-empty and passes the blacklist.
- Returns `Err(BridgeError::CommandDenied { reason })` for empty or blacklisted commands.
- Does NOT check the whitelist under any mode.
- In `Permissive` mode, `validate()` and `validate_builtin()` are behaviorally identical — test `test_validate_builtin_in_permissive_mode` (L744–L751) encodes this.

### 4. Block-by-Block Analysis

**L203: `let raw = command.trim();`**
**L205–L208: empty-command rejection**
- **What/Why:** Identical logic to `validate()` L142–L149. This duplication is intentional — both gates must independently reject empty commands regardless of the code path.
- **Depends on:** Nothing; first check.

**L213: normalization call**
- **What:** `normalize_for_blacklist_match(raw)` — same call as in `validate()`.
- **Why here:** The normalization fix applies equally to builtin commands. A domain builder might embed `${IFS}` if user-supplied data (e.g., a service name) contained that string. Normalizing before the blacklist match is the correct default.
- **First Principles:** The blacklist is the only gate for builtin paths. If normalization were skipped here, a user could defeat the blacklist on the builtin path by crafting input (e.g., a container name) that becomes a blacklisted sequence when the domain builder concatenates it into a command string.

**L215–L218: read-lock acquisition**
- **What/Why:** Identical to `validate()`. Same lock, same poison recovery.
- **Assumptions:** Same as `validate()`.

**L220–L226: blacklist check**
- **What:** Identical blacklist iteration to `validate()`.
- **Why here:** This is the sole security gate for builtin paths. No whitelist check follows.
- **Assumptions:** The blacklist was compiled with the same patterns as available to `validate()`. No separate builtin blacklist exists; the same pattern set protects both paths.

### 5. Cross-Function Dependencies

- Calls `normalize_for_blacklist_match` (L213).
- Called by `ExecuteCommandUseCase::validate_builtin` (execute_command.rs L165–L166), which is called from `StandardTool` pipeline (standard_tool.rs L296) and from individual handler files (`ssh_disk_usage.rs` L116, `ssh_find.rs` L154, `ssh_tail.rs` L137, `ssh_metrics.rs` L145, `ssh_metrics_multi.rs` L197, `ssh_file_write.rs` L220).
- Shares `self.patterns` with `validate()` and `reload()`.

**Invariants:**
1. A command that would fail `validate()` due to the whitelist will pass `validate_builtin()` in any mode — this is the defining behavioral contract of the builtin path.
2. A command that fails `validate()` due to the blacklist will also fail `validate_builtin()` — both share the same blacklist and normalization logic.
3. The trust invariant is external to the code: callers must ensure that user-controlled values embedded in the command string are safely escaped before `validate_builtin()` is called. There is no type-level enforcement of this invariant.

---

## Trust Boundary Analysis

The key trust boundary in this module is the distinction between:

| Call Path | Entry Point | Whitelist Checked | Assumed Input Source |
|---|---|---|---|
| Raw user exec | `validate()` | Yes (Standard/Strict) | MCP client JSON — fully untrusted |
| Builtin tool exec | `validate_builtin()` | No | Domain builder output — assumed partially trusted |

The boundary is crossed at the `ExecuteCommandUseCase` level:
- `execute()` → `validate()` (tools that expose raw `command` parameter to MCP client)
- `validate_builtin()` → domain builder → `validate_builtin()` (tools that build commands internally)

The boundary is implicit and enforced by convention, not by type. A handler that calls `ctx.execute_use_case.validate_builtin` on a raw user value would bypass the whitelist silently.

The MCP client is the external adversarial principal. All data arriving via JSON-RPC `tools/call` parameters is untrusted until processed by `validate()`. The config file is trusted (file-permission checked at load time per config.md rule).

---

## Audit Logger Integration (from `audit.rs`)

When `validate()` returns `Err(BridgeError::CommandDenied)`, the caller (`ExecuteCommandUseCase::execute` or individual handlers) is responsible for logging an `AuditEvent::denied(host, command, reason)` event (audit.rs L49–L60). The audit event includes:

- `command`: the **original** MCP-client command (pre-normalization, pre-trim). Unclear whether trimming is applied before the audit event is constructed at the call site — need to inspect `execute_command.rs` caller.
- `reason`: the string from `BridgeError::CommandDenied { reason }`, which includes the matched blacklist pattern text.
- `event_type`: `"command_denied"` (audit.rs L52).

The `AuditLogger` applies sanitization (`Sanitizer`) to `event.command` before writing to disk (audit.rs L204–L205, L94–L96) — so even if a blacklisted command contains credential material, the audit trail will redact it if the sanitizer pattern matches.

---

## Default Blacklist Patterns — Production Coverage (from `types.rs` L638–L686)

The 35 default patterns are all `(?i)` case-insensitive. Key structural observations:

| Pattern | Matches | Normalized-input dependency |
|---|---|---|
| `(?i)rm\s+-rf\s+/` | `rm -rf /`, `rm  -rf  /` | Yes — IFS evasion now caught by normalization |
| `(?i)mkfs\.` | Any `mkfs.*` invocation | No whitespace token |
| `(?i)dd\s+if=` | `dd if=...` | Yes |
| `(?i)>\s*/dev/` | Redirect to device | Yes |
| `(?i)chmod\s+777` | `chmod 777 ...` | Yes |
| `(?i)curl.*\|.*sh` | Curl-pipe-to-shell | `.` matches any non-newline |
| `(?i)\bsystemctl\s+(stop\|disable\|isolate)\b` | Systemd disruption | Yes |
| `(?i)\biex\b` | PowerShell `Invoke-Expression` alias | No whitespace |
| `(?i)\bvault\s+(delete\|kv\s+delete)\b` | Vault key deletion | Yes |

Patterns using `\s+` between tokens are directly dependent on the normalization in `normalize_for_blacklist_match` to catch IFS/ANSI-C evasion. Patterns without whitespace tokens (e.g., `mkfs\.`, `\biex\b`) are normalization-independent.

---

## Test-Derived Invariants (from the `validate_blocks_*` Suite, L839–L893)

The normalization tests at L839–L893 encode the following invariants that must hold for the fix to be complete:

| Test | Invariant |
|---|---|
| `validate_blocks_ifs_substitution` (L843) | `rm${IFS}-rf${IFS}/` → denied (maps to default blacklist `rm\s+-rf\s+/`) |
| `validate_blocks_dollar_ifs_no_braces` (L856) | `rm $IFS-rf $IFS/` → denied |
| `validate_blocks_ansi_c_quoted_whitespace` (L866) | `rm$'\t'-rf$'\t'/` → denied |
| `validate_blocks_line_continuation` (L876) | `rm \\\n-rf /` → denied |
| `validate_passes_clean_safe_command_in_permissive` (L886) | `ls -la /tmp` → ok (regression check) |

All five tests use `SecurityConfig::default()` which activates `SecurityMode::Standard` and the default 35-pattern blacklist. They test the **combined** behavior of normalization + blacklist regex, not the normalization function in isolation.

---

## Cross-Function Call Chain (End-to-End)

```
MCP JSON-RPC: {"method":"tools/call","params":{"name":"ssh_exec","arguments":{"host":"pi","command":"rm${IFS}-rf${IFS}/"}}}
  ↓
McpServer::handle_tools_call (mcp/server.rs — not read)
  ↓
ToolContext.execute_use_case.execute(request)         [ExecuteCommandUseCase]
  ↓
CommandValidator::validate("rm${IFS}-rf${IFS}/")       [L141]
  ↓
  trim() → "rm${IFS}-rf${IFS}/"                        [L142]
  non-empty check → passes                              [L145]
  normalize_for_blacklist_match(...)
    .replace("${IFS}", " ") → "rm -rf /"               [L57]
  read-lock acquired                                    [L159]
  blacklist loop: pattern `(?i)rm\s+-rf\s+/`
    .is_match("rm -rf /") → true                       [L165]
  returns Err(CommandDenied{"matches blacklist: (?i)rm\\s+-rf\\s+/"})
  ↓
ExecuteCommandUseCase: logs AuditEvent::denied(host, original_command, reason)
  ↓
Handler returns error to McpServer
  ↓
McpServer serializes BridgeError → JSON-RPC error response to client
```

For the builtin path with `ssh_find`:

```
ssh_find handler: build_find_command(args) → "find /tmp -name '*.log' -mtime +7"
  ↓
ctx.execute_use_case.validate_builtin("find /tmp ...")
  ↓
CommandValidator::validate_builtin("find /tmp ...")    [L202]
  trim() → unchanged                                   [L203]
  non-empty → passes                                   [L205]
  normalize → unchanged (no IFS sequences)             [L213]
  blacklist loop → no match                            [L221]
  returns Ok(())
  ↓
executor.exec(...)
```

---

## Open Questions

1. **`$'\x09'` and `$'\011'` (octal/hex-encoded tab):** `normalize_for_blacklist_match` handles `$'\t'` but not the hex or octal equivalents. Clarify whether any default blacklist pattern could be evaded via these forms. Specifically: does `rm$'\x09'-rf$'\x09'/` reach the blacklist regex as `rm\t-rf\t/` (where `\t` is matched by `\s`)? The current normalization would NOT collapse `$'\x09'` — need to verify whether `\s` in the regex crate matches a literal tab character (it does), making this moot IF the tab reaches the regex as a literal byte. The question is whether bash actually sends the literal `$'\x09'` string or the expanded tab.

2. **`${IFS:-" "}` (default-value expansion):** Not normalized. If a client sends `rm${IFS:- }-rf${IFS:- }/`, the `${IFS}` substring is not present as a literal and the normalization at L57 does not fire. Whether the blacklist regex `rm\s+-rf\s+/` would still match depends on whether the regex engine sees `rm${IFS:- }-rf...` as a contiguous non-whitespace run. It does — `\s+` would not match `${IFS:- }`. This is an open structural question about normalization coverage.

3. **Audit log records raw or trimmed command:** The caller to `validate()` that subsequently builds `AuditEvent::denied(host, command, reason)` — does it pass the pre-trim or post-trim command? The `normalize_for_blacklist_match` output is never logged. Confirm by reading `execute_command.rs` in full.

4. **Lock-poison recovery in validate():** `PoisonError::into_inner` at L161 and L217 uses the pre-panic guard state. If the prior panic happened during a partial write in `reload()`, is the recovered guard in a consistent state? In Rust, `RwLock` poisoning marks the lock as poisoned after a write-lock holder panics; the guard recovered via `into_inner` still holds valid `CompiledPatterns` (the struct was either fully swapped or not, due to Rust's ownership/drop semantics). This appears safe but warrants a code trace of `reload()`'s write guard scope.

5. **`validate_builtin` caller discipline:** No type-level enforcement prevents a handler from passing user-controlled input directly to `validate_builtin` instead of `validate`. The contract is documented in comments (L193–L196) but not mechanically enforced. A review pass on all ~8 call sites listed in the grep output is needed to confirm each one constructs the command exclusively from domain-builder output before calling `validate_builtin`.

6. **Reload count logging discrepancy:** `reload()` logs `config.whitelist.len()` and `config.blacklist.len()` (L119–L120), which are raw counts from the config, not the count of successfully compiled patterns. If invalid patterns were skipped during `compile()`, the log will overstate the active pattern count. An operator monitoring the "Security rules reloaded" log line may believe more patterns are active than actually are.

7. **`validate()` whitelist match on `normalized_for_match` vs `raw`:** The current design explicitly uses `raw` for whitelist matching (L174). A test or documentation asserting whether `ls${IFS}-la` would be denied by whitelist `^ls\b` in strict mode would concretize the asymmetry. This is likely intentional but is not explicitly tested in the normalization test suite.

8. **Server startup wiring of `CommandValidator`:** The production instantiation of `CommandValidator` inside the MCP server is not visible in the four read files. Need to inspect `src/main.rs` or `src/mcp/server.rs` to confirm that `SecurityConfig::default()` is not silently used in production (which would produce Standard mode with empty whitelist, blocking all `validate()` calls).

---

**Key invariants summary:**

- Blacklist always applies; whitelist applies only in Standard/Strict mode; both operate after normalization (blacklist) or on raw input (whitelist).
- `validate_builtin` bypasses the whitelist; the blacklist is the sole runtime gate for builtin paths.
- Normalization is scoped to five substitutions: `\\\n`, `${IFS}`, `$IFS`, `$'\t'`, `$'\n'`, `$' '`. No other shell expansions are handled.
- In a default production deployment (`SecurityMode::Standard`, empty whitelist), all commands to `validate()` will be denied; only `validate_builtin()` paths produce successful commands.
- The `RwLock` architecture allows concurrent reads with atomic swap on reload; lock poison recovery uses stale-but-consistent state.

**Relevant source files:**
- `/home/muchini/mcp-ssh-bridge/src/security/validator.rs` (primary target)
- `/home/muchini/mcp-ssh-bridge/src/security/mod.rs`
- `/home/muchini/mcp-ssh-bridge/src/security/audit.rs`
- `/home/muchini/mcp-ssh-bridge/src/ports/tools.rs`
- `/home/muchini/mcp-ssh-bridge/src/config/types.rs` (default blacklist, `SecurityMode`, `SecurityConfig::default`)
- `/home/muchini/mcp-ssh-bridge/src/domain/use_cases/execute_command.rs` (delegation layer)
- `/home/muchini/mcp-ssh-bridge/src/mcp/standard_tool.rs` (builtin call site)

---


---

## `src/mcp/pending_requests.rs` (Vuln 8 patched surface)

---

### Module-Level Context

`src/mcp/pending_requests.rs` (L1-L179) implements the correlation table that pairs server-initiated JSON-RPC requests (elicitation, sampling, `roots/list`) with their eventual client responses. The pre-audit design held one global instance on `McpServer`; the Vuln 8 fix replaced that with one `Arc<PendingRequests>` allocated per `serve_session` call at `server.rs:L641`, making the map's scope strictly bounded to a single transport session's lifetime.

---

## `ClientResponse` Enum (L16-L25)

### 1. Purpose

`ClientResponse` is the typed union that represents the result of a single server-initiated round-trip. It exists so the `oneshot` channel carries structured data rather than raw JSON, eliminating a `serde` deserialization step at the caller and making the happy-path/error-path explicit at the type level.

### 2. Inputs and Assumptions

1. `Success(Value)` — the `result` field from a JSON-RPC response object; assumed to be well-formed but semantics are caller-defined.
2. `Error.code` (`i32`) — the JSON-RPC error code; assumed to fall within signed 32-bit integer range; no range validation occurs at construction.
3. `Error.message` (`String`) — human-readable error string; assumed to be UTF-8 valid (guaranteed by Rust's `String` type).
4. `Error.data` (`Option<Value>`) — optional structured error context; may be `null`, an object, or any `serde_json::Value` variant; no schema constraint enforced.
5. The enum is only ever constructed inside `route_incoming_message` (`server.rs:L876-L884`), so the source of the discriminant is always a `JsonRpcMessage` that passed JSON parsing.

### 3. Outputs and Effects

- No state mutations; this is a pure data carrier.
- Its `#[derive(Debug)]` allows structured logging at call sites.
- The enum is `Send` because `Value` is `Send`, making it safe to transfer across the oneshot channel from the `serve_session` reader task to any spawned request handler task.

---

## `PendingRequests::new()` / `Default::default()` (L35-L39, L84-L87)

### 1. Purpose

Constructs an empty pending-request correlation table. The `Default` impl delegates entirely to `new()` at L85, establishing a single code path for construction. The `#[must_use]` attribute at L34 ensures callers assign the returned value.

### 2. Inputs and Assumptions

1. No parameters; the constructor is pure.
2. Assumes the allocator can provide memory for a `HashMap` and a `Mutex` wrapper; OOM is not handled beyond Rust's default abort.
3. Assumes the caller will subsequently share this value behind `Arc` before passing it to async tasks (enforced at `server.rs:L641`).
4. Assumes there is no pre-existing state to migrate from; a fresh instance starts empty.
5. The `Default` impl is semantically identical to `new()`: no optional fields, no global side effects.

### 3. Outputs and Effects

- Returns a `PendingRequests` with `pending` field initialised as an empty `HashMap` wrapped in `std::sync::Mutex`.
- No storage writes, no events, no external interactions.
- Postcondition: `self.is_empty()` returns `true`.

### 4. Block-by-Block Analysis

**L36-L39 — HashMap + Mutex construction:**

- **What:** Allocates an empty `HashMap<String, oneshot::Sender<ClientResponse>>` and wraps it in `std::sync::Mutex`.
- **Why here:** The `Mutex` is chosen over `tokio::sync::Mutex` because `create_request` and `resolve` are synchronous critical sections; they hold the lock only to insert/remove a single map entry and immediately release. There is no `await` point inside the lock in either function, making `std::sync::Mutex` correct and marginally more efficient (no async wakeup machinery needed).
- **Assumptions:** No concurrent callers can reach this particular instance before construction completes (guaranteed by Rust's ownership model).
- **First Principles:** A lock exists to serialize access to the map. The map exists because multiple concurrent tokio tasks may call `create_request` and `resolve` on the same `Arc<PendingRequests>` at the same time (one task per dispatched JSON-RPC request). The key design decision is: synchronous Mutex is safe here exactly because neither `create_request` nor `resolve` call `await` while holding the lock.

---

## `PendingRequests::create_request()` (L46-L54)

### 1. Purpose

Atomically allocates a correlation entry: generates a cryptographically opaque request ID, constructs a `oneshot` channel, stores the sender in the map, and returns the ID plus receiver to the caller. The caller uses the ID to label the outbound request and the receiver to await the eventual response.

### 2. Inputs and Assumptions

1. `&self` — shared reference; concurrent callers are serialised inside by the `Mutex`.
2. Assumes `uuid::Uuid::new_v4()` is backed by a CSPRNG on the target platform; this is the `uuid` crate's guarantee when compiled with the `v4` feature.
3. Assumes the `Mutex` has not been poisoned; if it has, `expect` panics the calling thread/task. This is an explicit design decision documented by the comment at L50 ("pending lock poisoned").
4. Assumes the caller will eventually either `await` the returned `rx`, drop it (timeout case), or let it be garbage-collected at session tear-down — all three paths are safe.
5. Assumes the session's reader loop will deliver matching responses via `resolve()` using the same ID; the caller does not validate this assumption itself.
6. Assumes no two invocations will produce the same UUID (UUID v4 collision probability is negligible: ~2^{-122}).

### 3. Outputs and Effects

- **Return:** `(String, oneshot::Receiver<ClientResponse>)` — the ID (format `"srv-{32 hex chars}"`) and the waiting end of the channel.
- **State write:** Inserts `id -> tx` into `self.pending` inside the Mutex critical section (L51).
- **Channel allocation:** Creates a tokio `oneshot` channel; the sender half stays in the map, receiver goes to caller.
- **Postcondition:** `self.len()` increases by exactly 1.
- **Side effect if duplicate key:** Not possible by construction given UUID v4 — but if it were, `HashMap::insert` would silently replace the previous sender, dropping it and causing the first waiter to observe a permanently closed receiver. No defence against this edge case is coded (not needed in practice).

### 4. Block-by-Block Analysis

**L47 — UUID generation:**

- **What:** Calls `uuid::Uuid::new_v4().simple()` to produce a 32-character lowercase hex string, prefixed with `"srv-"`.
- **Why here:** Must precede channel and map operations so the ID is available before the sender is stored.
- **Assumptions:** `new_v4()` is thread-safe and non-blocking; no external I/O.
- **Depends on:** `uuid` crate feature `v4` being compiled in.
- **5 Whys — Why UUID v4 and not a sequential counter?**
  1. Why avoid a counter? A counter would be guessable.
  2. Why does guessability matter? A client could construct `"srv-1"` and call `resolve("srv-1", ...)` to hijack another session's pending slot.
  3. Why was this the root of Vuln 8? Because the legacy code used predictable IDs on a shared map — any session could resolve any other session's entry.
  4. Why does per-session scoping not fully eliminate the need for opaque IDs? Because within a session, multiple concurrent requests are in-flight; if IDs were predictable, a malicious client could resolve an earlier request it did not own.
  5. Why `simple()` format? Produces a compact 32-character hex string with no hyphens, reducing wire overhead and simplifying string equality checks.

**L48 — oneshot channel creation:**

- **What:** `oneshot::channel()` allocates a paired `(Sender, Receiver)`.
- **Why here:** Must be created with the ID so both can be stored/returned as a unit.
- **Assumptions:** `tokio::sync::oneshot` channels are `Send`; the receiver can be moved into a spawned task.
- **5 Hows — How does the oneshot ensure the response is delivered exactly once?**
  1. The sender is consumed by `tx.send(response)` at `resolve()` L63.
  2. After `send()`, the sender is dropped; any subsequent `send()` on the same sender is a compile-time error.
  3. The receiver returns `Err` if the sender was dropped without sending (captured at `client_requester.rs:L95` as `ChannelClosed`).
  4. `tokio::time::timeout` wraps the `rx.await` at `client_requester.rs:L92-L95`, so a stale receiver does not leak memory indefinitely.
  5. If the receiver is dropped first (L165-L170 test), `tx.send()` returns `Err(ClientResponse)` which is explicitly discarded at L63 with `let _ = ...`.

**L50-L51 — Mutex lock and insert:**

- **What:** Acquires the synchronous `Mutex`, inserts the `(id, tx)` pair, then immediately releases the lock on scope exit.
- **Why here:** The Mutex critical section is as narrow as possible — just the `insert` call.
- **Assumptions:** No `await` inside the lock; holding a `std::sync::Mutex` across an `await` point would be a compilation error (`MutexGuard: !Send`) but would require `tokio::sync::Mutex` to compile at all. The design avoids this entirely.
- **Depends on:** `id` being computed before locking.

**L53 — Return:**

- **What:** Returns `(id, rx)` — the ID is cloned because it was moved into the map at L51.
- **Why here:** The clone occurs after the lock is released, avoiding holding the lock during the allocation.

### 5. Cross-Function Dependencies

- **Callee:** `uuid::Uuid::new_v4()` — external, non-blocking CSPRNG call. Adversarial consideration: if the platform's entropy source is exhausted or weak, ID uniqueness degrades; this is a platform concern, not an application concern.
- **Callee:** `tokio::sync::oneshot::channel()` — internal tokio primitive; allocation failure would panic, consistent with Rust's OOM handling.
- **Caller:** `ClientRequester::send_request()` at `client_requester.rs:L83` — the only production call site. It calls `create_request`, sends the request, then awaits `rx`.
- **Shared state:** `self.pending` (`Mutex<HashMap>`) — shared with `resolve()`, `len()`, `is_empty()`.
- **Invariant coupling:** The returned `id` string must exactly match the `id` field serialised into the outbound `JsonRpcOutboundRequest` at `client_requester.rs:L85`; any mismatch means `resolve()` will never find the entry.

---

## `PendingRequests::resolve()` (L59-L68)

### 1. Purpose

Delivers a `ClientResponse` to the task awaiting a specific server-initiated request, identified by `id`. This is the only write path that removes entries from the map, making it the sole eviction mechanism. It is called by the session's reader loop (`server.rs:L885`) when an incoming message carries no `method` field — the JSON-RPC signal that it is a response to a server-initiated request.

### 2. Inputs and Assumptions

1. `&self` — shared reference, concurrent access serialised by Mutex.
2. `id: &str` — the request ID string; assumed to be the exact string returned by `create_request()`; case-sensitive; no normalisation is performed.
3. `response: ClientResponse` — the parsed response from the client; moved into the oneshot channel.
4. Assumes the Mutex has not been poisoned; `expect` at L60 panics if it has.
5. Assumes the caller (reader loop) has correctly identified an incoming message as a response (no `method` field) before calling `resolve`; no second check is performed here.
6. Assumes `id` came from the client's response JSON, normalised at `server.rs:L872-L875`; string vs integer IDs are pre-converted to `String` before reaching `resolve`.
7. Assumes that a `false` return value is benign — the caller at `server.rs:L885-L887` logs at `debug` level and continues.

### 3. Outputs and Effects

- **Return:** `bool` — `true` if an entry was found and removed; `false` if the ID was unknown.
- **State write:** Removes `id` from `self.pending` via `HashMap::remove()` (L61). The map shrinks by one entry on success.
- **Channel write:** Calls `tx.send(response)` on the stored sender; `let _ =` discards the `Err` case (dropped receiver).
- **Postcondition:** After returning `true`, no entry with `id` remains in the map; repeated calls with the same `id` return `false`. This makes `resolve` idempotent on the second call.
- **No event emission:** The resolved value travels through the oneshot channel to the awaiting task, not through any notification channel.

### 4. Block-by-Block Analysis

**L60-L61 — Lock acquisition and remove:**

- **What:** Acquires `Mutex`, atomically removes the entry, holds both lock and `Option<Sender>` simultaneously, then releases the lock on scope exit.
- **Why here:** The `remove` must be atomic with the "found?" decision to prevent double-resolution in a concurrent scenario where two client messages arrive with the same ID milliseconds apart.
- **Assumptions:** `HashMap::remove` returns the stored sender in `O(1)` average; no reallocation.
- **Depends on:** The ID having been inserted by `create_request` using the identical string key.
- **First Principles:** Why remove on resolve rather than leave the entry? Leaving it would allow a second call with the same ID to re-trigger the now-dropped sender. By removing atomically, the map guarantees at-most-once delivery: the first `resolve` wins, subsequent calls return `false`.

**L62-L64 — Send to oneshot:**

- **What:** Calls `tx.send(response)`, discards the `Err` with `let _`.
- **Why here:** Executed after the lock is released (the lock guard `pending` drops when its scope exits at `}` on L67, but the actual guard is `pending` which was bound by `let mut pending = ... .lock()...` — the guard lives until the end of the outer function scope at L68, so the send happens while the guard is technically alive). Unclear: need to verify that the Mutex guard does not hold across `tx.send()`. Inspecting L60-L67 more carefully: `pending` (the guard) is declared on L60 and in scope through L67; `tx.send` is on L63. This means the Mutex is held during `tx.send`. Because `tx.send` on a `tokio::sync::oneshot::Sender` is a synchronous, non-blocking call (it simply moves the value into the channel slot), holding `std::sync::Mutex` across it is safe — no deadlock risk from re-entrant locking since `tx.send` does not call back into `PendingRequests`.
- **Assumptions:** `oneshot::Sender::send` never blocks.
- **5 Whys — Why discard the Err from tx.send?**
  1. Why might `send` fail? The receiver was dropped before `resolve` was called.
  2. Why would a receiver be dropped early? The awaiting task timed out (via `tokio::time::timeout`) and moved on.
  3. Why is this acceptable? The server already removed the entry from the map, so no future resolution attempt will occur; the operation is complete from the server's perspective.
  4. Why not log a warning? Dropped receivers are a normal timeout path — logging at warn would create noise for any timed-out elicitation. The test at L162-L169 documents this as expected.
  5. Why not restore the entry on failure? The receiver is dropped; restoring the sender would be pointless — it can never be read.

### 5. Cross-Function Dependencies

- **Callee:** `HashMap::remove` — std; no external dependency.
- **Callee:** `oneshot::Sender::send` — tokio; synchronous, non-blocking.
- **Callers:**
  - `server.rs:L885` — `route_incoming_message`, the only production call site; called from the session reader loop when a client response arrives.
  - Called with IDs normalised from `Value::String(s)` or `other.to_string()` (L872-L875).
- **Shared state:** `self.pending` — same map as `create_request`; concurrent access serialised.
- **Invariant coupling:** `resolve` is the only eviction path. If a response never arrives (client disconnect, network loss), the entry stays in the map indefinitely until the session ends and `session_pending` is dropped with all remaining senders.

---

## `PendingRequests::len()` and `is_empty()` (L72-L80)

### 1. Purpose

Diagnostic accessors that report the current depth of the pending map. `is_empty()` delegates to `len()` rather than `HashMap::is_empty()` directly, accepting one redundant lock acquisition; the trade-off is simplicity over micro-optimisation.

### 2. Inputs and Assumptions

1. `&self` — shared reference.
2. Assumes the Mutex is not poisoned; `expect` panics if it is.
3. The count returned is a snapshot — it may be stale by the time the caller acts on it; no external caller should make scheduling decisions based on this value.
4. Both are annotated `#[must_use]`, preventing accidental discard.
5. These are used only in tests (L117, L121, L175-L177) and for diagnostics; no production control flow depends on them.

### 3. Outputs and Effects

- `len()` returns `usize`; `is_empty()` returns `bool`.
- No state mutations, no events, no external interactions.
- `is_empty()` acquires the lock twice in total (once via `len()`); not a correctness issue, only a micro-efficiency note.

---

## `Default` Impl (L83-L87)

### 1. Purpose

Satisfies the `Default` trait so `PendingRequests` can be constructed via `PendingRequests::default()` or used in struct fields with `#[derive(Default)]`. Delegates to `new()` to ensure a single canonical construction path.

### 2. Inputs and Assumptions

1. No parameters.
2. Assumes `new()` is pure and has no preconditions.
3. Assumes no global state is consulted during construction.
4. Assumes callers invoking `default()` have the same intent as callers invoking `new()`.
5. Because no test directly calls `default()`, the equivalence is enforced only by code inspection.

### 3. Outputs and Effects

- Returns a fresh empty `PendingRequests`.
- No state mutations beyond heap allocation.
- Postcondition: identical to `new()`.

---

## The Vuln 8 Invariant: Per-Session Isolation

The central structural invariant established by the Vuln 8 fix is:

**Each transport session owns exactly one `Arc<PendingRequests>` instance, allocated at session entry and never shared with any other session.**

This is enforced at three concrete code sites:

1. **`server.rs:L641`** — `let session_pending = Arc::new(PendingRequests::new());` — a fresh instance is created inside `serve_session`, local to that invocation's stack frame.

2. **`server.rs:L733-L742`** — Every spawned request-handler task receives `Arc::clone(&session_pending)` for this session only. No other session's `session_pending` is cloned here.

3. **`server.rs:L885`** — `session_pending.resolve(&id_str, response)` — client responses are resolved against the session-local map only. The reader loop for session A cannot reach session B's map.

The comment at `pending_requests.rs:L44-L45` names both mechanisms that together prevent cross-session resolution:
- Per-session allocation (structural isolation).
- UUID v4 IDs (opaque identifiers even within a session).

When `serve_session` exits (after `reader.recv()` returns `None` at `server.rs:L678` and the cleanup at `server.rs:L819-L835` completes), `session_pending` is dropped along with all remaining `Arc<PendingRequests>` clones held by in-flight spawned tasks. Dropping the `Arc<PendingRequests>` when its reference count reaches zero drops the `HashMap`, which drops all remaining `oneshot::Sender` values, signalling `ChannelClosed` to any tasks still waiting on their receivers. This is the implicit eviction path for requests that never received a response (client disconnect mid-elicitation).

---

## Concurrency Model

### Sync Primitive Choice

`std::sync::Mutex` (L29) is used instead of `tokio::sync::Mutex`. This is structurally correct because:

- `create_request` acquires the lock, inserts one entry, releases the lock — no `await` inside the critical section.
- `resolve` acquires the lock, removes one entry, calls `tx.send()` (synchronous), releases the lock — no `await` inside.
- `len`/`is_empty` acquire and release with no `await`.

Holding a `std::sync::Mutex` guard across an `await` point would make the guard `!Send`, causing a compile error in async task contexts. The current code avoids this entirely.

### Cancellation Safety

`create_request` itself has no `await` points and is cancellation-safe. `resolve` is also cancellation-safe. The async concern lives one layer up in `ClientRequester::send_request` (`client_requester.rs:L78-L103`):

- `send_request` calls `self.pending.create_request()` at L83 (sync, safe).
- Then awaits `self.tx.send(...)` at L87-L90 (mpsc send; cancellation here leaves the ID in the map with no one to resolve it — a transient leak until session end).
- Then awaits `tokio::time::timeout(self.timeout, rx)` at L92-L95 (cancellation here leaves the ID in the map; the timeout will still fire when the task is dropped, but the oneshot receiver drops too, so the entry becomes a dead sender that `resolve` will eventually attempt and discard via `let _ = tx.send(...)`).

The practical effect: if `send_request` is cancelled between L83 and L92, the map entry is never resolved by the client response but is silently cleaned up at session drop. No cross-session state is affected.

### Concurrency Scenario: Multiple Concurrent Elicitations

Within a single session, multiple in-flight requests are possible (e.g. a batch request spawning parallel handlers). Each spawned task calls `create_request` independently, receiving distinct UUID-based IDs. The Mutex serialises the inserts. The reader loop resolves each response by ID, with the Mutex serialising removes. No ordering guarantees are needed because oneshot channels are independent per-request.

---

## Cross-Module Data Flow

```
serve_session (server.rs:L635)
  |
  +--> Arc::new(PendingRequests::new())          [session_pending born, L641]
  |
  +--> reader loop (L678)
  |      |
  |      +--> route_incoming_message(..., &session_pending, ...)  [L695]
  |             |
  |             +--> [no method] session_pending.resolve(id, response)  [L885]
  |             |       ^--- only this session's map is touched
  |             |
  |             +--> [request] tokio::spawn(handle_request_with_cancel(
  |                             ..., Some(Arc::clone(&session_pending)), ...))  [L733-L743]
  |                             |
  |                             +--> create_tool_context(..., session_pending)  [server.rs:L395-L428]
  |                             |       ctx.pending_requests = session_pending  [L428]
  |                             |
  |                             +--> check_destructive_elicitation(
  |                             |       ..., session_pending.as_ref(), ...)  [L345-L350]
  |                             |       ClientRequester::new(tx, pending, 120s)
  |                             |           send_request()
  |                             |               create_request()  [pending_requests.rs:L46]
  |                             |               tx.send(outbound_request)
  |                             |               rx.await (with timeout)
  |
  +--> session ends, session_pending Arc<> ref count drops to 0
         HashMap dropped, all remaining senders drop, dead receivers close
```

---

## Test Coverage Assessment

The inline test suite (`pending_requests.rs:L90-L179`) covers:

| Scenario | Test |
|---|---|
| ID uniqueness across consecutive calls | `test_create_request_unique_ids` (L94-L102) |
| Legacy predictable IDs do not resolve | `test_resolve_predictable_legacy_id_does_not_succeed` (L105-L111) |
| Successful round-trip | `test_resolve_success` (L113-L128) |
| Error round-trip | `test_resolve_error` (L131-L153) |
| Unknown ID returns false | `test_resolve_unknown_id` (L155-L160) |
| Dropped receiver does not panic | `test_resolve_dropped_receiver` (L163-L169) |
| `is_empty` reflects state | `test_is_empty` (L172-L178) |

The test at L105-L111 directly validates the Vuln 8 property from the ID-format side: `"srv-1"` and `"srv-2"` (the legacy sequential patterns) cannot resolve any entry.

Cross-session isolation is validated at `server.rs:L2511-L2514` and L2547-L2552` in tests that construct two independent `PendingRequests` instances and verify `route_incoming_message` routes responses only to the supplied instance.

---

## Structural Invariants Summary

1. **Per-session allocation invariant (Vuln 8):** One `Arc<PendingRequests>` per `serve_session` invocation, never shared across sessions (`server.rs:L641`).

2. **Opaque ID invariant:** All IDs are `"srv-{uuid_v4_simple}"` — unguessable, probabilistically unique, non-sequential. Enforced at `pending_requests.rs:L47`.

3. **At-most-once resolution invariant:** `HashMap::remove` at L61 ensures that once an ID is resolved, it cannot be resolved again; subsequent `resolve` calls with the same ID return `false`.

4. **Mutex holds no `await` invariant:** Neither `create_request` nor `resolve` crosses an `await` point while holding the `std::sync::Mutex` guard, making both functions safe to call from any async context without risk of deadlock or `Send` bound violations.

5. **Implicit eviction invariant:** Entries not explicitly resolved are cleaned up implicitly when the `Arc<PendingRequests>` is dropped at session end, which drops all remaining senders, propagating closure to waiting receivers.

6. **Single eviction path invariant:** `resolve()` is the only function that removes entries from the map. There is no background sweeper, no TTL mechanism, and no `clear()` method. The map can grow unbounded within a session if responses never arrive; session drop is the only guaranteed cleanup.

---

## Open Questions

1. **Mutex guard across `tx.send()`:** At `resolve()` L60-L67, the `Mutex` guard `pending` remains in scope through L63 when `tx.send(response)` is called. `oneshot::Sender::send` is documented as non-blocking, but this warrants verification against the tokio internals: if `tx.send` on a closed receiver involves any parking/wake logic under the hood, holding a `std::sync::Mutex` across it could block tokio worker threads. Unclear; need to inspect tokio's `oneshot` implementation to confirm the non-blocking guarantee.

2. **Unbounded map growth within a session:** If a session sends many server-initiated requests and the client never responds (e.g. a misbehaving client that reads requests but ignores them), entries accumulate indefinitely until session end. There is no per-entry TTL and no maximum pending-count guard. The `ClientRequester` timeout (10s for `roots/list` at `server.rs:L935`, 120s for elicitation at `server.rs:L371`) drops the receiver on timeout, but the sender stays in the map until `resolve()` is eventually called or the session drops. Unclear how large the map can grow under adversarial client behavior within a single long-lived session.

3. **Batch request path and session_pending:** Batch requests (L755-L819 in `server.rs`) spawn parallel handlers. In the batch path, `session_pending` is not passed to `handle_request_with_cancel` (the batch sub-handlers at L787-L806 do not carry `session_pending`). This means tools requiring elicitation within a batch request would fail the `None` check at `server.rs:L350`. Need to verify whether this is intentional (batched destructive tools are simply blocked) or an omission.

4. **`allocate_session_pending_for_test()` visibility:** The method at `server.rs:L217-L219` is `pub` (not `pub(crate)`) to allow integration tests in a separate crate, gated by `#[doc(hidden)]`. It constructs a fresh `PendingRequests::new()` and does not interact with any shared server state. The method's presence on `McpServer`'s public surface, while semantically harmless, means downstream users of the crate (if ever published) would see a method labelled for test use only. Unclear whether a `#[cfg(test)]` re-export from an integration test helper module would be a cleaner boundary.

5. **No `Drop` impl on `PendingRequests`:** Entry eviction at session end relies entirely on Rust's drop order. If a future refactor stores `session_pending` in a struct field rather than a local variable (e.g. for HTTP session state), the drop-on-session-exit guarantee would no longer hold automatically. The current design is safe, but the invariant is implicit and could be strengthened by an explicit `Drop` that logs or asserts a clean (empty) map state.

---

## src/mcp/session_capabilities.rs (Vuln 9 patched surface)

Relevant files:

- `/home/muchini/mcp-ssh-bridge/src/mcp/session_capabilities.rs` — primary target (46 lines)
- `/home/muchini/mcp-ssh-bridge/src/mcp/server.rs` — allocation site L646, write site L1134-1153, read sites L329, L433-436, L928
- `/home/muchini/mcp-ssh-bridge/src/mcp/transport/session_store.rs` — `SessionData` shape; does not store `SessionCapabilities` (capabilities live on the stack frame of `serve_session`, not in the session store)

---

### Module Overview

The module at L1-6 opens with an explicit tombstone: it replaces server-wide `AtomicBool` fields that leaked capability advertisements across clients sharing the same daemon process. The tombstone is part of the Vuln 9 fix audit trail; the comment at L2-5 is the normative statement of the invariant the module enforces.

The module exports exactly one type: `SessionCapabilities` (L12-16). It has no `Drop` impl. Lifecycle is entirely governed by `Arc` reference counting inside `serve_session`.

---

## Function: `SessionCapabilities::new` (L20-22)

### 1. Purpose

`new` is a named constructor that delegates to `Default::default`. It exists so call sites can use the name `SessionCapabilities::new()` rather than the derived `Default` path, maintaining consistency with the project's Rust conventions (named constructors preferred). Its sole effect is to zero-initialize all three `AtomicBool` flags.

### 2. Inputs and Assumptions

| # | Input / Assumption | Detail |
|---|---|---|
| A1 | No parameters | Pure constructor, no caller-supplied state. |
| A2 | `Self::default()` is infallible | `AtomicBool::default()` returns `false`; this can never panic or fail. |
| A3 | Caller will wrap in `Arc` | The allocation pattern at server.rs L646 is `Arc::new(SessionCapabilities::new())`. Nothing enforces this at the type level; it is a convention. |
| A4 | Construction happens before any `initialize` message is processed | The `serve_session` call at server.rs L646 constructs the capabilities object before the reader loop begins at L678, so no race on first write is possible. |
| A5 | `false` is the safe default for all three flags | A session that has not sent `initialize` is treated as advertising no extended capabilities. This is the fail-closed stance. |

### 3. Outputs and Effects

- **Returns** a `SessionCapabilities` with all three flags set to `false`.
- **No state writes** to any shared structure; the value is unboxed and caller-owned until wrapped.
- **No events emitted.**

### 4. Block-by-Block Analysis

**L21: `Self::default()`**

- *What*: Delegates to the `#[derive(Default)]` impl, which calls `AtomicBool::default()` for each field.
- *Why here*: Centralizing construction in `new` lets future maintainers add initialization logic without changing all call sites.
- *Assumptions*: `AtomicBool::default()` == `AtomicBool::new(false)` — this is guaranteed by the standard library.
- *Depends on*: `#[derive(Default)]` at L10.
- *First Principles*: An uninitialized capabilities object must be capability-absent, not capability-present. Setting flags to `false` by default is the only safe choice: a bug that forgets to clear a flag is far less dangerous than one that forgets to set it. Zeroing by default enforces the closed-world assumption.

### 5. Cross-Function Dependencies

- Called at server.rs L646 (`serve_session`), L234 (`allocate_session_capabilities_for_test`), and test sites L2512, L2534.
- Invariant coupling with `handle_initialize` (server.rs L1083): `new()` must return `false` for all flags so that `handle_initialize` is the only authorized writer.
- The `Default` derive at L10 is the structural dependency; removing it would break `new`.

---

## Impl: `Default` (derived, L10)

### 1. Purpose

Derived by `#[derive(Default)]` at L10. Provides `SessionCapabilities::default()` which zero-initializes all three `AtomicBool` fields. `new()` is a thin wrapper over this impl.

### 2. Inputs and Assumptions

| # | Assumption |
|---|---|
| A1 | `AtomicBool` implements `Default` as `AtomicBool::new(false)`. |
| A2 | Derived `Default` implementations never panic. |
| A3 | The derive is applied at the struct level, not overridden. |
| A4 | No field-level `#[serde(default)]` or custom attribute interferes with the derive. |
| A5 | The struct has no `PhantomData` or lifetime parameters that would complicate derivation. |

### 3. Outputs and Effects

- Returns `SessionCapabilities` with `supports_elicitation = false`, `supports_sampling = false`, `supports_roots = false`.
- No side effects, no state writes.

---

## Function: `set_supports_elicitation` (L24-26), `set_supports_sampling` (L27-29), `set_supports_roots` (L30-32)

These three setters are structurally identical; they are analyzed together.

### 1. Purpose

Each setter stores a boolean value into its corresponding `AtomicBool` field using `Ordering::Relaxed`. They are called exclusively from `handle_initialize` (server.rs L1135-1152) on the session-local capabilities object, translating the parsed `InitializeParams.capabilities` sub-fields into per-session flags.

### 2. Inputs and Assumptions

| # | Input / Assumption | Detail |
|---|---|---|
| A1 | `&self` — shared reference | `AtomicBool::store` takes `&self`, so no `&mut self` is needed. Interior mutability is provided by the atomic. |
| A2 | `v: bool` — caller-supplied, trusted domain value | The value comes from `init_params.capabilities.roots.is_some()` etc. at server.rs L1134, L1141, L1148 — derived from client-supplied JSON but already type-erased to `bool`. |
| A3 | `Ordering::Relaxed` is correct for this write | Justified below under First Principles. |
| A4 | Setters are called at most once per session lifetime | The MCP spec specifies `initialize` is sent exactly once per connection. Nothing in the code enforces this; a misbehaving client could send `initialize` multiple times, causing repeated stores (idempotent for `true`, but a later `false` could clear a previously set flag — unclear if this is guarded; inspect server.rs L1083 `initialized` flag gate). |
| A5 | The `Arc` wrapping this value is not cloned into concurrent tasks before this write | At server.rs L646, the `Arc` is created; it is not cloned until L734 (`session_caps_for_task`), which happens only after `route_incoming_message` (L695) has already dispatched the `initialize` request. The `initialize` handler is synchronous with respect to the reader loop. |
| A6 | No other function writes to these fields | Confirmed: the only writes in the codebase are the three setter calls at server.rs L1136, L1143, L1150. |

### 3. Outputs and Effects

- Stores a `bool` into the corresponding `AtomicBool` field.
- No return value (`()`).
- No events emitted.
- **Effect on downstream behavior**: subsequent calls to `supports_elicitation()` / `supports_sampling()` / `supports_roots()` from tool dispatch or `check_destructive_elicitation` will observe the stored value.

### 4. Block-by-Block Analysis

**`self.supports_elicitation.store(v, Ordering::Relaxed)` (L25)**

- *What*: Atomic store of `v` into `supports_elicitation`.
- *Why here*: Interior mutability via `AtomicBool` allows mutation through a shared reference, which is required because `McpServer` shares `Arc<SessionCapabilities>` across multiple tasks.
- *Assumptions*: The flag is written by the reader-loop task (which runs `handle_initialize`) and subsequently read by spawned request-handler tasks. The write at L1136 happens before the corresponding `tokio::spawn` at server.rs L735 that clones the `Arc`. In Tokio's execution model, `tokio::spawn` establishes a happens-before relationship for already-published atomic values.
- *Depends on*: The `AtomicBool` field declared at L13.
- *First Principles (Ordering::Relaxed)*: `Relaxed` provides atomicity (no torn reads/writes) but no ordering guarantees relative to other memory operations. For this use case, this is sufficient because: (1) the write at L1136 happens in the reader-loop task before the `Arc::clone` at L734 and the `tokio::spawn` at L735; (2) `tokio::spawn` itself is a synchronization point that ensures the spawned task observes all stores performed before the spawn; (3) the flag is written once and subsequently only read — there is no compare-and-swap or dependent update that would require `AcqRel`. *5 Whys*: Why `Relaxed`? Because the ordering is established by `spawn`. Why use `spawn` for ordering? Because Tokio's executor guarantees publish-before-start semantics. Why not `SeqCst`? It would add unnecessary overhead (a full memory barrier) without correctness benefit in this single-writer pattern.
- *5 Hows*: How does the spawned task see the flag? The `Arc<SessionCapabilities>` is cloned after the store; the clone's reference count increment is a `Release`/`Acquire` pair in `Arc`, ensuring the stored value is visible. How does this prevent cross-session leakage? Each `serve_session` invocation creates a new `SessionCapabilities` via `Arc::new(SessionCapabilities::new())` (L646); the `Arc` is never stored in `McpServer` fields, so no alias exists across sessions.

### 5. Cross-Function Dependencies

- Written by: `handle_initialize` (server.rs L1083), called from `handle_request_with_cancel` L1024.
- Read by: `supports_elicitation()`, `supports_sampling()`, `supports_roots()` — see getter analysis below.
- Shared state: the `Arc<SessionCapabilities>` is cloned at server.rs L734 into the spawned request task, and at L743 passed into `handle_request_with_cancel`. All clones point to the same heap-allocated `SessionCapabilities`.

---

## Function: `supports_elicitation` (L35-37), `supports_sampling` (L39-41), `supports_roots` (L43-45)

These three getters are analyzed together.

### 1. Purpose

Each getter loads the corresponding `AtomicBool` with `Ordering::Relaxed` and returns it as a plain `bool`. They are the read-side of the per-session capability gate. The `#[must_use]` attribute (L34, L38, L42) ensures callers cannot silently discard the return value — relevant for gating code that conditionally initiates elicitation or roots fetching.

### 2. Inputs and Assumptions

| # | Input / Assumption | Detail |
|---|---|---|
| A1 | `&self` — shared reference, no exclusive access needed. | `AtomicBool::load` takes `&self`. |
| A2 | `Ordering::Relaxed` is correct for reads. | See First Principles below. |
| A3 | The value was written before the current task received the `Arc`. | The single-writer / post-spawn-read pattern holds. |
| A4 | `#[must_use]` prevents accidental discard. | Compiler enforces this; a bare call without binding produces a warning promoted to error by `-D warnings`. |
| A5 | Callers treat `false` as a capability-absent gate. | Confirmed at server.rs L329-330, L928, L433-436. |

### 3. Outputs and Effects

- Returns the current value of the corresponding `AtomicBool`.
- No state mutations.
- No events emitted.
- **Postcondition**: return value is `false` until a `set_*` call has committed; `true` only after a successful `initialize` parse confirmed the client advertised the capability.

### 4. Block-by-Block Analysis

**`self.supports_elicitation.load(Ordering::Relaxed)` (L36)**

- *What*: Atomic load returning the current `bool`.
- *Why here*: `Relaxed` load of a value that was written before the owning task's `Arc` was cloned — the `Arc` clone itself establishes visibility.
- *Assumptions*: No second writer exists (only `set_*` functions write, and they are called only from `handle_initialize`).
- *Depends on*: Prior execution of `handle_initialize` having called `set_supports_elicitation`.
- *First Principles*: An atomic load of a value written before an `Arc` clone is observable because `Arc::clone` uses `AcqRel` on the reference counter, which acts as a release/acquire pair for all previously stored values in the allocation. Thus `Relaxed` on load is safe — the synchronization comes from the `Arc` reference count, not from the load ordering itself.
- *5 Hows*: How is freshness of the read guaranteed? The single-writer `handle_initialize` runs in the reader-loop task before any request-handler task is spawned. How could this be violated? Only if a concurrent `initialize` request were processed — prevented by the `initialized` `AtomicBool` at server.rs L62 (set at L1163 after processing). How does `check_destructive_elicitation` use this? It calls `session_caps.is_some_and(|c| c.supports_elicitation())` at server.rs L329 — the `Option` wrapper correctly handles the no-session code path.

### 5. Cross-Function Dependencies

- Called by `check_destructive_elicitation` (server.rs L329) — gates destructive-tool elicitation.
- Called by `create_tool_context` (server.rs L433, L436) — snapshots flags into `ToolContext.client_supports_elicitation` and `ToolContext.client_supports_sampling`.
- Called by `fetch_roots` (server.rs L928) — gates `roots/list` server-initiated request.
- Cross-function invariant: every call to these getters consults the session-local `Arc<SessionCapabilities>`, never a server-level field. The server struct (`McpServer`) has no `supports_*` fields in its definition (server.rs L46-92); this is the structural enforcement of the Vuln 9 fix.

---

## Storage Shape: Per-Session vs. Server-Singleton

**Server-singleton fields** (server.rs L46-92): `config`, `validator`, `sanitizer`, `audit_logger`, `registry`, `notification_tx`, `roots`, `mcp_logger`, `initialized`, `client_info`, `runtime_max_output_chars`, `active_requests`. All shared across sessions.

**Per-session, stack-allocated** (server.rs L646-647, inside `serve_session`):
```rust
let session_pending = Arc::new(PendingRequests::new());   // L641
let session_caps   = Arc::new(SessionCapabilities::new()); // L646
```
These two values are created fresh on each call to `serve_session`. They are not stored in any field of `McpServer`. They exist only in the stack frame of `serve_session` and in the `Arc` clones passed into spawned tasks. When the last clone drops (when the reader loop exits and all in-flight tasks complete), the heap allocation is freed.

**`SessionStore` / `InMemorySessionStore`** (session_store.rs L29-35): `SessionData` holds only `notification_tx` and `created_at`. It does not hold `SessionCapabilities`. The session store is the HTTP-transport-specific backing store for SSE channel routing; it is architecturally separate from the capability tracking mechanism.

**Key uniqueness guarantee**: `serve_session` is called once per transport-level session. The session identity is implicit (the stack frame and its derived `Arc` clones). There is no explicit session ID keying `SessionCapabilities`; isolation is enforced by the stack frame's lexical scope, not by a hashmap lookup.

---

## Lifecycle

| Phase | Location | Trigger |
|---|---|---|
| **Allocate** | server.rs L646 | `serve_session` entry — before reader loop |
| **Initialize (write flags)** | server.rs L1134-1153 in `handle_initialize` | Client sends `initialize` JSON-RPC request |
| **Read (dispatch)** | server.rs L329, L433-436, L928 | Any subsequent `tools/call`, `notifications/initialized`, or `notifications/roots/list_changed` |
| **Evict (drop)** | Implicit | `serve_session` exits (reader EOF); last `Arc` clone in spawned tasks drops on task completion |

There is no explicit "clear" or "reset" call. The capability object is write-once for all practical purposes (the MCP spec forbids re-initialization), though the code does not structurally enforce single-write (see open question OQ-1 below).

---

## Concurrency Analysis

### Which lock guards what?

`SessionCapabilities` uses `AtomicBool` — no `Mutex` or `RwLock`. Lock-freedom is achieved by the atomic primitive.

### Race analysis: can two sessions race on the same object?

No. Each `serve_session` invocation creates a distinct `Arc<SessionCapabilities>`. The `Arc` is never inserted into a server-level collection. Session A's `session_caps` and Session B's `session_caps` are unrelated heap allocations.

### Race analysis: within a single session

The only writer is the reader-loop task running `handle_initialize`. Request-handler tasks are spawned after `route_incoming_message` returns (L695), which is after `handle_initialize` completes (L738-744). The pattern is effectively single-writer / multiple-reader, where the write precedes all reads by construction of the `tokio::spawn` boundary.

`Ordering::Relaxed` on both load (L36, L40, L44) and store (L25, L28, L31) is correct under this pattern. The `Arc::clone` at L734 synchronizes visibility.

### Concurrent MCP clients: risk considerations

1. **Global `notification_tx` slot (server.rs L68, L653, L827-830)**: The server stores one `Arc<RwLock<Option<mpsc::Sender<WriterMessage>>>>`. With multiple concurrent sessions, each `serve_session` overwrites this slot at L653. The cleanup at L827-830 guards against stale clearing with a `same_channel` check, but in a high-connection scenario the slot's value is non-deterministic — it holds whichever session connected last. This is a pre-existing design limitation documented in the code comment at L648-652 and is distinct from the Vuln 9 surface.

2. **`roots` field (server.rs L79, L942)**: `roots` is a server-level `Arc<RwLock<Vec<RootEntry>>>`. When client A sends `notifications/roots/list_changed`, `fetch_roots` overwrites the roots vector with A's roots. This is shared state that client B's tool handlers can observe via `ctx.roots`. This is pre-existing behavior, unrelated to Vuln 9.

3. **`client_info` (server.rs L64, L1155)**: Written per `initialize`, shared server-level — same cross-session overlap concern as `roots`.

---

## Vuln 9 Fix: Invariant Established

The invariant established by the Vuln 9 fix is:

**No `SessionCapabilities` flag from one client's `initialize` handshake is ever observable by a different client's request handlers.**

The lines that enforce this invariant are:

- **server.rs L646**: `let session_caps = Arc::new(SessionCapabilities::new());` — fresh allocation per `serve_session` invocation; no lookup into a shared map.
- **server.rs L734**: `let session_caps_for_task = Arc::clone(&session_caps);` — only the local `session_caps` is cloned, never a server field.
- **server.rs L1128-1153**: Writes go to `session_caps` (the local variable), not to any `McpServer` field.
- **server.rs L46-92** (struct definition): No `client_supports_elicitation`, `client_supports_sampling`, or `client_supports_roots` field exists anywhere in `McpServer`.
- **server.rs L329**: `session_caps.is_some_and(|c| c.supports_elicitation())` — the gate reads from the passed-in per-session handle, not from `self`.

The pre-fix code would have had server-level `AtomicBool` fields in `McpServer` written during any client's `initialize` and read during every subsequent request regardless of which client issued it. The current code proves isolation by the absence of such fields.

---

## Batch-Path Observation

At server.rs L797-798, batch requests within a single session dispatch through `server.handle_request(request)` (L991-993), which calls `handle_request_with_cancel` with all five optional arguments as `None`:

```rust
pub async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
    self.handle_request_with_cancel(request, None, None, None, None).await
}
```

This means batch-dispatched `tools/call` requests receive `session_caps = None`. In `create_tool_context` (server.rs L433-436), `None` produces `client_supports_elicitation = false` and `client_supports_sampling = false`. In `check_destructive_elicitation` (server.rs L329), `None` produces `supports_elicitation = false`, which causes the function to return `Err(...)` if `require_elicitation_on_destructive` is enabled.

This is documented in the `handle_request` doc comment at server.rs L986-990 as an intended limitation: "Server-to-client features (elicitation, sampling) are unavailable on this code path." The batch path does not forward `session_caps`, so destructive tools in a batch are hard-blocked when the feature flag is set.

---

## Key Invariants Summary

| # | Invariant | Enforced by |
|---|---|---|
| I1 | Each `serve_session` call creates exactly one `SessionCapabilities`, allocated on the heap and not stored in `McpServer`. | server.rs L646; absence of capability fields in `McpServer` struct L46-92. |
| I2 | All three flags default to `false`; `true` is set only after successful deserialization of `initialize` params. | `Default` derive at L10; setter calls at server.rs L1134-1153 inside `if let Some(caps) = session_caps` guards. |
| I3 | Flag writes happen in the reader-loop task before any request-handler task is spawned for this session. | Sequential execution: `route_incoming_message` (L695) completes before `tokio::spawn` (L735) for the same message. |
| I4 | `Ordering::Relaxed` on atomic stores/loads is safe because `Arc::clone` acts as the synchronization boundary. | Standard library `Arc` reference-count increment uses `AcqRel`; the clone at L734 publishes prior stores. |
| I5 | The `None` session_caps path (batch, legacy `handle_request`) is fail-closed: capability queries on `None` return `false`. | `Option::is_some_and` semantics at server.rs L329, L433-436. |

---

## Open questions

**OQ-1** — Re-initialization write ordering: `initialized` (`AtomicBool` at server.rs L62, set at L1163 with `SeqCst`) guards whether the server has processed an `initialize`. If a misbehaving client sends a second `initialize`, `handle_initialize` (L1083) does not short-circuit on `self.initialized.load()` before writing capabilities. Unclear whether there is a guard; need to inspect the full `handle_initialize` body at server.rs L1083-1160 for an early-return check.

**OQ-2** — `runtime_max_output_chars` at server.rs L65/L1125: This is a server-level `Arc<RwLock<Option<usize>>>` written during `initialize` with a client-specific override. With two concurrent sessions whose clients have different `max_output_chars` override profiles, the last writer wins. This is a cross-session contamination surface distinct from Vuln 9 but structurally similar. Need to confirm whether the HTTP transport is expected to serve multiple clients simultaneously.

**OQ-3** — `supports_roots` not propagated into `ToolContext`: `create_tool_context` (server.rs L390-439) snapshots `client_supports_elicitation` and `client_supports_sampling` from `session_caps`, but not `supports_roots`. Tool handlers receiving `ToolContext` cannot inspect the roots capability directly; they observe `ctx.roots` (the fetched list). If the roots list is stale or empty (e.g., fetched before the client sent `notifications/initialized`), a tool handler has no way to distinguish "client does not support roots" from "client supports roots but declared none." The observable behavior difference is unclear; need to inspect tool handlers that consume `ctx.roots`.

**OQ-4** — Batch path silently degrades: When `require_elicitation_on_destructive` is `true` and a client sends a batch containing a destructive tool call, the call is blocked with an error result (because `session_caps = None` implies `supports_elicitation = false`). The client receives no indication that the request would succeed in a non-batch form. This is a documented limitation but may be surprising to API consumers. No finding; structural observation for audit context.

**OQ-5** — `session_caps` not stored in `SessionData` (session_store.rs): The HTTP-transport `SessionData` (L29-35) does not carry `SessionCapabilities`. If the HTTP transport ever routes a `tools/call` request arriving on a reconnected SSE stream to a newly dispatched handler without the originating `serve_session`'s `session_caps`, the handler would receive `None` and lose capability context. Need to trace the HTTP transport's handler dispatch path to confirm whether `session_caps` is threaded correctly across SSE reconnects.


---

## src/mcp/transport/oauth.rs

**File:** `/home/muchini/mcp-ssh-bridge/src/mcp/transport/oauth.rs`
**Lines:** 1–499 (499 total)
**Branch:** `security/audit-2026-05-09`

---

### Structural map

| Symbol | Lines | Kind |
|--------|-------|------|
| `OAuthConfig` | L33–54 | Public struct + serde |
| `TokenClaims` | L57–73 | Public struct + method |
| `scopes` module | L76–85 | Pub constants |
| `JwtClaims` | L88–105 | Private struct (deserialization target) |
| `OAuthValidator` | L107–241 | Public struct with 5 methods |
| `OAuthValidator::new` | L131–136 | Constructor |
| `OAuthValidator::set_static_keys` | L139–141 | Mutating method |
| `OAuthValidator::key_count` | L144–147 | Accessor |
| `OAuthValidator::load_jwks` | L149–169 | Mutating method |
| `OAuthValidator::validate_token` | L171–241 | Core validation method |
| `oauth_middleware` | L244–286 | Axum async middleware |
| `unauthorized` | L288–297 | Helper |
| `OAuthMetadata::from_config` | L314–335 | Builder |

---

### Data-flow trust boundary

```
HTTP layer (untrusted)
  └─► oauth_middleware
        └─► OAuthValidator::validate_token(token: &str)   ← trust boundary
              ├─► decode_header(token)          [jsonwebtoken; parses untrusted bytes]
              ├─► allowlist match               [config-driven; trusted]
              ├─► kid lookup                    [config-driven; trusted]
              ├─► DecodingKey construction      [config-driven; trusted]
              ├─► Validation construction       [config-driven; trusted]
              └─► decode::<JwtClaims>()         [jsonwebtoken; returns verified claims]
```

`OAuthConfig` (issuer, audience, required\_scopes) originates from the YAML config loader, which is a trusted surface. The `token` bytes passed to `validate_token` are fully attacker-controlled.

---

### Function 1: `OAuthValidator::new` (L131–136)

#### 1. Purpose

Constructs an `OAuthValidator` with the caller-supplied `OAuthConfig` and an empty `HashMap` for public keys. No IO takes place. The constructor is intentionally minimal — the module-level doc (L10–18) explicitly states that an empty key map causes every token to be rejected with "Unknown JWT signing key", so callers must call `set_static_keys` or `load_jwks` before wiring the validator into a live path.

#### 2. Inputs and Assumptions

| Input | Type | Trust level |
|-------|------|-------------|
| `config` | `OAuthConfig` (by value) | Trusted — originates from YAML config loader |
| Implicit: no ambient global state | — | — |

Assumptions:
1. `config.issuer` is a non-empty, correctly formatted URL string when the validator will be used in production. No validation is performed here.
2. `config.audience` is a non-empty string. No validation is performed.
3. `config.required_scopes` may be empty (default), in which case any valid JWT will pass scope enforcement.
4. The caller is responsible for populating keys before any `validate_token` call; the constructor gives no warning on empty key map construction.
5. `OAuthConfig` is `Clone`, so the caller retains an independent copy after moving into `Self`.

#### 3. Outputs and Effects

- Returns `OAuthValidator { config, keys: HashMap::new() }`.
- No state writes outside the returned struct.
- No events emitted.
- No external interactions.

Postcondition: `self.keys.is_empty()` is always true immediately after `new` returns. Therefore `validate_token` will return `Err("Unknown JWT signing key: …")` for any token until `set_static_keys` or `load_jwks` is called.

#### 4. Block-by-Block Analysis

**L132–135 — struct literal construction**

- What: Moves `config` into the struct field, creates an empty `HashMap` for `keys`.
- Why here: Rust requires all fields to be initialised at construction time. `HashMap::new()` is zero-cost (no heap allocation until first insert).
- Assumptions: `OAuthConfig` implements `Move`. `HashMap::new()` is infallible.
- Depends on: nothing prior.
- First Principles: the invariant "no keys, no valid tokens" is intentionally baked in at construction rather than lazily discovered at validation time. This forces callers to consciously populate keys, preventing accidental permissive defaults.

Invariants established by `new`:
1. `self.keys.len() == 0` immediately after construction.
2. `self.config` is an exact copy of the caller's `OAuthConfig` at call time (subsequent config mutations in the caller do not propagate).
3. No key material is reachable from `self` until an explicit `set_static_keys` or `load_jwks` call.

#### 5. Cross-Function Dependencies

- Called by `oauth_middleware` (L275): `OAuthValidator::new((*config).clone())` — per-request construction, meaning the key map starts empty on every HTTP request (see Section on `oauth_middleware` below for the structural observation).
- Called by test helper `make_validator` (L400–411): here `set_static_keys` is called immediately after, satisfying the key-population invariant.
- `set_static_keys` and `load_jwks` are the only two functions that break the zero-key invariant established here.

---

### Function 2: `OAuthValidator::set_static_keys` (L139–141)

#### 1. Purpose

Replaces the entire in-memory key map with a caller-supplied list of `(kid, pem)` pairs. This is the primary path for populating RSA/ECDSA PEM public keys that were provisioned out-of-band (e.g. read from config files or a secrets manager).

#### 2. Inputs and Assumptions

| Input | Type | Trust level |
|-------|------|-------------|
| `&mut self` | mutable borrow | Internal |
| `keys` | `Vec<(String, String)>` | Trusted (caller controls key material) |

Assumptions:
1. The `String` values are assumed to be valid PEM blobs; no format validation is performed here. Validation defers to `DecodingKey::from_rsa_pem` at call time inside `validate_token`.
2. The `kid` strings (first tuple element) are assumed to be UTF-8 and non-empty. An empty `kid` is accepted by the `HashMap` without error.
3. Duplicate `kid` values in the input `Vec` are resolved by `collect()` using the last-wins semantics of `Iterator::collect::<HashMap>`.
4. The method is fully synchronous; callers must ensure no concurrent `validate_token` calls are in flight (there is no internal `RwLock`). Thread safety is the caller's responsibility — `OAuthValidator` does not implement `Sync`.
5. Calling `set_static_keys` with an empty `Vec` is legal and resets the key map to the same empty state as `new`.

#### 3. Outputs and Effects

- Replaces `self.keys` entirely (previous keys are dropped).
- No return value.
- No events emitted.
- No external interactions.

Postcondition: `self.keys.len() == keys.len()` (minus any duplicate kids, which collapse to one entry).

#### 4. Block-by-Block Analysis

**L140 — `self.keys = keys.into_iter().collect()`**

- What: Consumes the input `Vec` and rebuilds the `HashMap` atomically (from the perspective of single-threaded access).
- Why here: a single assignment is simpler than `clear()` + loop. It also ensures the old key map's memory is freed before the new one is held.
- Assumptions: `HashMap::collect` from an iterator of `(String, String)` does not fail.
- Depends on: `HashMap<String, String>`'s `FromIterator` implementation.
- 5 Whys on the full-replacement design: (1) Why replace rather than merge? To avoid stale key accumulation when keys rotate. (2) Why not sort or deduplicate before insertion? The caller is trusted; deduplication would add complexity for no gain in a trusted context. (3) Why not validate PEM here? Deferred to decode time to keep `set_static_keys` infallible. (4) Why no `RwLock`? `OAuthValidator` is designed for single-threaded setup followed by immutable use; thread safety is an `Arc`-wrapping concern for the caller. (5) Why consume the Vec? To avoid a heap clone of potentially large key material.

Invariants:
1. After `set_static_keys(v)`, `self.keys.len() <= v.len()`.
2. Only kids present in `v` are reachable; prior kids are permanently discarded.
3. Key material is stored as raw strings (no memory protection / zeroize).

#### 5. Cross-Function Dependencies

- Callers: `make_validator` (test, L410). No production call site in `oauth.rs` itself. The production call site must exist in whatever initialisation code constructs and populates the validator before wiring it into the router — that code is noted in the module doc as "left for a follow-up" (L15).
- `validate_token` reads `self.keys` at L199; `set_static_keys` is the primary writer.
- `key_count` (L144–147) reads `self.keys.len()` for diagnostics.

---

### Function 3: `OAuthValidator::load_jwks` (L149–169)

#### 1. Purpose

Parses a pre-fetched JWKS JSON document (RFC 7517) and replaces the in-memory key map with the RSA `n.e` component pairs found in it. The HTTP fetch is intentionally absent from this function; the caller provides the already-parsed `serde_json::Value` so this crate does not require an HTTP client dependency in the `http` feature gate.

#### 2. Inputs and Assumptions

| Input | Type | Trust level |
|-------|------|-------------|
| `&mut self` | mutable borrow | Internal |
| `jwks` | `&serde_json::Value` | Partially trusted — caller-fetched from remote JWKS URI |

Assumptions:
1. `jwks["keys"]` must be a JSON array. If absent or not an array, the function returns `Err("jwks.keys not an array")` and leaves `self.keys` unchanged.
2. Every key object in the array must contain `"n"` and `"e"` string fields (RSA modulus and public exponent, base64url-encoded). Any key missing either field causes the function to return `Err` and abort without partial writes (the temp `HashMap` is only assigned to `self.keys` at L167 after the loop completes successfully).
3. The `"kid"` field is optional; `unwrap_or_default()` (L162) means a missing `kid` yields an empty string `""` as the key identifier. Multiple keys with no `kid` will collide in the `HashMap`.
4. Only RSA keys (with `n` and `e` fields) are handled. EC keys (which use `x`, `y`, `crv`) are silently skipped if they lack `n`/`e`, because the `ok_or("jwk.n missing")?` early-return would fire first.
5. The caller is responsible for fetching the JWKS document from the correct URI and verifying TLS. This function performs no origin, freshness, or integrity checks on the document.
6. Thread safety: same as `set_static_keys`. No `RwLock` protection.

#### 3. Outputs and Effects

- Returns `Ok(())` on success.
- Returns `Err(String)` on parse failure, leaving `self.keys` unchanged.
- On success, `self.keys` is fully replaced with the new `HashMap`.
- No events emitted.
- No external interactions (the HTTP call is the caller's responsibility).

Postcondition: On `Ok`, `self.keys` contains exactly the `n.e`-format strings for each key in the JWKS array that has both `n` and `e` fields. EC-only keys are absent.

#### 4. Block-by-Block Analysis

**L160–166 — loop over JWKS array**

- What: Iterates over each JSON object in `jwks["keys"]`, extracts `kid`, `n`, `e`, and inserts `"<n>.<e>"` into a local `HashMap`.
- Why here: Building into a local `keys` before assigning to `self.keys` (L167) ensures atomicity — a parse failure partway through the array does not corrupt the existing key map.
- Assumptions: `k["n"]` and `k["e"]` are valid base64url strings. The function does not validate this; `DecodingKey::from_rsa_components` (called later in `validate_token` at L205) performs the actual base64 decode.
- Depends on: `serde_json::Value`'s indexing semantics. If `jwks` is not a JSON object, `jwks["keys"]` returns `Value::Null`, and `as_array()` returns `None`, triggering the early return.
- First Principles: The `n.e` string encoding is an internal convention for distinguishing JWK-sourced keys from PEM-sourced keys at `validate_token` L204. A JWK key contains a `.` separator; a PEM key does not. This is a structural invariant that must hold across both functions.

**L162 — `kid` extraction with `unwrap_or_default`**

- What: Silently falls back to `""` when a JWK object lacks a `kid` field.
- Why here: RFC 7517 does not mandate `kid`. However, `validate_token` requires `kid` from the token header (L196–198) and uses it for lookup. A token with a missing `kid` will return `Err("JWT missing kid header")` before the key lookup, so the empty-string key in the HashMap is unreachable via the normal path.
- 5 Hows consideration: How can a legitimate key with `kid = ""` be loaded? Via `load_jwks` with a JWKS entry missing `kid`. How is it later matched? Only if a token's header also omits `kid`, which `validate_token` already rejects (L196–198). So the empty-string slot is dead code in the normal flow.

**L167 — atomic assignment**

- What: Replaces `self.keys` only after the full loop succeeds.
- Why here: Guarantees that a partially parsed JWKS does not leave the validator in a mixed-key state.

Invariants:
1. `self.keys` is either fully replaced or unchanged (no partial writes on error).
2. EC-only keys (missing `n` or `e`) cause an `Err` return; they cannot be silently skipped.
3. The dot-separator encoding (`format!("{n}.{e}")`) is the discriminant used in `validate_token` to distinguish JWK-sourced from PEM-sourced keys.

#### 5. Cross-Function Dependencies

- `validate_token` (L204): reads the `n.e` format string and calls `key_material.split_once('.')`. Both functions share the invariant that a dot in the stored value means JWK, no dot means PEM.
- There is no production call site in `oauth.rs` itself; the module doc (L9–18) states JWKS loading is "left for a follow-up." The function exists for future use or caller-controlled setup.
- Risk consideration for the remote JWKS source: the caller fetches the document over HTTP/HTTPS. If TLS verification is skipped or the fetch is from an attacker-controlled URI, the entire key set can be replaced with attacker keys. This function performs zero origin checks.

---

### Function 4: `OAuthValidator::validate_token` (L179–241)

This is the primary security-enforcing function. The analysis follows every branch.

#### 1. Purpose

Given a raw JWT string from the HTTP layer (fully attacker-controlled), perform a multi-stage validation pipeline: (a) parse the unverified header to extract algorithm and key id; (b) reject all non-asymmetric algorithms; (c) look up the matching public key; (d) construct a `jsonwebtoken::Validation` object; (e) cryptographically verify the token and decode claims; (f) enforce scope requirements. Returns `TokenClaims` on success or a human-readable error string on any failure.

#### 2. Inputs and Assumptions

| Input | Type | Trust level |
|-------|------|-------------|
| `&self` | shared borrow | Internal |
| `token` | `&str` | UNTRUSTED — caller-controlled bytes from HTTP Authorization header |
| `self.config.issuer` | `String` | Trusted — from YAML config |
| `self.config.audience` | `String` | Trusted — from YAML config |
| `self.config.required_scopes` | `Vec<String>` | Trusted — from YAML config |
| `self.keys` | `HashMap<String,String>` | Trusted — populated by `set_static_keys` or `load_jwks` |

Assumptions:
1. `token` may be any sequence of UTF-8 bytes. No length limit is enforced by this function; the HTTP body size limit (1MB, L230 in `http.rs`) is the only upstream cap.
2. `self.config.issuer` is non-empty in production. If empty, `Validation::set_issuer(&[""])` will match only tokens whose `iss` claim is the empty string.
3. `self.config.audience` is non-empty in production. Same concern as issuer.
4. `self.keys` may be empty (in the `oauth_middleware` path, it always is — see L275 `http.rs`). This causes every token to fail at L200 with "Unknown JWT signing key".
5. The `scope` claim in the token is a space-delimited string (RFC 8693 §4.2). The code at L222–226 splits on whitespace, which also handles tab/newline separators.
6. `sub` claim is optional (`Option<String>` in `JwtClaims`, L91); `unwrap_or_default()` at L236 means a missing `sub` yields `""` in `TokenClaims`.
7. `aud` claim (L97) is deserialized as `serde_json::Value` and marked `allow(dead_code)` — claim validation against the configured audience is delegated to `jsonwebtoken` via `Validation::set_audience`.
8. The 30-second leeway at L217 applies to both `exp` and `nbf` checks.

#### 3. Outputs and Effects

- Returns `Ok(TokenClaims { sub, iss, scopes })` on success.
- Returns `Err(String)` on any validation failure; the error string is logged (L282) and returned to the HTTP client as a JSON body. The error string may echo back token content (e.g. kid value from `format!("Unknown JWT signing key: {kid}")` at L200).
- No state writes (shared borrow).
- No events emitted.
- No external interactions.

Postcondition: If `Ok` is returned, the caller can trust that the token was signed by a key whose `kid` is registered, the algorithm is in the asymmetric allowlist, `iss` matches `self.config.issuer`, `aud` matches `self.config.audience`, `exp` is in the future (within leeway), `nbf` (if present) is in the past (within leeway), and all `required_scopes` are present.

#### 4. Block-by-Block Analysis

**L181 — `decode_header(token)`**

- What: Calls `jsonwebtoken::decode_header`, which base64url-decodes and JSON-parses only the first segment of the JWT (the header). No signature verification occurs. Returns a `jsonwebtoken::Header` containing `alg` and optionally `kid`.
- Why here: The algorithm and kid must be known before the correct decoding key can be selected.
- Assumptions: `token` is a `.`-delimited string with at least two segments. `decode_header` returns `Err` for any malformed input, which is mapped to `Err("Invalid JWT header: …")`.
- Depends on: The `jsonwebtoken` crate. The parsed `header.alg` is a typed `Algorithm` enum — the attacker controls which variant is deserialized. This is the known context item documented in the Task-4 context7 audit: `header.alg` is unverified at this point.
- First Principles (algorithm confusion root): The purpose of reading the header first is key selection, not algorithm trust. The algorithm read here must be cross-checked against an allowlist before being used in `Validation::new(header.alg)` at L212. The next block performs that check.

**L184–194 — algorithm allowlist match**

- What: A `match` on `header.alg` accepts only `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `PS256`, `PS384`, `PS512`. Any other variant (including `HS256`, `HS384`, `HS512`, `EdDSA`, `none`/`None`) triggers `return Err(format!("Algorithm '{other:?}' not accepted"))`.
- Why here: This is the first line of defense against algorithm-confusion attacks. Without it, an attacker could present an HMAC-signed token using the public key as the HMAC secret.
- Assumptions: The `Algorithm` enum variants in `jsonwebtoken` exactly correspond to the identifiers in the JWT header `alg` field. The `none` algorithm maps to either a parse error (most JWT libs reject `alg: none` at the header decode stage) or to an enum variant caught by the `other` arm.
- 5 Whys on the allowlist: (1) Why not accept EdDSA? Not listed — unclear if an intentional omission or an oversight. (2) Why reject HS family here rather than at `Validation::new` time? Because `Validation::new(header.alg)` would build a validator for the attacker's chosen HS algorithm and then the caller-supplied key (a public RSA key in PEM) would be used as an HMAC secret. The allowlist check must precede key selection and `Validation` construction. (3) Why use a `match` rather than a set? Exhaustive pattern coverage means a new `Algorithm` variant added by a dependency update would produce a compile error, forcing an explicit decision. (4) Why return early rather than falling through? Fail-fast prevents any further processing of a structurally-rejected token. (5) Why does the reject branch echo `other:?`? The `Debug` repr of `Algorithm` contains the variant name (e.g. `"HS256"`), which is safe to expose in error messages.
- Depends on: L181's `decode_header` successfully returning a `Header` with a valid `alg`.

**L196–202 — kid extraction and key lookup**

- What: Extracts `header.kid` (L196–198), returning `Err("JWT missing kid header")` if absent. Then looks up `self.keys.get(&kid)` (L199–202), returning `Err("Unknown JWT signing key: {kid}")` if not found.
- Why here: After the algorithm is confirmed safe, the correct public key must be identified. Requiring `kid` prevents the validator from iterating all known keys, which would be a potential timing oracle.
- Assumptions: `kid` is an arbitrary attacker-controlled string after extraction from the header. It is used only as a lookup key in `self.keys` (a `HashMap`); it is not used for any other operation. The `format!` at L200 embeds the raw `kid` value into the error string. If `kid` contains control characters or very long strings, those are echoed in the error response body (see `unauthorized` at L290 → JSON-encoded).
- 5 Hows on requiring kid: (1) How does the kid requirement interact with a JWKS that has empty-kid entries from `load_jwks`? Those entries are keyed on `""` in the HashMap but cannot be matched because `validate_token` returns `Err("JWT missing kid header")` for a token with no `kid` before reaching the lookup. (2) How does the lookup scale? `HashMap::get` is O(1) average. (3) How is the kid validated? It is not. Any string is accepted as a lookup key. (4) How long can kid be? No length limit enforced by this function. (5) How does this interact with the per-request empty key map in `oauth_middleware`? The lookup always fails because `self.keys` is always empty in that path.

**L204–210 — key material discrimination and `DecodingKey` construction**

- What: Calls `key_material.split_once('.')` to determine whether the stored value is in `n.e` JWK format or raw PEM format. JWK components call `DecodingKey::from_rsa_components(n, e)`; PEM calls `DecodingKey::from_rsa_pem(key_material.as_bytes())`.
- Why here: The dot-separator convention was established in `load_jwks` (L165). This is the other end of that invariant.
- Assumptions: `key_material.split_once('.')` splits on the first `.`. A PEM blob contains no `.` characters (PEM uses `-----BEGIN PUBLIC KEY-----` and base64 with no periods). A JWK `n.e` string contains exactly one `.`.
- Depends on: The invariant that `load_jwks` always stores `format!("{n}.{e}")` and `set_static_keys` stores raw PEM. If a PEM blob ever contained a `.` in the base64 segment, the discriminant would misfire. Standard base64 uses `+`, `/`, `=` — not `.` — so this is structurally sound for correctly formed PEM.
- First Principles on key format discrimination: The dot-separator is an internal encoding convention, not a data-format standard. It is not validated; it is a coincidental property of the two data shapes. A malformed PEM with an embedded `.` (e.g. from a corrupted config or injected newline) would cause `DecodingKey::from_rsa_components` to be called with incorrect arguments and fail at the decode step, not silently succeed.
- Only RSA components are constructed here. The `from_rsa_components` path handles keys loaded via `load_jwks`. The `from_rsa_pem` path handles keys loaded via `set_static_keys`. EC keys loaded via `set_static_keys` as PEM would use `from_rsa_pem` and fail at decode time with an error from the `jsonwebtoken` layer, not silently.

**L212–217 — `Validation` construction**

- What: Creates `Validation::new(header.alg)`, then sets issuer, audience, enables `validate_exp`, `validate_nbf`, and sets 30-second leeway.
- Why here: The `Validation` object encodes what the `decode` call must enforce. Building it after the allowlist check means `header.alg` has already been confirmed to be asymmetric.
- Assumptions: `Validation::new(header.alg)` pins the expected algorithm to `header.alg`. Any token whose header `alg` differs from this will be rejected by `decode`. Since `header.alg` was already checked against the allowlist, the algorithm pinned here is always in `{RS256, RS384, RS512, ES256, ES384, PS256, PS384, PS512}`.
- Known context item (do not re-flag): `Validation::new(header.alg)` uses the attacker-controlled algorithm from the header. The allowlist check at L184–194 is the mitigation. What is documented here for context: the mitigation works because the allowlist check is a pure `match` with no fall-through, and `Validation::new` with any of the listed algorithms configures signature verification for asymmetric keys only.
- Known context item (do not re-flag): `set_required_spec_claims` is not called at L212–217. The default `Validation::new` marks `["exp"]` as required spec claims. The code explicitly sets `validate_exp = true` (L215, already the default), `validate_nbf = true` (L216, non-default), and leeway (L217). Issuer and audience are set via `set_issuer`/`set_audience` (L213–214), which also add those claims to the internal required-claims set in `jsonwebtoken` 9.x.

**L219–220 — `decode::<JwtClaims>` call**

- What: Performs full cryptographic verification of the token signature against `decoding_key`, and deserializes the payload into `JwtClaims`.
- Why here: This is the trust anchor. After this call, all fields in `data.claims` are cryptographically verified.
- Assumptions: `JwtClaims` must successfully deserialize from the verified payload. Missing required fields (e.g. `iss` is not `Option`) would cause `decode` to return `Err`.
- Depends on: All prior blocks. `decoding_key` must match the algorithm configured in `validation`.
- The `exp` field in `JwtClaims` is `i64` (L101), marked `allow(dead_code)`. Its enforcement is entirely delegated to `Validation`. Deserializing it into the struct does not re-validate it; the struct field is there for completeness only.

**L222–226 — scope extraction**

- What: Splits `data.claims.scope` (a space-delimited string) on whitespace and collects into `Vec<String>`.
- Why here: Scope enforcement (L229–233) requires a structured representation. Splitting post-verification ensures the scope string is from the verified payload.
- Assumptions: `scope` is `#[serde(default)]` (L98), so a missing `scope` claim yields an empty string, producing an empty `Vec<String>`. The scope format is `"scope1 scope2 scope3"` (RFC 8693). Any internal whitespace (tabs, multiple spaces) produces empty strings in the split result; `split_whitespace()` (not `split(' ')`) handles this correctly by treating consecutive whitespace as a single delimiter.

**L229–233 — required scope enforcement**

- What: Iterates `self.config.required_scopes`, returning `Err` if any required scope is absent from the extracted `scopes` Vec.
- Why here: Authorization (scope) enforcement is separate from authentication (signature + claims). It runs after the signature is verified.
- Assumptions: Scope comparison is case-sensitive exact-string equality (`s == required` at L230). A scope like `"MCP:TOOLS:EXECUTE"` would not match `"mcp:tools:execute"`.
- 5 Whys on scope check ordering: (1) Why after `decode` rather than before? Scopes are in the payload, which is untrusted until the signature is verified. (2) Why iterate `required_scopes` rather than checking a set? For small scope lists (typical: 1–4 items), linear scan is adequate. (3) Why return on the first missing scope? Fail-fast; the error message names the specific missing scope, aiding debugging. (4) Why exact-match rather than prefix? MCP scopes are full identifiers; prefix matching would be unsound. (5) Why is `required_scopes` trusted? It comes from the YAML config, not the token.

**L235–239 — `TokenClaims` construction**

- What: Builds the returned `TokenClaims` from verified claim fields.
- Why here: The public API exposes `TokenClaims`, not `JwtClaims`, keeping internal deserialization details private.
- Assumptions: `sub` is `unwrap_or_default()` — a token without a `sub` yields `""`. Callers receiving `sub = ""` cannot use it as a meaningful principal identifier.

Invariants for `validate_token`:
1. If `Ok` is returned, the token was signed by a key whose `kid` is in `self.keys` and whose algorithm is in the asymmetric allowlist.
2. If `Ok` is returned, `iss == self.config.issuer` and `aud` includes `self.config.audience` (enforced by `jsonwebtoken`).
3. If `Ok` is returned, all strings in `self.config.required_scopes` are present in `TokenClaims.scopes`.

#### 5. Cross-Function Dependencies

- `decode_header`: `jsonwebtoken` crate, external. Input: attacker-controlled `token`. Output: parsed `Header` (alg, kid). Risk: this function must be treated as parsing untrusted data; its output must not be trusted until the allowlist check passes.
- `DecodingKey::from_rsa_components` / `from_rsa_pem`: `jsonwebtoken` crate, external. Input: trusted key material. If malformed, returns `Err` which propagates as `Err(String)` to the caller. Risk: malformed keys in `self.keys` surface here, not at load time.
- `decode::<JwtClaims>`: `jsonwebtoken` crate, external. The most critical external call. Input: untrusted token bytes, trusted decoding key, trusted validation config. The crate documentation (cached in `audit/2026-05-09/surface/context7/jsonwebtoken.md`) confirms that `Validation::new(alg)` pins the algorithm and that `set_issuer`/`set_audience` add those claims to the required set. Risk: behavioral changes across `jsonwebtoken` crate versions could silently weaken enforcement without code changes.
- `oauth_middleware` calls `validate_token` at L276. The validator it creates at L275 has an empty key map, so every token fails at the kid-lookup step (L200). This is documented in the module-level comment (L10–18) and in the comment at L272–274.
- Callers in tests (`jwt_verification_tests`) call `validate_token` on a properly populated validator (via `make_validator`), which is the intended production shape.

---

### Function 5: `oauth_middleware` (L244–286)

#### 1. Purpose

An Axum async middleware function that intercepts every HTTP request and enforces OAuth Bearer-token authentication when `config.enabled = true`. It extracts the `Authorization: Bearer <token>` header, constructs a per-request `OAuthValidator`, delegates to `validate_token`, and either forwards to `next` or returns HTTP 401.

#### 2. Inputs and Assumptions

| Input | Source | Trust level |
|-------|--------|-------------|
| `request: Request` | Axum framework | Untrusted HTTP request |
| `next: Next` | Axum framework | Trusted next-middleware chain |
| `Arc<OAuthConfig>` from `request.extensions()` | Set by `build_router_with_store` L183 | Trusted |

Assumptions:
1. `Arc<OAuthConfig>` is expected to be present in extensions when OAuth is enabled; if absent, the middleware passes through without authentication (L248–251).
2. The `Authorization` header value is expected to be valid UTF-8; non-UTF-8 values are silently treated as absent (`.and_then(|v| v.to_str().ok())` at L261).
3. Bearer token prefix matching is case-sensitive: `auth.strip_prefix("Bearer ")` at L267. A header value of `"bearer token123"` (lowercase) would fail this check and return 401.
4. `token.trim()` at L270 strips leading/trailing whitespace from the extracted token. This is the only normalization applied.
5. The `OAuthValidator` constructed at L275 has an empty key map (see module doc L10–18). Therefore, `validate_token` always returns `Err("Unknown JWT signing key: …")` in this path.
6. `(*config).clone()` at L275 performs a full `OAuthConfig` clone on every request.

#### 3. Outputs and Effects

- On success: calls `next.run(request).await` — forwards the unmodified request. The `TokenClaims` are logged at `debug` level (L278) but are not injected into the request extensions. Downstream handlers cannot access the validated claims.
- On failure: returns the output of `unauthorized(&e)` — HTTP 401 with a JSON body `{"error":"unauthorized","message":"<error>"}`. The error message may contain the kid from the token header.
- No state writes.
- No events emitted beyond logging.

Postcondition: If `next.run` is called, either OAuth is disabled, or OAuth is enabled but the key map is empty — meaning no real validation has occurred in the current implementation.

#### 4. Block-by-Block Analysis

**L246–255 — config extraction and early pass-through**

- What: Attempts to extract `Arc<OAuthConfig>` from request extensions. If absent, passes through. If present but `!config.enabled`, passes through.
- Why here: The middleware is registered unconditionally when `oauth_config.enabled` is true (`http.rs` L181–183), so `config.enabled` should always be `true` here. The check at L253 is therefore defensive — it cannot be false in the production wiring.
- Assumptions: The only way `config` is absent from extensions is if the middleware is somehow registered without the corresponding `axum::Extension` layer. The `build_router_with_store` function (http.rs L181–183) always adds both the middleware and the extension in sequence.
- 5 Hows on the pass-through: How can an operator disable auth after enabling it? Restart with `enabled: false` in config — the middleware is not added (http.rs L181). How can the pass-through be reached? Either the extension was not added (wiring error) or `enabled = false` (defensive check). How does this affect security? A wiring error would silently bypass auth. How would such an error manifest? All requests pass through — no 401. How is this testable? A test that registers the middleware without the extension and expects 200 for an unauthenticated request.

**L258–269 — Authorization header extraction**

- What: Reads the `authorization` header (lowercase), converts to `&str`, strips `"Bearer "` prefix. Returns 401 if absent or not a Bearer scheme.
- Why here: Header extraction must precede token parsing.
- Assumptions: Axum's `HeaderMap` stores header names lowercase-normalized. The `"authorization"` key (lowercase) matches HTTP/2 pseudo-header conventions.

**L275 — per-request `OAuthValidator` construction**

- What: `OAuthValidator::new((*config).clone())` — creates a fresh validator with no keys.
- Why here: The module doc explains this is a known structural gap pending the follow-up to wire `Arc<OAuthValidator>` through extensions.
- Depends on: `OAuthValidator::new` (always produces an empty key map).
- Structural observation: Because the key map is always empty, `validate_token` always fails at the kid-lookup step (L200). The algorithm allowlist check (L184–194) is never reached in this code path in production.

**L276–284 — validate and route**

- What: Calls `validate_token`, logs the outcome, and either forwards or returns 401.
- Assumptions: The error message from `validate_token` is forwarded to the HTTP client in the JSON body at L282. The `warn!` macro logs the error at L283.

Invariants:
1. If `config.enabled = true` and the extension is wired, every request without a valid Bearer header reaches `validate_token`.
2. `validate_token` always fails in the current wiring because the validator has an empty key map.
3. Validated `TokenClaims` are not injected into request extensions; downstream handlers have no access to principal or scope information.

#### 5. Cross-Function Dependencies

- `OAuthValidator::new` (L275): see analysis above.
- `OAuthValidator::validate_token` (L276): core dependency.
- `build_router_with_store` (http.rs L161–233): the caller that registers this middleware. Wiring order: OAuth middleware is added before the extension (http.rs L182 then L183). Axum applies layers in reverse registration order, so the extension is available when the middleware runs.
- `unauthorized` (L282): helper that produces the 401 response.

---

### Function 6: `OAuthMetadata::from_config` (L314–335)

#### 1. Purpose

Builds an `OAuthMetadata` struct (RFC 8414 Authorization Server Metadata) from an `OAuthConfig` and a base URL string. This is returned by the `GET /.well-known/oauth-authorization-server` discovery endpoint. It is an informational document; it does not perform any authentication or authorization.

#### 2. Inputs and Assumptions

| Input | Type | Trust level |
|-------|------|-------------|
| `config` | `&OAuthConfig` | Trusted — from YAML config |
| `base_url` | `&str` | Trusted — constructed from `config.bind` in `handle_oauth_discovery` |

Assumptions:
1. `config.issuer` may be empty; the code defaults to `base_url` in that case (L316–320).
2. `base_url` is constructed from `config.bind` as `format!("http://{}", state.config.bind)` (http.rs L502). This is always HTTP, not HTTPS, regardless of the TLS configuration. There is no TLS configuration in the current codebase.
3. `token_endpoint` is hardcoded as `"{base_url}/oauth/token"` (L321). No `/oauth/token` route is defined in `build_router_with_store`. A client following this metadata document would attempt to obtain tokens from a nonexistent endpoint.
4. The four `scopes_supported` values are hardcoded from the `scopes` module constants (L322–327). They do not reflect `config.required_scopes`, which may be a subset or superset.
5. `grant_types_supported` includes `"authorization_code"` and `"client_credentials"` (L329–332). No authorization code flow is implemented.

#### 3. Outputs and Effects

- Returns an `OAuthMetadata` struct.
- No state writes.
- No events emitted.
- No external interactions.

Postcondition: The returned metadata is a static description of capabilities, not a live description of what is implemented.

Invariants:
1. `metadata.issuer` is never empty; it defaults to `base_url` when `config.issuer` is empty.
2. `metadata.token_endpoint` always points to a non-existent route.
3. The scopes in `metadata.scopes_supported` are hardcoded and not derived from config.

#### 4. Cross-Function Dependencies

- Called by `handle_oauth_discovery` (http.rs L497–504), which supplies `base_url` from `config.bind`.
- The discovery endpoint is behind the `origin_guard` middleware but not behind the OAuth middleware (http.rs L189–196 vs L181–183 wiring).

---

### HTTP layer wiring: how `OAuthValidator` is integrated

In `build_router_with_store` (http.rs L161–233):

```
L181: if oauth_config.enabled {
L182:     router = router.layer(axum::middleware::from_fn(super::oauth::oauth_middleware));
L183:     router = router.layer(axum::Extension(Arc::clone(&oauth_config)));
       }
```

Key structural observations:
- The OAuth middleware is registered at L182 with `from_fn`, not `from_fn_with_state`. It receives no `Arc<OAuthValidator>` — only the `Arc<OAuthConfig>` extension at L183.
- Layer application order in Axum: layers are applied in reverse registration order. So `axum::Extension(oauth_config)` (L183, applied second) runs before `oauth_middleware` (L182, applied first in Axum's execution order). The extension is therefore available when the middleware extracts it from `request.extensions()`.
- The middleware constructs a new `OAuthValidator::new(config.clone())` on every request (oauth.rs L275), with an empty key map. This is the wiring gap documented in the module comment (oauth.rs L10–18).
- `TokenClaims` from a successful `validate_token` are not stored in request extensions (oauth.rs L278–279). The `next.run(request)` call passes the original unmodified request. No downstream handler can access the validated principal or scopes without re-parsing the token.

Token claims and session mapping:

The `SessionStore` and `SessionData` (session_store.rs) contain no reference to `TokenClaims`, `sub`, or any OAuth principal. Session IDs are randomly generated UUIDs (http.rs L298). There is no mapping from a validated OAuth principal to a session. A client can create multiple sessions with different tokens, or the same session with different tokens across requests, without any cross-session principal consistency enforcement.

---

### `JwtClaims` struct (L88–105) — structural note

`JwtClaims` is the deserialization target for the verified JWT payload.

| Field | Type | `serde` attribute | Structural note |
|-------|------|-------------------|-----------------|
| `sub` | `Option<String>` | `#[serde(default)]` | Missing `sub` yields `None`; surfaces as `""` in `TokenClaims` |
| `iss` | `String` | (none) | Required by `serde`; missing `iss` causes deserialization `Err` |
| `aud` | `serde_json::Value` | `#[allow(dead_code)]` | Deserializes any JSON shape; validation delegated to `jsonwebtoken` |
| `scope` | `String` | `#[serde(default)]` | Missing `scope` yields `""` (no scopes) |
| `exp` | `i64` | `#[allow(dead_code)]` | Present for completeness; enforcement by `Validation` |
| `nbf` | `Option<i64>` | `#[serde(default)]`, `#[allow(dead_code)]` | Optional; enforcement by `Validation` |

The `aud` field is `#[allow(dead_code)]` and typed `serde_json::Value` to accept both `"aud":"str"` and `"aud":["str"]` shapes per RFC 7519 §4.1.3. Actual validation is performed by `jsonwebtoken` internally via `Validation::set_audience`. The struct field exists only to allow deserialization to succeed for both shapes.

---

## Open questions

1. **Key population in production.** `oauth_middleware` constructs a zero-key `OAuthValidator` per request (oauth.rs L275). The module doc (L10–18) states this is a known gap pending a follow-up that wires `Arc<OAuthValidator>` through Axum extensions. What is the current mechanism, if any, for populating keys in a production HTTP deployment? Is there any call site outside tests that calls `set_static_keys` or `load_jwks`? (Unclear; need to search all callers of `OAuthValidator::new` outside `oauth.rs`.)

2. **EdDSA omission.** The algorithm allowlist (L185–192) includes `RS*`, `ES*`, `PS*` but not `EdDSA`. Is this intentional (e.g. the `jsonwebtoken` version in use does not expose EdDSA for JWKS paths) or an oversight? The `DecodingKey` construction at L204–210 only handles RSA paths (`from_rsa_components` and `from_rsa_pem`). An ES256-signed token would pass the allowlist check but then attempt to use an RSA decoding key, causing a `decode` error. Confirm whether EC PEM keys are supported via `set_static_keys` and whether `from_rsa_pem` also accepts EC public keys in `SubjectPublicKeyInfo` format.

3. **`set_required_spec_claims` absence (known context item).** As documented in `audit/2026-05-09/surface/context7/jsonwebtoken.md`, `set_required_spec_claims` is not called. What claims does `jsonwebtoken 9.x`'s `Validation::new(alg)` mark as required by default, and do `set_issuer`/`set_audience` implicitly add `iss`/`aud` to the required set? Confirm against the `jsonwebtoken` 9.x source to establish whether `iss` and `aud` can be absent from the token payload without causing a `decode` error.

4. **`sub` optionality.** `sub` is `Option<String>` with `unwrap_or_default()` (L236). A token without `sub` produces `TokenClaims { sub: "" }`. Since claims are not injected into request extensions, this is currently a latent issue rather than an active one. If downstream handlers are ever given access to `TokenClaims`, a missing `sub` yielding `""` would need to be distinguished from a subject whose name is the empty string.

5. **EC key format mismatch.** `validate_token` L207–209 uses `DecodingKey::from_rsa_pem` for the non-JWK path. The name implies RSA-only. If `set_static_keys` is called with an EC PEM, does `from_rsa_pem` accept it (some implementations accept generic `SubjectPublicKeyInfo` PEM regardless of key type), or does it silently fail? Need to inspect `jsonwebtoken`'s `DecodingKey::from_rsa_pem` implementation to confirm.

6. **kid echo in error responses.** `format!("Unknown JWT signing key: {kid}")` (L200) and the `unauthorized` helper (L290–296) produce a JSON response body containing the kid. The kid is attacker-controlled. While JSON-encoded (no raw HTML injection path), an extremely long kid could produce a large error response body. The only upstream size guard is the request body limit (1MB at http.rs L230), but the `Authorization` header is not subject to this limit.

7. **Token claims not propagated downstream.** `validate_token` returns `TokenClaims` with `sub`, `iss`, and `scopes`, but `oauth_middleware` does not inject these into request extensions (oauth.rs L278–279). If OAuth-gated handlers need to enforce per-operation scope checks (e.g. require `mcp:tools:execute` for a destructive tool), they have no access to the validated claims. The `scopes` module constants (L76–85) suggest this level of granularity is intended, but the propagation path does not exist.

8. **No JWKS refresh scheduling.** `load_jwks` (L149–169) exists but is never called in the current codebase outside tests. There is no scheduled refresh loop, no cache invalidation, and no TTL on the loaded keys. Key rotation at the IdP would require a server restart or an explicit out-of-band `load_jwks` call.

9. **`allowed_origins` and OAuth independence.** The `origin_guard` middleware (http.rs L121–143) rejects requests with no `Origin` header. Non-browser OAuth clients (e.g. a server-side daemon using `client_credentials`) do not send an `Origin` header. This means non-browser clients are rejected at the origin gate before reaching the OAuth middleware, even if they present a valid Bearer token. Need to confirm whether this is intentional design (loopback-only non-browser clients) or a gap for legitimate M2M OAuth clients.

---

**Relevant source files:**

- `/home/muchini/mcp-ssh-bridge/src/mcp/transport/oauth.rs`
- `/home/muchini/mcp-ssh-bridge/src/mcp/transport/http.rs`
- `/home/muchini/mcp-ssh-bridge/src/mcp/transport/session_store.rs`
- `/home/muchini/mcp-ssh-bridge/audit/2026-05-09/surface/context7/jsonwebtoken.md`
- `/home/muchini/mcp-ssh-bridge/tests/fixtures/oauth/test_pub.pem`

---

## `src/ssh/client.rs` — Handler + Auth Path: Per-Function Micro-Analysis

Relevant source files:
- `/home/muchini/mcp-ssh-bridge/src/ssh/client.rs`
- `/home/muchini/mcp-ssh-bridge/src/ssh/known_hosts.rs`
- `/home/muchini/mcp-ssh-bridge/src/ssh/pool.rs`
- `/home/muchini/mcp-ssh-bridge/src/config/types.rs` (L439-L481 for `AuthConfig`)

---

## 1. `ClientHandler` struct and `Handler::check_server_key`

**Source**: `client.rs` L146-L182

---

### Purpose

`ClientHandler` is the concrete implementation of `russh::client::Handler` whose sole security-critical method, `check_server_key`, executes host-key verification before any credentials are transmitted. It exists to bridge the russh callback mechanism (which invokes `check_server_key` during the SSH handshake, before authentication begins) into the project's own `known_hosts` verification layer. Without a correct implementation here, a MITM is undetectable because russh calls `check_server_key` before the encrypted session is established and before any auth data is sent.

---

### Inputs and Assumptions

1. **`server_public_key: &PublicKey`** — type `russh::keys::PublicKey`. Trust level: **untrusted**. This value comes directly from the remote server's SSH handshake message. It has been parsed by russh from the wire; the correctness of that parse depends on the russh library (opaque; no internal source).
2. **`self.hostname: String`** — trust level: **trusted** (sourced from `HostConfig.hostname`, which is config-file controlled). This field is set at `ClientHandler::new` call sites in `establish_connection` (L349) and `connect_via_jump` (L294). It contains the configured target hostname, NOT the DNS-resolved or network-level address.
3. **`self.port: u16`** — trust level: **trusted** (sourced from `HostConfig.port`). Set at L349 and L294.
4. **`self.verification_mode: HostKeyVerification`** — trust level: **trusted** (sourced from `HostConfig.host_key_verification`, default `Strict`). Copied by value (enum is `Copy`, L315 of `config/types.rs`).
5. **Assumption: russh invokes this callback exactly once per handshake**, before authentication. If russh ever re-invokes this after key material has been transmitted (e.g., on re-key), the semantics are unclear without reading russh internals.
6. **Assumption: `hostname` matches the identity the user intended to connect to**, not a DNS-resolved IP. The `known_hosts` file standard includes entries keyed by hostname or IP; if the caller passes `target_host` as an IP string (L347 `let target_host = &host.hostname`) and the `known_hosts` file stores a hostname alias, verification may yield `Unknown` even for a legitimate host.
7. **Assumption: `verify_host_key` is synchronous and not cancellation-sensitive**. The method signature is `async fn` (russh trait requirement), but the internal call (L169-L174) is entirely synchronous blocking I/O through `check_known_hosts` (from russh-keys). If the `known_hosts` file is on a slow filesystem, this blocks the async executor.
8. **Assumption: `PublicKey` can safely be compared against stored host keys**. No constraint on key type or algorithm: RSA, ECDSA, Ed25519 are all accepted as the server-presented key type.

---

### Outputs and Effects

1. **Returns `Ok(true)`** — tells russh to accept the connection and proceed to the authentication phase. Occurs only when `known_hosts::verify_host_key` returns `Ok(())` (L175).
2. **Returns `Ok(false)`** — tells russh to reject the connection. russh will then tear down the transport layer. Occurs on any `Err` from `verify_host_key` (L177). The error is logged at `tracing::error!` level with `error = %e` but the return value is `Ok(false)`, not `Err(...)`.
3. **Side effect: logs error** — on verification failure, `tracing::error!` at L177 is emitted. This log does NOT include the actual key fingerprint or the presented key bytes, only the error string from `BridgeError` (which does include fingerprint data for `SshHostKeyMismatch` and `SshHostKeyUnknown` error variants, as seen in `verify_host_key` at known_hosts.rs L137-L145).
4. **No state mutation** — `ClientHandler` fields are never written after construction. `verify_host_key` does mutate the `known_hosts` file in `AcceptNew` mode (via `add_key` at known_hosts.rs L156), which is a filesystem side effect from within this callback.

**Postcondition**: After `Ok(true)` is returned, russh proceeds with authentication. The `ClientHandler` instance is consumed or retained by the russh session handle for the session lifetime (unclear from russh internals; the `Handler` is passed by move into `client::connect`).

---

### Block-by-Block Analysis

**Block 1: Struct definition and constructor (L146-L160)**

- **What**: Defines `ClientHandler` with three fields (`hostname`, `port`, `verification_mode`) and a `const fn new`.
- **Why here**: The handler must carry enough context to perform verification without global state (no `Mutex`, no `Arc`). Keeping it immutable after construction is the right design.
- **Assumptions**: All three fields are known before connection is attempted; they come from `HostConfig` which has been validated at config load time.
- **Depends on**: `HostKeyVerification` being `Copy` (it is: L314 of `config/types.rs`). If it were not `Copy`, the `const fn` would not compile.
- **First Principles**: Why not embed a reference to `HostConfig` directly? Because `Handle<ClientHandler>` must be `'static` for russh's async machinery; a reference would impose a lifetime constraint that would propagate through the entire connection stack. Using owned `String` + `Copy` enum avoids this entirely.

**Block 2: `check_server_key` — delegation to `known_hosts::verify_host_key` (L165-L181)**

- **What**: Calls `known_hosts::verify_host_key` and maps its `Result<()>` to `Result<bool>` using `Ok(true)` for success and `Ok(false)` for failure.
- **Why here**: This is the single extension point russh provides for host verification. The implementation must not return `Err` unless russh can handle that appropriately; returning `Ok(false)` is the safe rejection path.
- **Assumptions**: `known_hosts::verify_host_key` is infallible in the sense that it will always return either `Ok(())` or `Err(BridgeError::...)` — never panic. The `Err` branch at L176-L179 swallows the error type into `Ok(false)`, so any `Err` from the filesystem (e.g., permissions error, disk full) is treated identically to a legitimate verification failure (key mismatch or unknown host). This flattening is documented (implicitly by the design) but makes the failure reason visible only via the error log.
- **Depends on**: `known_hosts::verify_host_key` consuming the same `hostname`/`port` combo that russh used for the connection. There is no round-trip through the network on this path — `hostname` and `port` are purely config-sourced.
- **5 Whys — why does failure return `Ok(false)` rather than `Err(russh::Error)`?**
  1. Why `Ok(false)` not `Err`? The russh `Handler::check_server_key` signature is `Result<bool, Self::Error>` — returning `Ok(false)` causes russh to cleanly abort without propagating the application-level error type.
  2. Why would returning `Err` be worse? An `Err` from the handler is propagated up as a `russh::Error`, losing the `BridgeError` type and any structured context.
  3. Why do we still want the error logged? Because the caller (`establish_connection`) gets back `Err(russh::Error::HostKeyChanged)` or similar — not the `BridgeError`. The `tracing::error!` at L177 is the only place where the structured reason is captured.
  4. Why is the fingerprint in the error string but not a separate log field? Because `BridgeError::SshHostKeyMismatch` has `actual` and `expected` fields (as confirmed in the test at `client.rs` L1302-L1313), and `%e` formats those into the error message string.
  5. Why does this matter for audit? A machine-readable structured log field with the fingerprint would be more parseable for security alerting than embedding it in an error string.

---

### Cross-Function Dependencies

1. **Calls `known_hosts::verify_host_key`** (known_hosts.rs L117-L161) — see dedicated analysis below.
2. **Called by russh internals** — russh calls this during the key exchange phase. The exact russh call site is opaque (no source available here), but the contract is: called once per handshake, before user auth.
3. **`ClientHandler::new` is called at two sites**:
   - `establish_connection` (L349): `ClientHandler::new(target_host.clone(), port, host.host_key_verification)` — uses `host.hostname` as `target_host`.
   - `connect_via_jump` (L294): `ClientHandler::new(host.hostname.clone(), host.port, host.host_key_verification)` — uses `host.hostname` directly.
   Both call sites correctly pass the config-level hostname and port, not DNS-resolved values. This is consistent.
4. **Shared state**: None. `ClientHandler` shares no state with the pool or any other connection.

**Invariants**:
- `self.hostname` is always the config-declared hostname, never a DNS-resolved IP unless the operator put an IP in config.
- `self.verification_mode` never changes after construction.
- If `known_hosts::verify_host_key` returns `Err`, `check_server_key` always returns `Ok(false)` — never `Ok(true)` on error.

---

## 2. `known_hosts::verify_host_key`

**Source**: `known_hosts.rs` L117-L161

---

### Purpose

This function is the top-level policy dispatcher for host key verification. It enforces one of three modes (`Off`, `Strict`, `AcceptNew`) against the result of actually comparing the presented key with the local `known_hosts` file. It exists as a standalone function (rather than being inlined into `check_server_key`) to allow unit testing without a real SSH connection. It is the first line of MITM defense in the bridge.

---

### Inputs and Assumptions

1. **`hostname: &str`** — the configured hostname to look up in `known_hosts`. Same value as `ClientHandler.hostname`.
2. **`port: u16`** — port number. The `known_hosts` format includes port-qualified entries like `[hostname]:port`. Whether russh's `check_known_hosts` uses port in lookup depends on russh internals (opaque here). At port 22 (default SSH), most `known_hosts` files omit the port.
3. **`key: &PublicKey`** — the presented server public key. Untrusted.
4. **`mode: HostKeyVerification`** — copied `enum`, trusted.
5. **Assumption: `dirs::home_dir()` returns a valid path** on the running platform. On containerized or headless deployments, `$HOME` may be unset; in that case `check_known_hosts_permissions()` (L86) returns early without error, but the warning is silently skipped.
6. **Assumption: `check_known_hosts` from russh-keys uses the system `~/.ssh/known_hosts` path** and no other path. There is no path override mechanism visible in this code. This means the bridge's key verification shares the same `known_hosts` file as the user's interactive SSH client — a coupling point.
7. **Assumption: `add_key` (called in `AcceptNew` mode) is atomic from the filesystem's perspective**. In practice, `learn_known_hosts` likely uses `OpenOptions::append`, which is atomic on Linux for small writes but not on all filesystems or across reboots.
8. **Assumption: the TOCTOU race documented at L58-L62 is known and accepted**. The comment explicitly notes it.
9. **Assumption: `Off` mode's `warn!` at L127-L131 is delivered to a log sink that operators actually read**. If logging is discarded (no subscriber), the `Off` mode warning is silently dropped.

---

### Outputs and Effects

1. **Returns `Ok(())`** — verification passed; the caller (`check_server_key`) maps this to `Ok(true)`.
2. **Returns `Err(BridgeError::SshHostKeyMismatch {...})`** — key changed for a known host. Occurs in both `Strict` (L137-L140) and `AcceptNew` (L149-L152) modes. The error carries `host`, `expected` (line number reference), `actual` (fingerprint).
3. **Returns `Err(BridgeError::SshHostKeyUnknown {...})`** — host not in `known_hosts`. Only occurs in `Strict` mode (L142-L145). Carries `host` and `fingerprint`.
4. **Returns `Err(BridgeError::Config(...))`** — if `check_known_hosts` (or `learn_known_hosts`) returns an unexpected error (e.g., parse failure, I/O error). Via `verify` at L48.
5. **Side effect: writes to `~/.ssh/known_hosts`** — in `AcceptNew + Unknown` path (L155-L157). This is a permanent state change: once written, subsequent connections to the same host in `Strict` mode will verify correctly (or fail if a key change occurs after the write).
6. **Side effect: emits `warn!` log** — for `Off` mode (L127) and `AcceptNew + Unknown` (L155). The `Off` mode warning is the only in-code signal that verification is disabled; there is no hard error.

---

### Block-by-Block Analysis

**Block 1: `check_known_hosts_permissions()` call (L123)**

- **What**: Advisory check on `~/.ssh/known_hosts` permissions, emitting a `warn!` if the file is world- or group-writable beyond 0644.
- **Why here**: Called unconditionally before any mode dispatch, so every connection attempt checks permissions. This is correct ordering — verifying file integrity preconditions before trusting its content.
- **Assumptions**: The permission check reads metadata but never modifies the file. If `home_dir()` fails (L87), the function returns silently — the permission check is completely skipped.
- **Depends on**: `#[cfg(unix)]` compilation (L84). On non-Unix, the stub (L105-L107) is a no-op, meaning Windows builds receive no permission warning regardless of ACL state.
- **5 Hows — how does the permission logic work?**
  1. Gets home directory via `dirs::home_dir()` (L86).
  2. Constructs path `~/.ssh/known_hosts` (L89).
  3. Reads metadata via `std::fs::metadata` (L91).
  4. Extracts Unix mode bits masked to low 9 bits (L92: `metadata.mode() & 0o777`).
  5. Warns if `mode & 0o077 != 0 AND mode != 0o644` — this allows 0644 (readable by group/others) but warns on 0664, 0666, 0660, etc. The logic does NOT warn on 0644 explicitly. This is a documented intentional choice: 0644 is a commonly-used mode where `known_hosts` is readable by all, which is not a secret but could allow anyone to enumerate known hostnames.

**Block 2: `Off` mode branch (L126-L132)**

- **What**: Logs a security warning and returns `Ok(())` unconditionally.
- **Why here**: Early return avoids any file I/O when verification is disabled, which is the correct short-circuit.
- **Assumptions**: The operator has deliberately set `Off` mode. The warning is the only protection mechanism; there is no capability to require a human acknowledgment.
- **Depends on**: Logging infrastructure being active. If `tracing` subscriber is not initialized (e.g., during tests without `tracing_subscriber`), the warning is silently dropped.
- **First Principles**: Why allow `Off` at all? Air-gapped or ephemeral hosts (containers spun up fresh) may present keys that change per launch. In those environments, `Off` is the only workable mode. The design accepts this by making `Off` a named mode rather than, say, a numeric verification level.

**Block 3: `Strict` mode branch (L135-L145)**

- **What**: Calls `verify()` (which wraps `check_known_hosts`) and converts all non-`Match` results to errors.
- **Why here**: Strict is the default and the most conservative path.
- **Assumptions**: `verify` always returns `Ok(VerifyResult::*)` or `Err(BridgeError::Config(...))`. The `?` propagation at L135 means a config/I/O error in `verify` terminates with `Err` and causes `check_server_key` to return `Ok(false)`.
- **Depends on**: `verify` (known_hosts.rs L29-L52) correctly mapping `russh_keys::Error::KeyChanged { line }` to `VerifyResult::Mismatch`.
- **5 Whys — why is `Unknown` an error in Strict mode?**
  1. An unknown host means the bridge has no basis for trust.
  2. If accepted silently, any new server (legitimate or attacker-controlled) could be connected to.
  3. Operators should manually provision `known_hosts` or accept the key interactively before using Strict mode.
  4. This is standard SSH client behavior (OpenSSH strict equivalent is `StrictHostKeyChecking=yes`).
  5. Without this, an operator who provisions the bridge on a new host but forgets to pre-populate `known_hosts` would silently connect to whatever host answers.

**Block 4: `AcceptNew` mode branch (L147-L159)**

- **What**: Identical to Strict for `Match` and `Mismatch`, but calls `add_key` on `Unknown`.
- **Why here**: TOFU model — trust on first use.
- **Assumptions**: Between the `verify()` call at L147 and the `add_key()` call at L156, the filesystem state of `known_hosts` may have changed (TOCTOU). The comment at L58-L62 acknowledges this.
- **Depends on**: `add_key` succeeding. If it fails (permissions error, disk full), the error propagates as `Err(BridgeError::Config(...))` and causes the connection to be rejected — which is the safe fail-closed behavior.
- **5 Hows — how does the TOCTOU manifest?**
  1. Thread A calls `verify()`, gets `Unknown`.
  2. Thread B simultaneously connects to the same host (same `host_name`), calls `verify()`, also gets `Unknown`.
  3. Thread A calls `add_key()`, appends the key to `known_hosts`.
  4. Thread B also calls `add_key()`, appends a duplicate entry.
  5. Result: duplicate entries in `known_hosts` — not a security issue (russh accepts the first match), but a resource consumption issue and a potential source of confusion during manual review.

---

### Cross-Function Dependencies

1. **Calls `verify(hostname, port, key)`** — which calls `check_known_hosts` (russh-keys, external). `check_known_hosts` is a black-box: it reads `~/.ssh/known_hosts`, parses it, and compares by key algorithm and raw key bytes (not fingerprint hash).
2. **Calls `add_key(hostname, port, key)`** — which calls `learn_known_hosts` (russh-keys, external). This writes to `~/.ssh/known_hosts`.
3. **Calls `check_known_hosts_permissions()`** — internal advisory check.
4. **Called by `ClientHandler::check_server_key`** (client.rs L169-L174).
5. **Shared state**: `~/.ssh/known_hosts` file is shared between all concurrent connections and with the user's interactive SSH client. No in-memory lock protects this shared resource.

**Invariants**:
- `Off` mode always returns `Ok(())` — no file I/O.
- `Mismatch` is always an error in both `Strict` and `AcceptNew`.
- `Unknown` is an error only in `Strict`.
- `add_key` is called at most once per connection attempt in `AcceptNew + Unknown` path.

---

## 3. `establish_connection`

**Source**: `client.rs` L334-L446

---

### Purpose

This function translates a `HostConfig` into a live `Handle<ClientHandler>` — a russh client handle over which auth and channel operations can subsequently run. It handles two transport paths: direct TCP (`client::connect`) and SOCKS-proxied TCP (`client::connect_stream` over a SOCKS stream). The function is the first network interaction point in the connection lifecycle.

---

### Inputs and Assumptions

1. **`host_name: &str`** — the config alias, used only for error messages and tracing. Never sent over the network.
2. **`host: &HostConfig`** — carries `hostname`, `port`, `socks_proxy`, `host_key_verification`. Trusted (config-sourced).
3. **`limits: &LimitsConfig`** — carries `keepalive_interval_seconds` and `connection_timeout_seconds`. Trusted.
4. **Assumption: `host.hostname` is a valid DNS name or IP address**. There is no validation at this layer; DNS resolution happens inside `client::connect` or `Socks5Stream::connect`. If the hostname is malformed, the error is a russh `SshConnection` error.
5. **Assumption: `limits.keepalive_interval_seconds` is non-zero**. If zero, `Duration::from_secs(0)` is used for `inactivity_timeout` and `keepalive_interval`, which would trigger keepalive/timeout immediately. Config validation is assumed to catch this; not verified here.
6. **Assumption: the SOCKS proxy's `username`/`password` (if present) are trusted credentials from config**. `socks.password` is `Option<String>` — NOT wrapped in `Zeroizing` (confirmed at `config/types.rs` L420-L421). This differs from the SSH password/passphrase handling.
7. **Assumption: `client::connect` and `client::connect_stream` are non-blocking from a thread-safety perspective** — they are `async` functions, so they yield the executor while waiting.
8. **Assumption: the timeout wrapping at L366 and L429 correctly covers the full connection attempt**, including DNS resolution and TCP handshake.

---

### Outputs and Effects

1. **Returns `Ok(Handle<ClientHandler>)`** — a live russh session handle, post-key-exchange, pre-authentication. The `check_server_key` callback has already completed successfully at this point.
2. **Returns `Err(BridgeError::SshConnection {...})`** — on TCP connect failure, russh error, or timeout.
3. **Returns `Err(BridgeError::SocksProxy {...})`** — on SOCKS proxy connection failure or timeout.
4. **Side effect: network I/O** — TCP connection established to `target_host:port` (direct) or via SOCKS proxy. The russh key exchange (including the `check_server_key` callback) runs implicitly inside `client::connect`.

---

### Block-by-Block Analysis

**Block 1: `Config` construction (L339-L346)**

- **What**: Builds `russh::client::Config` with `inactivity_timeout`, `keepalive_interval`, and `keepalive_max = 3`. Uses `..Default::default()` for all other fields.
- **Why here**: Connection config must be set before the connect call.
- **Critical observation**: The `..Default::default()` path means that `Preferred` algorithms (kex, cipher, key, mac) and `Limits` (re-key thresholds) are taken from russh's upstream default. Per the russh audit baseline (russh.md line 12-16), the upstream default includes algorithm choices that the audit doc recommends restricting. The re-key `Limits` are also not set explicitly here, meaning long-lived sessions in the pool (up to 1 hour per `pool.rs` L58) accumulate data without scheduled re-keying.
- **Depends on**: `LimitsConfig.keepalive_interval_seconds` being a sensible value.
- **First Principles**: Why not set `Preferred` algorithms explicitly? The current code accepts whatever russh defaults to. This is a scope gap: the audit doc for russh explicitly lists which algorithms to prefer and which to exclude, but the bridge does not configure them.

**Block 2: `ClientHandler` construction (L349)**

- **What**: `ClientHandler::new(target_host.clone(), port, host.host_key_verification)`.
- **Why here**: Must be constructed before `client::connect` because it is moved into the connection.
- **Assumptions**: `target_host` is a clone of `host.hostname`. There is no normalization (lowercase, trim). If the YAML config contains trailing whitespace in `hostname`, it propagates into the `known_hosts` lookup.

**Block 3: SOCKS proxy path (L354-L413)**

- **What**: If `host.socks_proxy` is set, uses `tokio_socks` to establish a SOCKS4 or SOCKS5 stream, then calls `client::connect_stream` over it.
- **Why here**: SOCKS proxy is a transport-level concern that must be resolved before the SSH layer.
- **Key observation at L373-L383**: SOCKS5 username/password are passed as `&str` references to `Socks5Stream::connect_with_password`. The `socks.password` field is `Option<String>` (NOT `Zeroizing<String>` — confirmed in `config/types.rs` L419-L421). This means the SOCKS password lives in a plain `String` in the config struct's heap allocation and is never zeroed on drop.
- **Depends on**: The error mapping via `map_err` closures — these capture `host_name` by reference via the `|e|` closure, which is correct and efficient.

**Block 4: Direct connection path (L425-L445)**

- **What**: Formats `target_host:port` as a string, calls `client::connect` with a connection timeout wrapper.
- **Why here**: Simpler path when no proxy is configured.
- **Observation**: `sanitize_ssh_error` is NOT applied at L438-L443 where the russh error is formatted into `BridgeError::SshConnection.reason`. The `reason` field uses `e.to_string()` directly. This is different from the auth error paths (L508, L541, L576) which do call `sanitize_ssh_error`. Connection errors at this level are less likely to contain credential material, but could contain auth-method names if russh includes them in connection-phase errors.

---

### Cross-Function Dependencies

1. **Calls `client::connect`** (russh, black box) — synchronous from a caller perspective but internally async. Triggers the SSH handshake, which invokes `ClientHandler::check_server_key`.
2. **Calls `client::connect_stream`** (russh, black box) — same as above but over a provided `AsyncRead + AsyncWrite` stream.
3. **Calls `Socks5Stream::connect` / `Socks4Stream::connect`** (tokio-socks, black box) — SOCKS proxy negotiation. Adversarial analysis: if the SOCKS proxy returns unexpected data, `tokio_socks::Error` is mapped to `BridgeError::SocksProxy` with `e.to_string()` — the error string could contain proxy-returned data (untrusted). Truncation via `sanitize_ssh_error` is NOT applied here.
4. **Called by `connect` (L219)** and **`connect_via_jump` (L296)** (indirectly, via the direct path).
5. **Shared state**: None; produces a new `Handle` each time.

**Invariants**:
- If this function returns `Ok`, `check_server_key` has already returned `Ok(true)`.
- If `check_server_key` returned `Ok(false)`, russh propagates an error that causes this function to return `Err`.
- The returned `Handle` is authenticated only at the transport (SSH handshake) level, not the user-authentication level.

---

## 4. `authenticate` (dispatch) and `auth_with_key`

**Source**: `client.rs` L449-L528

---

### Purpose

`authenticate` is the auth-method dispatcher that reads `HostConfig.auth` and routes to one of three method-specific async functions. `auth_with_key` is the most security-sensitive of these, as it loads a private key file from disk (potentially passphrase-protected) and uses it to prove identity to the remote server. Together they form the second phase of the connection flow (after `establish_connection`), transmitting credentials over the already-verified encrypted session.

---

### Inputs and Assumptions

1. **`handle: Handle<ClientHandler>`** — the post-key-exchange russh handle. Trust level: the transport is encrypted and the server has been verified at this point (or explicitly trusted-on-first-use).
2. **`host_name: &str`** — used only for error messages and tracing.
3. **`host: &HostConfig`** — the whole host config, including the `auth` variant. Trusted.
4. **For `auth_with_key`: `path: &str`** — the key file path from config. May contain `~` (expanded via `shellexpand::tilde` at L487). No other validation at this layer.
5. **For `auth_with_key`: `passphrase: Option<&str>`** — a borrowed `&str` slice derived from `Zeroizing<String>` via `.as_ref().map(|s| s.as_str())` at `authenticate` L461. The `Zeroizing<String>` lives in `AuthConfig::Key { passphrase: Option<Zeroizing<String>> }` — it is zeroed when `AuthConfig` drops.
6. **Assumption: The passphrase is passed to `load_secret_key` as `Option<&str>`** (russh-keys canonical API, confirmed in russh-keys.md line 10-11). The passphrase is used inside `load_secret_key` for key decryption, then the borrowed slice is released. However, the decryption process within russh-keys may produce intermediate buffers not wrapped in `Zeroizing`. Those intermediate allocations are opaque.
7. **Assumption: `shellexpand::tilde` does not perform shell injection**. `shellexpand::tilde` replaces `~` with `HOME` env var; it does not execute shell commands. The expanded path is used only as a `Path`, not passed to a shell.
8. **Assumption: `load_secret_key` reads the file permissions internally**. There is no explicit file-permission check in this code (no `fs::metadata` call). Whether russh-keys enforces `0600` permissions on key files is unclear without reading its source (opaque).
9. **Assumption: `handle.best_supported_rsa_hash()` at L495-L500 communicates with the server** (it `await`s), meaning it sends/receives a server query. If the server is adversarial, it could return a weak hash algorithm. The result is passed directly to `PrivateKeyWithHashAlg::new` at L502, which determines the RSA signature scheme used.
10. **Assumption: The `auth_result.success()` check at L515** is the correct predicate for success. Partial auth (banner-only, or multi-factor partial success) would not satisfy `success()`, which is the conservative behavior.

---

### Outputs and Effects

1. **Returns `Ok(SshClient { handle, host_name, jump_client: None })`** — authenticated session ready for command execution.
2. **Returns `Err(BridgeError::SshAuth { user, host })`** — authentication failed. Note that the error message deliberately does not include the auth method name (L517-L520 for key auth; the error only contains `host_name`, not "key" or "publickey"). This is consistent with `sanitize_ssh_error` masking at L508.
3. **Returns `Err(BridgeError::SshKeyInvalid { path })`** — the key file could not be loaded. The path is included in the error (L492); the passphrase itself is NOT included.
4. **Side effect: key material is loaded into heap memory** via `load_secret_key` return value (`key_pair` at L490). `key_pair` has type `russh::keys::PrivateKeyWithHashAlg` (actually first `PrivateKey`, then wrapped at L502). Rust will drop this when it goes out of scope at the end of `auth_with_key`, but without `ZeroizeOnDrop` on the russh type itself (opaque), the private key bytes may remain in heap memory until overwritten by the allocator.
5. **Side effect: private key is sent over the encrypted SSH channel** via `handle.authenticate_publickey` at L504. The actual private key bytes are not transmitted (public-key auth sends a signature, not the key), but the signing operation uses the in-memory private key.

---

### Block-by-Block Analysis

**Block 1: `authenticate` dispatch (L454-L476)**

- **What**: Pattern-matches on `&host.auth` (borrowed to avoid consuming the `Zeroizing` wrapper), then calls the appropriate `auth_with_*` function.
- **Why here**: Dispatch must happen before the handle is moved into any specific auth function.
- **Critical observation at L461**: `passphrase.as_ref().map(|s| s.as_str())` — this borrows the `Zeroizing<String>` as `&str`. The `Zeroizing<String>` backing buffer remains owned by `host.auth`. When `auth_with_key` runs, the passphrase is a temporary `&str` pointing into the `Zeroizing` allocation. The allocation is zeroed when `AuthConfig` drops (end of the caller's scope), not at the end of `auth_with_key`. This is correct: the `Zeroizing` wrapper is retained by the config owner for as long as the connection attempt is alive.
- **Observation: WinRM variants at L469-L475** — these return `Err` without attempting SSH auth. This is correct protocol-separation guard. The `Ntlm { password: Zeroizing<String> }` field is never accessed from this path.

**Block 2: `shellexpand::tilde` (L487-L488)**

- **What**: Expands `~` in the key path.
- **Why here**: Before the `Path::new` and `load_secret_key` call.
- **Assumptions**: `HOME` env var is set. If unset, `shellexpand::tilde` behavior is implementation-defined (it may return the literal `~` or fail). No error handling for this case.
- **First Principles**: Why not resolve the path through the config validation layer? The path is validated for existence during config load (per `.claude/rules/config.md`: "SSH key files must exist AND have 0600 permissions on Unix"), but that validation uses the path as-is. The `~` expansion here must produce the same path the validator saw, assuming the same `HOME` env at config load time and connection time.

**Block 3: `load_secret_key` call (L490-L493)**

- **What**: Reads and decrypts the private key from disk. Returns a `PrivateKey`.
- **Why here**: Must occur before `authenticate_publickey` which needs the private key.
- **Depends on**: Passphrase being correct (decryption failure returns error), key file existing and being readable (I/O failure returns error). Both are mapped to `BridgeError::SshKeyInvalid` with the sanitized error message.
- **Observation**: `sanitize_ssh_error(&e)` is applied at L492. The sanitized error is placed into `BridgeError::SshKeyInvalid { path: format!("{path}: {...}") }`. The raw path (e.g., `/home/user/.ssh/id_rsa`) is included in the error message — this is acceptable for debug purposes since the path is not a secret, but the error is included in the error chain propagated to callers, and potentially logged.
- **5 Hows — how does the passphrase reach `load_secret_key`?**
  1. `HostConfig` is deserialized from YAML; `passphrase` field is `Option<Zeroizing<String>>`.
  2. `Zeroizing<String>` wraps the plain string in a type that implements `Drop` with zeroing semantics.
  3. In `authenticate`, `passphrase.as_ref().map(|s| s.as_str())` produces `Option<&str>`.
  4. This `Option<&str>` is passed as-is to `auth_with_key` as `passphrase: Option<&str>`.
  5. `load_secret_key(key_path, passphrase)` receives the `&str` directly. Inside russh-keys, the passphrase is used to decrypt the key material; intermediate decryption buffers are opaque.

**Block 4: RSA hash algorithm negotiation (L495-L502)**

- **What**: Calls `handle.best_supported_rsa_hash()` to negotiate the RSA signature hash algorithm with the server.
- **Why here**: Must occur before `authenticate_publickey` for RSA keys; for Ed25519/ECDSA it is a no-op (returns `None`).
- **Assumptions**: The server's response is trusted (we have already verified the server's identity via `check_server_key`). The `ok().flatten().flatten()` chain at L499-L500 silently discards errors and uses `None` (no explicit RSA hash) as a fallback. This means if the negotiation fails, we fall back to an unspecified default.
- **Observation**: `hash_alg: Option<HashAlg>` is then passed to `PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg)`. If `hash_alg` is `None` and the key is RSA, the behavior depends on russh's internal default for `PrivateKeyWithHashAlg` with `None` hash. This is opaque without russh source, but the concern is whether `None` triggers SHA-1 (deprecated) or SHA-256.

**Block 5: `authenticate_publickey` (L504-L513)**

- **What**: Sends the public-key auth request to the server and awaits the result.
- **Why here**: The final network step of key-based authentication.
- **Observations**: The error from russh at L507-L512 is passed through `sanitize_ssh_error` (masking auth method names), and the resulting `BridgeError::SshAuth` error deliberately uses `"authentication failed"` as the reason — stripping the method name. This is consistent with the anti-reconnaissance design.

---

### Cross-Function Dependencies

1. **Calls `load_secret_key`** (russh-keys, black box) — key file path and passphrase are inputs; private key material is output. No adversarial concern on this call since path and passphrase are config-sourced (trusted). The only risk is side-channel: timing of the return could indicate whether decryption succeeded without the network round-trip.
2. **Calls `handle.authenticate_publickey`** (russh, black box) — sends the signed authentication request over the established encrypted channel. The server (already key-verified) receives this.
3. **Called by `authenticate` (L456-L463)** which is called by `connect` (L220) and `authenticate_with_jump` (L325).
4. **Shared state**: The key material (`key_pair`) lives on the heap for the duration of `auth_with_key`. The `Zeroizing<String>` passphrase is retained by `AuthConfig` for the duration of the entire connection invocation.

**Invariants**:
- The passphrase `&str` slice is valid only as long as `AuthConfig` is alive (guaranteed by borrow checker — the reference through `authenticate`'s match arm borrows `host.auth`).
- `load_secret_key` is called before any network auth exchange.
- `key_pair` is dropped at the end of `auth_with_key` regardless of success or failure.
- If `auth_result.success()` is false, `Err` is returned — the `handle` is consumed by `authenticate_publickey` (moved into it), so there is no re-use of a failed handle.

---

## 5. `auth_with_password`

**Source**: `client.rs` L531-L561

---

### Purpose

Performs SSH password authentication over an already-established encrypted session. The password is transmitted to the server in plaintext at the SSH protocol level (encrypted by the SSH transport layer, but not wrapped in a public-key challenge), making this method the weakest SSH auth method. It exists to support legacy hosts that do not accept key-based or agent-based auth.

---

### Inputs and Assumptions

1. **`handle: Handle<ClientHandler>`** — authenticated transport (post-key-exchange).
2. **`host_name: &str`** — for error messages only.
3. **`host: &HostConfig`** — for `user` field.
4. **`password: &str`** — the plaintext password derived from `AuthConfig::Password { password: Zeroizing<String> }`. At the call site in `authenticate` (L465-L467), `password` is passed as `password` (the `Zeroizing<String>` is deref'd to `&str` via the implicit `Deref<Target=String>` chain).

**Correction**: Looking at L465-L466: `AuthConfig::Password { password } => { Self::auth_with_password(handle, host_name, host, password).await }`. The `password` here is a `&Zeroizing<String>` (pattern-matched from `&host.auth`). The function signature at L535 takes `password: &str`. `Zeroizing<String>` implements `Deref<Target=String>` and `String` implements `Deref<Target=str>`, so the coercion to `&str` happens implicitly at the call site. The `Zeroizing<String>` is borrowed, not consumed.

5. **Assumption: the `password: &str` slice passed to `handle.authenticate_password` is transmitted verbatim over the SSH channel** (encrypted at the transport level). There is no hashing or KDF applied by this code.
6. **Assumption: `Zeroizing<String>` is zeroed when `AuthConfig` drops**, not when `auth_with_password` returns. The `&str` reference is just a borrow; the backing buffer is zeroed by the `Zeroizing` destructor later.
7. **Assumption: error messages at L541-L545 do not include the password value**. `sanitize_ssh_error` is called on the russh error, which would mask auth method names but not passwords. The password is not placed in any error struct field here.
8. **Assumption: `handle.authenticate_password` (russh) does not buffer the password beyond the SSH message lifetime**. This is opaque.

---

### Outputs and Effects

1. **Returns `Ok(SshClient)`** on success.
2. **Returns `Err(BridgeError::SshAuth)`** on failure. The reason string is `"{host_name}: authentication failed"` (not method-specific).
3. **Side effect**: password is transmitted over the encrypted SSH channel.

---

### Invariants

- The password `&str` is borrowed from a `Zeroizing<String>` — it is never copied into a plain `String` within this function.
- On success or failure, the function returns without retaining any reference to the password.
- The `handle` is consumed by `authenticate_password` (moved); a failed authentication cannot be retried on the same handle.

---

## 6. `auth_with_agent` (Unix variant)

**Source**: `client.rs` L564-L652

---

### Purpose

Implements SSH agent authentication by connecting to the local SSH agent (via `SSH_AUTH_SOCK` Unix socket), enumerating all identities held by the agent, and attempting each one against the remote server. This is the most operationally convenient auth method but involves an external process (`ssh-agent`) as a trust boundary.

---

### Inputs and Assumptions

1. **`handle: Handle<ClientHandler>`** — post-key-exchange russh handle.
2. **`host_name: &str`**, **`host: &HostConfig`** — for error messages and `user` field.
3. **Implicit input: `SSH_AUTH_SOCK` environment variable** — the Unix socket path for the SSH agent. If unset, `AgentClient::connect_env()` fails.
4. **Assumption: the SSH agent process is trusted**. The agent exposes identities and performs signing operations. A compromised agent could return malicious public keys (pointing to identity spoofing rather than credential exposure, since the private key material does not leave the agent).
5. **Assumption: `request_identities()` at L583 returns an exhaustive list of available keys**. If the agent has many keys (common in developer environments), all are tried sequentially.
6. **Assumption: no `KeyLifetime` constraint is set** when using agent identities. Per the russh-keys audit baseline (russh-keys.md line 13-14), `add_identity` supports `Constraint::KeyLifetime`. However, this code uses already-loaded agent identities, not adding new ones — so lifetime constraints would have to be set by whoever loaded the key into the agent, not by this code.
7. **Assumption: `best_supported_rsa_hash()` is called once per identity inside the loop (L604-L609)**. For N identities, this makes N round-trips to the server. For large identity sets, this multiplies network latency.
8. **Assumption: `last_error` at L602 accumulates only the most recent error**, discarding earlier identity errors. If identity 1 fails with a meaningful error and identity 2 fails with a generic error, only identity 2's error is reported.

---

### Outputs and Effects

1. **Returns `Ok(SshClient)`** — on first identity accepted by the server.
2. **Returns `Err(BridgeError::SshAuth)`** — if no identity is accepted. The error includes `identities.len()` and the last error string. The last error string for `Ok(_)` (key rejected by server) is the literal `"Key rejected by server"` (L628), which does not contain auth method names and does not need sanitization. For `Err(e)` paths, `e.to_string()` is used without `sanitize_ssh_error` at L631.
3. **Side effect**: for each identity attempted, a cryptographic signature is requested from the SSH agent and transmitted to the remote server.

---

### Cross-Function Dependencies

1. **Calls `AgentClient::connect_env()`** (russh-keys, black box) — reads `SSH_AUTH_SOCK`. Adversarial analysis: if `SSH_AUTH_SOCK` points to a socket controlled by an attacker (e.g., in a compromised container), the attacker could return arbitrary identities and perform arbitrary signing on behalf of the client.
2. **Calls `handle.authenticate_publickey_with`** (russh, black box) — uses the agent as a signer.
3. **Called by `authenticate` (L468)** for `AuthConfig::Agent`.

**Invariants**:
- If `identities.is_empty()`, returns `Err` immediately (L594-L600) — no attempt is made.
- The loop exhausts all identities before returning `Err`.
- The private key material never leaves the SSH agent process; only the public key and a signature are transmitted.

---

## 7. `connect_via_jump` and RAII jump_client

**Source**: `client.rs` L247-L315

---

### Purpose

This function establishes a two-hop SSH connection: first connecting to a jump/bastion host, then opening a `direct-tcpip` channel through it, and finally establishing a second SSH session over that tunnel. The RAII pattern for `jump_client` is the structural mechanism that keeps the tunnel alive: if `jump_client` were dropped, the first SSH session would close, killing the `direct-tcpip` channel and thus destroying the transport for the inner SSH session.

---

### Inputs and Assumptions

1. **`host_name: &str`** — alias for the final target host.
2. **`host: &HostConfig`** — config for the target. The `host.hostname` and `host.port` are used as the `direct-tcpip` destination at L274.
3. **`jump_host_name: &str`** and **`jump_host: &HostConfig`** — config for the jump host.
4. **`limits: &LimitsConfig`** — shared across both connections.
5. **Assumption: `host.hostname` and `host.port` at L274 are the network-visible hostname/port of the target as seen from the jump host**. If the target is only reachable by a private address from the jump host, and the config contains the external/public address, the tunnel will fail. This is a configuration correctness assumption, not a code defect.
6. **Assumption: `channel_open_direct_tcpip` at L272-L278 uses the config-sourced hostname/port**, not user-supplied values. There is no injection risk here because these come from the validated config.
7. **Assumption: the `ChannelStream` wrapper correctly implements `AsyncRead + AsyncWrite` and handles partial reads/buffering**. Analysis of `ChannelStream` (L39-L134) shows it buffers unconsumed data from `ChannelMsg::Data`. The `AsyncWrite::poll_write` (L103-L116) is not fully buffered — it writes directly to the channel and returns the full `buf.len()` on success. This is safe if the channel can always accept the full write, which SSH flow-control mechanisms should ensure.
8. **Assumption: the jump host's key is also verified**. The `connect` call at L262 uses the full connection pipeline including `check_server_key`. The jump host has its own `HostKeyVerification` setting (`jump_host.host_key_verification`), and a separate `ClientHandler` is constructed for it.

---

### Outputs and Effects

1. **Returns `Ok(SshClient { handle, host_name, jump_client: Some(Box<Self>) })`** — the outer `SshClient` wraps the inner `russh::Handle` for the target connection, while the `jump_client` field carries the jump host's `SshClient`.
2. **Returns `Err`** at any of the five failure points (L262, L272-L279, L296-L301, L306).
3. **Side effect**: two SSH sessions are established; one `direct-tcpip` channel is opened on the jump host session.
4. **RAII semantic**: `SshClient.jump_client` has `#[allow(dead_code, clippy::struct_field_names)]` at L190. The `jump_client` field is never read after being set at L328. Its sole purpose is lifetime management: it keeps the jump-host `SshClient` alive. When the outer `SshClient` drops, `jump_client` drops (executing its `close()` or simply dropping the russh handle), which closes the jump-host connection and the `direct-tcpip` channel.

---

### Block-by-Block Analysis

**Block 1: Jump host connection (L262)**

- **What**: `Self::connect(jump_host_name, jump_host, limits).await?` — full connection including key verification and authentication.
- **Why here**: Must be established before the tunnel can be opened.
- **Depends on**: `jump_host` having valid auth config and a reachable hostname.
- **5 Whys — why not reuse a pooled connection for the jump host?**
  1. `connect_via_jump` receives a raw `HostConfig`, not a pool handle.
  2. The tunnel must keep the connection open for the lifetime of the target connection.
  3. A pooled connection could be evicted or expire, killing the tunnel.
  4. A dedicated owned connection (not pooled) avoids this lifecycle coupling.
  5. The pool at `pool.rs` L157 calls `connect_via_jump` — the jump host connection is not separately pooled.

**Block 2: `channel_open_direct_tcpip` (L272-L279)**

- **What**: Opens a `direct-tcpip` channel from the jump host to the target.
- **Why here**: Required before wrapping the channel as a stream.
- **Observation**: The `originator_address` is hardcoded as `"127.0.0.1"` with port `0` (L274). This is the "where the tunnel is coming from" hint, which SSH servers may log for audit. Hardcoding `127.0.0.1:0` means the jump host's SSH server will record the tunnel as originating from localhost — which is technically inaccurate and could mislead audit logs on the jump host.

**Block 3: Inner session `Config` construction (L285-L291)**

- **What**: Builds a second `russh::client::Config` for the inner session.
- **Why here**: The inner session has its own transport config.
- **Observation**: Same `..Default::default()` pattern as `establish_connection` — same implications for algorithm selection and re-key limits.

**Block 4: `authenticate_with_jump` (L306)**

- **What**: Calls `Self::authenticate(handle, host_name, host).await` then attaches `jump_client`.
- **Why here**: Authentication runs after transport establishment; the jump client is attached after successful auth to ensure we don't drop the jump connection if auth fails.
- **Depends on**: `authenticate` completing successfully. If it fails, `jump_client` drops at the end of `connect_via_jump` on the `?` propagation at L306, closing the jump-host connection correctly.

---

### Cross-Function Dependencies

1. **Calls `Self::connect`** — recursive, but for a different host. No infinite recursion risk because jump hosts do not themselves have jump host configs (not enforced by type, but circular jump configs would cause a connection failure rather than stack overflow due to the network timeout).
2. **Calls `jump_client.handle.channel_open_direct_tcpip`** — russh black box. Adversarial analysis: if the jump host is compromised, it could respond to the `direct-tcpip` request with data that is NOT from the actual target, allowing MITM on the inner SSH session. However, the inner session runs its own `check_server_key` using `host.host_key_verification`, so the target's key is still verified within the tunnel.
3. **Calls `client::connect_stream`** (russh, black box) — over the `ChannelStream`.
4. **Calls `authenticate_with_jump`** — internal, L318-L331.

**Invariants**:
- `jump_client` is always `Some(_)` on a successful return from `connect_via_jump`.
- `jump_client` is `None` on a successful return from `connect` (non-jump path).
- The inner SSH session's `check_server_key` runs with `host.host_key_verification` (target's config), not the jump host's mode. A target configured with `Off` will bypass verification even when tunneled.
- If `authenticate` fails after the jump connection is established, `jump_client` is dropped via `authenticate_with_jump` returning `Err`, which propagates up and causes the `jump_client` local variable to drop at the end of `connect_via_jump`.

---

## 8. Pool Interaction and Credential Lifetime in `ConnectionPool`

**Source**: `pool.rs`

---

### Purpose (credential residency angle)

The pool stores `SshClient` instances (which contain `Handle<ClientHandler>` wrapping the russh session) and re-uses them across multiple tool invocations. The security-relevant question is: **how long does credential material reside in memory, and what structures extend that lifetime?**

---

### Key Observations

**Auth credentials vs. session handles**: Once `auth_with_key` or `auth_with_password` returns, the credential material (`Zeroizing<String>` passphrase, private key bytes) is no longer held by the `SshClient`. The `SshClient` only holds a `Handle<ClientHandler>`, which is a post-authentication session handle. The private key material loaded by `load_secret_key` at client.rs L490 lives only for the duration of `auth_with_key` execution. After `PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg)` at L502, the `key_pair` is inside an `Arc`. That `Arc` is then moved into `handle.authenticate_publickey(...)` at L504 (which is `async` and takes ownership). After `authenticate_publickey` completes, the `Arc<PrivateKey>` is held by whatever russh internals retain it. This is opaque — unclear whether russh retains the private key for re-use in subsequent auth operations, or drops it after the initial auth.

**Passphrase zeroing**: `AuthConfig::Key { passphrase: Option<Zeroizing<String>> }` is part of `HostConfig`. The `HostConfig` is typically stored in the application config (`Arc<AppConfig>` or similar) and lives for the entire process lifetime. The `Zeroizing<String>` guarantees the passphrase is zeroed when that config struct drops — which under normal operation is at process exit. Between process start and exit, the passphrase is in memory in the `Zeroizing<String>`.

**Pool connection lifetime**: Per `pool.rs` L49-L59, the default `max_idle_seconds = 300` and `max_age_seconds = 3600`. A session in the pool lives up to 1 hour. During this time, the russh `Handle<ClientHandler>` (and whatever state russh retains, including any session key material) is live in memory.

**`SshClient` has no Drop that sends SSH DISCONNECT**: `close()` is a method that must be explicitly called (L880-L900). The pool infrastructure calls `close()` in the cleanup/eviction paths (`try_get_existing` L209, `cleanup` L280, `close_all` L360). The `PooledConnectionGuard::Drop` (L415-L437) returns the connection to the pool rather than closing it. A connection is closed only when it is evicted from the pool or when `close_all` is called. If the process exits without calling `close_all` (e.g., panic or kill signal), `SshClient` is dropped without sending `SSH_MSG_DISCONNECT`, leaving the server with a dangling session.

---

### Pool-Keyed Connection Invariant

Pool keys are host aliases (config names), not `(hostname, port)` pairs. The pool comment at `pool.rs` L174-L181 documents this: "Connections are keyed by host alias (`host_name`), which maps 1:1 to a `HostConfig` with a specific hostname/port." The security implication: if two hosts have the same alias (impossible via valid config, but worth noting), they would share pool slots. Config validation is assumed to prevent duplicate aliases.

---

## Summary of Key Invariants

| Invariant | Location | Condition |
|---|---|---|
| `check_server_key` never returns `Ok(true)` on verification failure | client.rs L165-L181 | The `Err(e)` branch maps to `Ok(false)`, never `Ok(true)` |
| `Off` mode always warns before accepting | known_hosts.rs L126-L132 | `warn!` is unconditional in `Off` branch |
| `Mismatch` is always rejected in all non-Off modes | known_hosts.rs L137-L140, L149-L152 | Both `Strict` and `AcceptNew` return `Err` on mismatch |
| Passphrase `&str` borrows from `Zeroizing<String>` | client.rs L461, config/types.rs L453 | Borrow checker enforces lifetime; zeroing deferred to config drop |
| `jump_client` owns the tunnel lifetime | client.rs L188-L191, L328 | Never read; presence = alive |
| Config algorithms not restricted | client.rs L339-L346, L285-L291 | `..Default::default()` used; no `Preferred` or `Limits` override |

---

## Open Questions

1. **Algorithm negotiation**: The `Config { ..Default::default() }` at client.rs L339 and L285 leaves `Preferred` algorithms and `Limits` (re-key thresholds) at russh defaults. What are russh 0.60's actual defaults? Are any weak algorithms (e.g., `diffie-hellman-group1-sha1`, `hmac-sha1`) included in the default `Preferred` set? The russh audit doc (russh.md line 11-16) recommends explicit restriction but does not state what russh's current defaults include.

2. **Private key `ZeroizeOnDrop`**: After `load_secret_key` returns a `PrivateKey` and it is placed in `Arc::new(key_pair)` (L502), does the russh/russh-keys `PrivateKey` type implement `ZeroizeOnDrop`? If not, the private key bytes persist in heap memory for an indeterminate duration after `Arc` drops. The russh-keys audit doc (russh-keys.md line 10-11) notes that `load_secret_key`'s intermediate buffers are opaque.

3. **`best_supported_rsa_hash()` fallback**: When this returns `None` (due to `.ok().flatten().flatten()` at L499-L500), `PrivateKeyWithHashAlg::new(Arc::new(key_pair), None)` is called. For an RSA key with `hash_alg = None`, does russh default to SHA-256 or SHA-1? The behavior is opaque without russh 0.60 source inspection.

4. **`check_known_hosts` port handling**: Does russh-keys' `check_known_hosts(hostname, port, key)` at known_hosts.rs L30 check port-qualified entries (format `[hostname]:port`) or ignore the port for standard port 22? If port is ignored at port 22, a host key stored for `host:22` and one for `host:2222` would both match `check_known_hosts("host", 22, key)` if the same key is presented on both ports.

5. **`sanitize_ssh_error` coverage gap on connection errors**: `sanitize_ssh_error` is applied at auth error sites (L508, L541, L576) but NOT at connection-phase error sites (L418-L424, L438-L444). If russh includes auth-method names in connection-phase error messages (e.g., "no matching host key: publickey"), those would not be masked. Needs verification against russh 0.60 error message formats.

6. **SOCKS proxy credential zeroing**: `SocksProxyConfig.password` is `Option<String>` at config/types.rs L420-L421 — NOT `Zeroizing<String>`. This SOCKS password is never zeroed on drop. The significance depends on whether operators deploy SOCKS proxies requiring password auth in production.

7. **`SSH_AUTH_SOCK` trust boundary in containerized deployments**: If the bridge runs in a container with `SSH_AUTH_SOCK` mounted from the host, is the agent socket protected by file permissions from other container processes? This is an environment/deployment question, not a code question, but worth documenting.

8. **`originator_address` hardcoded as `127.0.0.1:0`** in `channel_open_direct_tcpip` (client.rs L274): jump-host audit logs will record all tunnels as originating from localhost. Operators who rely on jump-host SSH logs for attribution will see misleading source addresses. Is this intentional (privacy-preserving) or an oversight?

9. **`AgentClient::connect_env()` error path**: at client.rs L572-L580, if the agent is not running, the error message is sanitized with `sanitize_ssh_error`. However, agent errors at this stage (before any auth attempt) likely do not contain auth method strings — the sanitization is conservative but correct. The question is whether the agent connection path leaks the socket path in the error string.

10. **Re-key limit on long-lived pool connections**: With `max_age_seconds = 3600` (1 hour) and no explicit russh `Limits` set, how much data can a single session accumulate before russh initiates a re-key? If russh's default `Limits` are infinite (or very large), a long-lived session that transfers large files (SFTP) could accumulate data beyond safe cryptographic bounds for the negotiated cipher.

---

## `src/domain/runbook.rs` — Per-Function Micro-Analysis

**File:** `/home/muchini/mcp-ssh-bridge/src/domain/runbook.rs` (429 LOC)
**Entry-point handlers:** `/home/muchini/mcp-ssh-bridge/src/mcp/tool_handlers/ssh_runbook_validate.rs`, `ssh_runbook_execute.rs`
**Sample runbooks:** `/home/muchini/mcp-ssh-bridge/config/runbooks/disk_full.yaml`, `service_restart.yaml`
**Upstream parser guidance:** `/home/muchini/mcp-ssh-bridge/audit/2026-05-09/surface/context7/serde-saphyr.md`

---

## Data-Flow Origin Map (pre-function)

Before function-level analysis, the YAML string origin must be established because every `serde_saphyr::from_str` call inherits its trust level from the source.

There are **three distinct ingestion paths** in the codebase:

| Call site | YAML origin | Caller trust level |
|---|---|---|
| L160 `load_runbook` | `std::fs::read_to_string(path)` — filesystem, path chosen by MCP client or startup | Attacker-controlled if path is user-supplied |
| L188 `builtin_runbooks` | `include_str!(...)` — compile-time file embedding | Fully trusted (build-time constant) |
| `ssh_runbook_validate.rs` L75 | `args.yaml_content` — raw string from MCP request body | Fully attacker-controlled (any connected MCP client) |

The validate handler at L75 (`ssh_runbook_validate.rs`) is the most direct external injection surface: it calls `serde_saphyr::from_str::<Runbook>(yaml)` on a string it extracted from the JSON-RPC request body with zero prior sanitization. The `load_runbook` path at L160 is attacker-controlled whenever the filesystem path can be influenced (e.g., a future tool that accepts a user-supplied path). The `include_str!` path at L188 is compile-time constant and not externally controllable.

---

## Function 1: `validate_runbook` (L86–L105)

### 1. Purpose

`validate_runbook` is the sole semantic gate between a deserialized `Runbook` struct and downstream use. It enforces that every runbook has a non-empty `name`, at least one `step`, and that every step either carries a `command` or a `condition` (preventing structurally degenerate steps). It does not inspect field *values*, only presence.

### 2. Inputs and Assumptions

| Parameter | Type | Trust level |
|---|---|---|
| `runbook` | `&Runbook` | Caller-dependent; deserialized from YAML of varying trust |

**Implicit inputs:**
- None. The function is pure — it reads only from the struct reference.

**Preconditions and assumptions:**
1. The caller has already completed `serde` deserialization; all fields are structurally present but their string *contents* are unvalidated.
2. `runbook.name` is a `String` — serde guarantees a valid UTF-8 value, but does not bound its length.
3. `runbook.steps` is a `Vec<RunbookStep>` whose elements were each independently deserialized; serde allows an unbounded number of steps.
4. `step.command` and `step.condition` are both `Option<String>`. This function's contract considers a step valid if *either* is `Some(_)` — the string content itself is not examined.
5. The `name`, `command`, and `condition` strings may contain shell metacharacters, newlines, YAML anchor expansions, or other payload content. This function does not reject them.
6. A step with `command: Some("")` and `condition: None` satisfies L97 (`step.command.is_none()` is false) and passes validation despite the command being an empty string.
7. There is no upper bound on `runbook.steps.len()` enforced here; a malformed YAML with 10,000 steps would yield a `Vec` of 10,000 `RunbookStep` values, all of which would iterate at L93.

### 3. Outputs and Effects

- **Returns** `Ok(())` when all invariants hold; `Err(String)` with a human-readable description otherwise.
- **No state writes.** The function is pure.
- **No events emitted.**
- **Postcondition:** On `Ok(())`, the caller can assume `runbook.name` is non-empty, `runbook.steps` is non-empty, and every step has at least one of `command` or `condition` as `Some(_)`. No postcondition is established on the *content* of these strings.

### 4. Block-by-Block Analysis

**Block A — Name check (L87–L89)**
- **What:** Rejects a runbook with an empty `name`.
- **Why here:** The name is the runbook's identity; downstream lookup (L82 `ssh_runbook_validate.rs`, L99–L101 `ssh_runbook_execute.rs`) matches runbooks by `r.name == *name`. An empty name would break lookup semantics without this guard.
- **Assumptions:** `is_empty()` on a `String` checks for zero bytes; a whitespace-only name (e.g., `"   "`) is non-empty and passes. Unclear whether whitespace-only names are semantically acceptable; need to inspect downstream lookup and display paths.
- **Depends on:** serde having populated `runbook.name` from the YAML `name:` key.
- **First Principles:** The name field serves as a primary key in the registry. A registry keyed by empty string would admit at most one runbook without collision, but the logic at L82 (`find(|r| r.name == *name)`) would succeed on the first empty-named runbook regardless of which was actually requested. Restricting to non-empty names is the minimal key-integrity invariant.

**Block B — Step count check (L90–L92)**
- **What:** Rejects a runbook with zero steps.
- **Why here:** A zero-step runbook is operationally meaningless and would produce an empty execution plan, confusing the caller.
- **Assumptions:** An empty `Vec` (zero length) is caught; serde's `#[serde(default)]` on `steps` is not present (the field is mandatory in the schema), so an absent `steps:` key causes a serde error before this function is reached. However, an explicit `steps: []` in YAML deserializes to an empty `Vec` and reaches this check.
- **Depends on:** The serde schema having required `steps`.
- **5 Whys — Why does this check exist here and not in serde?** (1) Serde handles structural well-formedness; (2) semantic constraints such as "at least one step" are business rules; (3) business rules belong in domain validation; (4) `validate_runbook` is the domain validation entry point; (5) therefore the check is here. This chain is clean.

**Block C — Per-step structural check (L93–L103)**
- **What:** Iterates all steps, rejects any step without a name and any step with neither `command` nor `condition`.
- **Why here:** After establishing the runbook is non-trivially populated, each step must satisfy the minimum structural requirement to be interpretable.
- **Assumptions that must hold:**
  1. The iteration order matches the YAML declaration order (Rust `Vec` maintains insertion order; serde preserves it).
  2. A step with `command: Some("")` is not caught here — the check is `is_none()`, not `is_some_and(|s| !s.is_empty())`.
  3. A step with `condition: Some("")` and `command: None` also passes — the condition string may be empty.
  4. `step.name.is_empty()` at L94 mirrors the same gap: a whitespace-only step name passes.
- **Depends on:** Block B having already confirmed `steps` is non-empty.
- **5 Hows — How could a step with a structurally empty command reach SSH execution?** (1) YAML provides `command: ""` (empty string); (2) serde deserializes it to `Some("")`; (3) `validate_runbook` sees `is_none()` as false, passes; (4) `apply_template("", vars)` returns `""`; (5) the execution plan emits `Command: ` (blank) and Claude would invoke `ssh_exec` with an empty command string. Whether `ssh_exec` would accept or reject an empty command is unclear; need to inspect `src/domain/use_cases/` for the `ssh_exec` builder.

### 5. Cross-Function Dependencies

- **Called by:** `load_runbook` (L163), `SshRunbookValidateHandler::execute` (L91 of validate handler), and transitively by `load_runbooks_from_dir` via `load_runbook`.
- **Calls:** None.
- **Shared state:** None.
- **Invariant couplings:**
  1. The invariant established by L87 (non-empty name) is required for the equality-based lookup at `ssh_runbook_execute.rs` L101.
  2. The invariant at L90 (non-empty steps) is required for `format_execution_plan` to emit at least one step block.
  3. The invariant at L97 (command or condition) is the sole semantic guard; it does not prevent command injection in the string values themselves.

---

## Function 2: `apply_template` (L111–L123)

### 1. Purpose

`apply_template` performs string substitution of `{{ key }}` and `{{key}}` tokens within a template string using a caller-supplied variable map. It is the only point in the codebase where runtime parameter values are merged into shell command strings before those commands are presented to the operator.

### 2. Inputs and Assumptions

| Parameter | Type | Trust level |
|---|---|---|
| `template` | `&str` | Trusted structure (from YAML); content may embed attacker values if params were user-supplied |
| `vars` | `&HashMap<String, String, S>` | Values are caller-supplied; keys originate from the runbook params schema |

**Preconditions and assumptions:**
1. `vars` contains string values that have undergone no sanitization for shell metacharacters before this call.
2. The function is `#[must_use]` — the caller must consume the returned `String`. Discarding the result is a compile-time warning.
3. There is no recursive substitution guard. If a variable's *value* contains a `{{ another_key }}` pattern, and `another_key` appears later in the iteration order of `vars`, the result depends on HashMap iteration order. However, the current implementation iterates over `vars` and performs all replacements in a single pass over `result`; a value injected in iteration `i` *can* be matched by a subsequent iteration `i+1` if the substituted value contains `{{ key_i+1 }}`. This is an implicit recursive substitution channel.
4. Iteration order over `HashMap` in Rust is non-deterministic across runs (it depends on `RandomState` seeding). This means the outcome of a template containing two variables that both appear in each other's values is non-deterministic.
5. The substitution patterns (`{{ key }}` with spaces, and `{{key}}` without) are the only two forms recognized. A pattern `{{  key  }}` (two spaces) does not match either form and is left unreplaced.
6. Unrecognized keys — those present in the template but absent from `vars` — are silently left as literal text. There is no rejection of unknown variable references.
7. The function does not validate or escape the substituted `value` strings in any way. Shell operators such as `;`, `|`, `&&`, `$(...)`, backticks, and newlines in a `value` are inserted verbatim into the returned string.

### 3. Outputs and Effects

- **Returns** a new owned `String` with all recognized patterns replaced.
- **No state writes.**
- **No events emitted.**
- **Postconditions:** The returned string is the template with zero or more replacements applied. Unreferenced variables from `vars` are silently ignored; unreferenced template slots are silently left in the output.

### 4. Block-by-Block Analysis

**Block A — Clone template to mutable `result` (L115)**
- **What:** Allocates a new `String` from the `template` slice.
- **Why here:** The function must produce a new owned value; the input is borrowed. Cloning at the start means all subsequent `replace` calls operate on the same accumulator.
- **Assumptions:** For large templates, this is a linear allocation. For a YAML-injected template with, say, 1 MB of text, this doubles memory usage for the duration of the call.
- **Depends on:** `template` being valid UTF-8 (guaranteed by Rust `&str`).

**Block B — Outer iteration over vars (L116)**
- **What:** Iterates every `(key, value)` pair in the `HashMap`.
- **Why here:** Each variable must be applied exactly once per iteration, but in non-deterministic order.
- **First Principles:** The fundamental operation is token substitution in a context where tokens are non-overlapping fixed strings. First-principles analysis: if substitution is purely positional and tokens do not nest within each other's syntax, a single-pass left-to-right scan over the *template* would be deterministic and O(n·m) where n=template length and m=number of keys. The current approach is instead O(m) outer iterations × O(n) inner `String::replace` calls per pattern, giving O(m·n) total, which is equivalent in complexity. The difference is that the current approach iterates over *variables* (HashMap order) rather than over *template positions*, which introduces the non-determinism described in assumption 4 above.

**Block C — Pattern construction and replacement (L117–L120)**
- **What:** Constructs two patterns (`{{ key }}` with spaces, `{{key}}` without), then calls `result.replace(pattern, value)` for each.
- **Why here:** Two syntactic forms are supported, as evidenced by the test at L200 (`{{ dir }}`) and L214 (`{{name}}`).
- **Assumptions:**
  1. `format!("{{{{ {key} }}}}")` produces the literal string `{{ key }}` because `{{` and `}}` are escape sequences in `format!`. This is correct Rust.
  2. `String::replace` replaces *all* occurrences of the pattern in `result`, not just the first. If the same key appears multiple times in the template, all occurrences are replaced in a single `replace` call. This is correct behavior for a substitution engine.
  3. The replacement `value` string is inserted verbatim; if `value` itself contains `{{ other_key }}`, the *next iteration* of the outer loop may replace that pattern if `other_key` is a key in `vars`. The outcome depends on whether `other_key` is visited in a later HashMap iteration.
- **5 Hows — How does a value containing `{{ service_name }}` create a recursive substitution path?** (1) The YAML runbook defines `params: {target: {default: "{{ service_name }}"}}` (or a user supplies it); (2) `apply_template` begins iterating; (3) on iteration for key `target`, value `{{ service_name }}` is inserted into `result`; (4) if key `service_name` is visited in a later HashMap iteration, the pattern `{{ service_name }}` now present in `result` is replaced; (5) the final output contains the value of `service_name` doubly substituted through `target`, which was not declared as a dependency.

**Block D — Implicit return (L122–L123)**
- **What:** Returns the accumulated `result`.
- **Why here:** The function contract requires returning the substituted string.
- **Depends on:** All prior iterations having completed.

### 5. Cross-Function Dependencies

- **Called by:**
  - `format_execution_plan` in `ssh_runbook_execute.rs` at L181, L186, L202 — for `command`, `condition`, and `rollback` fields of each step respectively.
- **Functions that call this function:** Only `format_execution_plan`.
- **Shared state:** None.
- **Invariant couplings:**
  1. `apply_template` produces a raw shell command string. The upstream caller (`format_execution_plan`) embeds it directly into a human-readable plan string without further sanitization.
  2. The downstream executor of that plan is the human/AI operator who calls `ssh_exec` manually. There is no programmatic sanitization layer between `apply_template` output and the SSH executor.
  3. The `vars` map passed in from `ssh_runbook_execute.rs` is built by merging runbook param defaults (from the YAML) with user-supplied params (from the MCP request); neither set is sanitized before being passed into `apply_template`.

---

## Function 3: `load_runbooks_from_dir` (L126–L153)

### 1. Purpose

`load_runbooks_from_dir` scans a directory for `.yaml` and `.yml` files, loads each via `load_runbook`, and returns the successful results as a `Vec<Runbook>`. It is the filesystem-backed runbook discovery path, as distinct from the compile-time `builtin_runbooks` path.

### 2. Inputs and Assumptions

| Parameter | Type | Trust level |
|---|---|---|
| `dir` | `&Path` | Caller-supplied; trust depends on caller (startup config vs. user request) |

**Preconditions and assumptions:**
1. The function is called with the output of `default_runbooks_dir()` in both `ssh_runbook_validate.rs` (L79–L81) and `ssh_runbook_execute.rs` (L96–L97). That path is `{config_dir}/mcp-ssh-bridge/runbooks/`, which is derived from `dirs::config_dir()` — a system call that reads OS-standard paths (`$XDG_CONFIG_HOME` on Linux, `%APPDATA%` on Windows). This means the directory is influenced by environment variables.
2. The function does not resolve symlinks or check for path traversal before passing `entry.path()` to `load_runbook`. A symlink within the directory pointing to an arbitrary file (e.g., `/etc/passwd`) would be read as YAML.
3. The function silently skips files it cannot read or parse (L145–L147 `warn!` only). This means a corrupted or adversarial file only results in a log warning, not a failure.
4. There is no limit on the number of files scanned. A directory with 10,000 YAML files would yield 10,000 `from_str` calls.
5. There is no limit on the depth of the scan; it is a flat single-level `read_dir` (L129). Subdirectories are ignored (they have no extension matching `.yaml` or `.yml`).
6. `entries.flatten()` at L134 silently discards `DirEntry` errors.
7. File extension matching at L137–L139 is case-sensitive: `.YAML` or `.Yaml` are not loaded.

### 3. Outputs and Effects

- **Returns** `Vec<Runbook>` — may be empty if the directory is absent, empty, or all files fail to parse.
- **No persistent state writes.**
- **Emits** `tracing::info!` for each successfully loaded runbook (L142), `tracing::warn!` for an unreadable directory (L130) or a failed file (L146).
- **External interaction:** `std::fs::read_dir` and transitively `std::fs::read_to_string` (inside `load_runbook`).

### 4. Block-by-Block Analysis

**Block A — Directory open (L129–L132)**
- **What:** Attempts `read_dir(dir)`; on failure, logs a warning and returns an empty Vec.
- **Why here:** Graceful degradation — the function is called even when user-runbooks may not exist yet (first run).
- **Assumptions:** A missing directory is not an error condition from the function's perspective. This is consistent with the startup flow where `default_runbooks_dir()` may not exist.
- **Depends on:** OS filesystem permissions for the process.

**Block B — Entry iteration and extension filter (L134–L149)**
- **What:** Flattens `DirEntry` results, checks the file extension, and dispatches to `load_runbook`.
- **Why here:** The `flatten()` at L134 silently skips IO errors on individual entries; the extension check at L137 ensures only YAML-shaped files are passed to the parser.
- **5 Whys — Why does the extension filter not use `to_ascii_lowercase()`?** (1) Case-sensitive matching means `.YAML` is silently ignored; (2) on case-insensitive filesystems (macOS HFS+, Windows NTFS), the operator may save a file as `runbook.YAML` and wonder why it is not loaded; (3) the decision was likely expedient; (4) the consequence is silent non-loading, not a failure mode; (5) it is worth noting but does not affect security posture on Linux.
- **Assumptions:** `entry.path()` returns the full absolute path for files within the scanned directory.

### 5. Cross-Function Dependencies

- **Calls:** `load_runbook` (L140) — analyzed below.
- **Called by:** Both `ssh_runbook_validate.rs` L79–L81 and `ssh_runbook_execute.rs` L97.
- **Shared state:** None.
- **Invariant couplings:** The returned `Vec<Runbook>` is merged with `builtin_runbooks()` at the call sites; name collisions between built-in and user runbooks are resolved by `find()` returning the *first* match (built-ins precede user runbooks in the concatenated vec at L95–L97 of `ssh_runbook_execute.rs`).

---

## Function 4: `load_runbook` (L156–L165)

### 1. Purpose

`load_runbook` reads a single YAML file from disk, deserializes it into a `Runbook` struct via `serde_saphyr::from_str`, and calls `validate_runbook` on the result. It is the innermost single-file ingestion function in the filesystem path.

### 2. Inputs and Assumptions

| Parameter | Type | Trust level |
|---|---|---|
| `path` | `&Path` | Filesystem-sourced; controlled by `load_runbooks_from_dir` |

**Preconditions and assumptions:**
1. `path` is a file that exists and has a `.yaml` or `.yml` extension (enforced by the caller).
2. The file content is read as a UTF-8 string. Non-UTF-8 bytes cause `read_to_string` to fail with an IO error, which is mapped to a `String` error and propagated.
3. **`serde_saphyr::from_str` at L160 is called without an explicit `Budget` or `Options`.** This is the call site flagged by the context7 audit. The parser operates under its internal defaults for `max_anchors`, `max_depth`, `max_nodes`, and `max_reader_input_bytes`. Those defaults have not been confirmed in the saphyr source; they are therefore unclear.
4. YAML anchors and aliases in the file are processed by saphyr before the `Runbook` struct is populated. The depth of alias expansion and the number of anchors are bounded only by saphyr's internal defaults.
5. The function does not check file size before reading. A multi-gigabyte file would be read entirely into memory before `from_str` is invoked.
6. After successful deserialization, `validate_runbook` is called (L163). Only structural presence is checked — the deserialized string values are not inspected.
7. The path is not checked for symlinks or traversal components (e.g., `../../etc/passwd`).

### 3. Outputs and Effects

- **Returns** `Ok(Runbook)` on success; `Err(String)` on IO failure, parse failure, or validation failure.
- **No state writes.**
- **No events emitted.** (The caller `load_runbooks_from_dir` logs success/failure.)
- **External interactions:** `std::fs::read_to_string` (one syscall), `serde_saphyr::from_str` (YAML parse, CPU-bound).

### 4. Block-by-Block Analysis

**Block A — File read (L157–L158)**
- **What:** Calls `std::fs::read_to_string(path)` and maps IO errors to a formatted error string.
- **Why here:** Must obtain the YAML content before parsing.
- **Assumptions:** File is valid UTF-8. No size cap is enforced.
- **Depends on:** OS file permissions and path validity.
- **First Principles:** The purpose of reading before parsing is to give the parser a complete in-memory representation. An alternative (not present here) would be `serde_saphyr::from_reader` with a `BufReader`, which would stream the file without a full allocation. The current `read_to_string` approach allocates the entire file content as a `String` before the parser sees any of it, doubling peak memory usage relative to a streaming approach for large files.

**Block B — YAML parse (L160–L161)**
- **What:** Calls `serde_saphyr::from_str::<Runbook>(&content)` and maps parse errors.
- **Why here:** Core deserialization step — converts raw YAML bytes into a strongly typed `Runbook`.
- **Assumptions:**
  1. `from_str` is the bare-defaults entry point. Per the upstream audit document (`serde-saphyr.md` line 18), budget parameters are only applied via `from_str_with_options`.
  2. Saphyr processes YAML anchors and aliases during parsing. Without `max_anchors` and `max_nodes` caps, a YAML document crafted with exponentially expanding aliases (billion-laughs pattern) would expand the in-memory representation unboundedly before the typed deserializer sees any data.
  3. The `Runbook` struct does not carry `#[serde(deny_unknown_fields)]`. Unknown keys in the YAML are silently ignored. This means a YAML with extraneous keys — including keys reserved for future expansion or keys intended to probe behavior — is accepted without error.
  4. The parse error is surfaced as a `String` error that includes `path.display()`, which aids debugging but does not affect the security posture.
- **5 Whys — Why is `from_str` used rather than `from_str_with_options`?** (1) `from_str` is the simplest saphyr entry point; (2) the runbook parsing was likely written against the minimal API surface; (3) the config loader at `src/config/loader.rs` L45 also uses the bare `from_str`; (4) no project-wide policy exists in `CLAUDE.md` or `domain-builders.md` requiring `Options` for YAML parsing; (5) therefore, the budget omission is structural and consistent across the codebase, not an isolated oversight.
- **5 Hows — How does the absence of `max_reader_input_bytes` interact with the file read at L157?** (1) `read_to_string` reads the entire file without cap; (2) the resulting `String` may be arbitrarily large; (3) `from_str` receives this unbounded `&str`; (4) saphyr allocates its parse tree in proportion to input size; (5) peak memory usage during `load_runbook` is approximately `2 × file_size + parse_tree_overhead` with no cap enforced in this function.

**Block C — Semantic validation (L163–L164)**
- **What:** Calls `validate_runbook(&runbook)` and propagates any error.
- **Why here:** Separating parse (structural) validation from semantic validation. Structural validation is implicit in serde's type mapping; semantic validation is explicit in `validate_runbook`.
- **Assumptions:** A successfully deserialized `Runbook` that fails `validate_runbook` is treated identically to a parse failure from the caller's perspective (both return `Err(String)`).
- **Depends on:** Block B having succeeded.

### 5. Cross-Function Dependencies

- **Calls:** `std::fs::read_to_string` (external, black-box), `serde_saphyr::from_str` (external, black-box parser), `validate_runbook` (internal, analyzed above).
- **Called by:** `load_runbooks_from_dir` (L140).
- **Shared state:** None.
- **Invariant couplings:**
  1. The `from_str` budget invariant is absent — this is the documented call site.
  2. The `validate_runbook` postcondition (non-empty name, non-empty steps, each step has command or condition) holds for every `Runbook` returned from this function.
  3. The returned `Runbook` has not had its string field *values* sanitized — that invariant is never established anywhere in this module.

---

## Function 5: `builtin_runbooks` (L176–L193)

### 1. Purpose

`builtin_runbooks` returns the five compile-time-embedded YAML runbook definitions as `Vec<Runbook>`. It serves as the trusted baseline set of runbooks that is always available regardless of the user's filesystem configuration.

### 2. Inputs and Assumptions

**Explicit inputs:** None.

**Implicit inputs:**
1. Five `include_str!` literals embedded at compile time from `config/runbooks/disk_full.yaml`, `service_restart.yaml`, `oom_recovery.yaml`, `log_rotation.yaml`, `cert_renewal.yaml`.
2. These files are under version control and reviewed as part of the build process. They are trusted.

**Preconditions and assumptions:**
1. The `include_str!` macros bind the YAML content at compile time. The deployed binary cannot load different content here unless recompiled.
2. **`serde_saphyr::from_str` at L188 is called without an explicit `Budget`.** This is the second flagged call site. However, because the YAML content is a compile-time constant (`&'static str`), the maximum input size is known at build time and cannot be influenced at runtime.
3. `filter_map` at L186–L190 silently drops any built-in runbook that fails to parse. A compile-time YAML parse failure would only be caught at build time if test coverage exercises `builtin_runbooks()` — which the test at L302 does. However, the `warn!` on L189 is a runtime-only signal; a build without running tests could silently ship with fewer than 5 built-ins.
4. `validate_runbook` is NOT called on built-in runbooks here. The `load_runbook` function calls `validate_runbook`, but `builtin_runbooks` bypasses `load_runbook` entirely and calls `from_str` directly. The only semantic validation of built-in runbooks occurs in tests.
5. The returned `Vec` may have fewer than 5 elements if any `from_str` call fails at runtime (unlikely given assumption 1 but structurally possible).
6. Built-in runbooks are prepended to user runbooks in the merge performed by callers. Name collisions between built-ins and user runbooks favor built-ins (first `find` match wins).

### 3. Outputs and Effects

- **Returns** `Vec<Runbook>` with 0–5 elements.
- **No state writes.**
- **Emits** `tracing::warn!` (L189) for any built-in that fails to parse at runtime.
- **Postcondition:** Each `Runbook` in the returned vec has passed serde deserialization. `validate_runbook` has *not* been applied.

### 4. Block-by-Block Analysis

**Block A — Definitions array (L177–L183)**
- **What:** Constructs a fixed-size array of 5 `&'static str` slices via `include_str!`.
- **Why here:** Centralizes the list of built-in runbooks in one place; adding a new built-in requires only adding a path here.
- **Assumptions:** All five paths must exist at compile time. Missing paths cause a compile error.
- **First Principles:** Embedding YAML as compile-time strings eliminates the filesystem attack surface for the built-in path entirely. A runtime file-loading mechanism for built-ins would be susceptible to file substitution; `include_str!` is immune.

**Block B — filter_map parse loop (L185–L192)**
- **What:** Parses each YAML string, maps parse errors to `warn!`, collects successes.
- **Why here:** Graceful degradation — a single malformed built-in should not prevent the others from loading.
- **Assumptions:**
  1. The `from_str` call at L188 uses bare defaults, same as L160. For built-ins, this is not a practical concern (content is bounded at compile time), but the code pattern is inconsistent with what `from_str_with_options` would require.
  2. `validate_runbook` is not called here. The built-in runbooks are validated only by the test at L302 (`test_builtin_runbooks_parse`), which checks name and steps are non-empty but does not call `validate_runbook` explicitly. Unclear whether a built-in runbook could contain a step with neither `command` nor `condition`; need to verify each YAML file independently.
- **5 Hows — How would a regression in a built-in YAML file be caught?** (1) `test_builtin_runbooks_parse` at L302 calls `builtin_runbooks()` and asserts length is 5; (2) if a YAML parse error occurs, `filter_map` drops that entry; (3) the Vec length would be 4 instead of 5; (4) the assertion `assert_eq!(runbooks.len(), 5)` would fail; (5) the regression is caught at test time, not at compile time, so it requires the test suite to run.

### 5. Cross-Function Dependencies

- **Calls:** `serde_saphyr::from_str` (L188) — external black-box parser, bare defaults.
- **Called by:** `ssh_runbook_validate.rs` L78, `ssh_runbook_execute.rs` L95.
- **Shared state:** None.
- **Invariant couplings:**
  1. Built-in runbooks are not passed through `validate_runbook`; they depend on test coverage for semantic correctness.
  2. The name collision resolution (built-ins win over user runbooks) depends on the merge order in callers.
  3. `builtin_runbooks` is called on every tool invocation of `ssh_runbook_validate` and `ssh_runbook_execute` — it is not cached. Each call re-parses all five YAML strings.

---

## Function 6: `format_execution_plan` (private, `ssh_runbook_execute.rs` L161–L210)

### 1. Purpose

`format_execution_plan` converts a resolved `Runbook` into a human-readable text execution plan that Claude or a human operator uses to manually invoke each step via `ssh_exec`. It calls `apply_template` to substitute variable values into commands, conditions, and rollback strings.

### 2. Inputs and Assumptions

| Parameter | Type | Trust level |
|---|---|---|
| `name` | `&str` | From `rb.name`; deserialized from trusted or attacker YAML |
| `description` | `&str` | From `rb.description`; same |
| `host` | `&str` | From `args.host`; validated against config (L87–L92 of execute handler) |
| `steps` | `&[RunbookStep]` | From deserialized runbook |
| `vars` | `&HashMap<String, String>` | Merge of param defaults (from YAML) and user-supplied params (from MCP request) |

**Preconditions and assumptions:**
1. `host` has been confirmed to exist in `ctx.config.hosts` (L87–L92 of execute handler). This is structural, not semantic validation — the host's connection details are trusted config.
2. `vars` values come from two sources: `rb.params[*].default` (YAML-sourced) and `args.params` (MCP request body, fully attacker-controlled). They are merged with `vars.extend(args.params)` at L113, meaning user-supplied values *overwrite* YAML defaults for the same key. No sanitization intervenes.
3. `apply_template(cmd, vars)` produces the full command string to be placed in the output plan. The plan is returned as a `String` — it is the tool's final output.
4. The function is not async; it is pure in the sense that it only reads its inputs and writes to a local `String`. No SSH calls occur here.
5. Unrecognized template variables (present in `cmd` but absent from `vars`) are silently left as literal `{{ key }}` text in the output plan. The operator would then execute a command containing the literal token — behavior is unclear at the `ssh_exec` level.
6. The condition string at L185–L190 is also passed through `apply_template` but is rendered as display text only, not evaluated programmatically. There is no condition evaluation logic in this path — the condition is shown to the operator for manual decision-making.
7. The `on_false` field at L188 is not passed through `apply_template`; it is emitted verbatim. If `on_false` contains template tokens, they remain unexpanded.

### 3. Outputs and Effects

- **Returns** a multi-line `String` representing the full execution plan.
- **No state writes.**
- **No external calls.**
- **Postcondition:** The returned string contains, for each step, the template-substituted `command`, the template-substituted `condition` (if any), confirmation flags, `save_as` labels, and template-substituted `rollback` commands.

### 4. Block-by-Block Analysis

**Block A — Header construction (L168–L175)**
- **What:** Writes the runbook name, host, description, and step count header.
- **Why here:** Provides operator context before the step list.
- **Assumptions:** `name`, `description`, and `host` are embedded directly into the output string with no HTML or shell escaping. The `description` field in particular is a free-text string from the YAML with no length or content validation.

**Block B — Per-step loop (L177–L207)**
- **What:** For each step: renders the step number and name, applies template to `command`, applies template to `condition`, prints `on_false` verbatim, prints confirmation warning, prints `save_as` label, applies template to `rollback`.
- **Why here:** The operator needs to see each step in order.
- **Assumptions:**
  1. `apply_template(cmd, vars)` at L181 produces the final command text. If `vars` contains an attacker-controlled value with shell metacharacters, those appear verbatim in the plan output.
  2. `apply_template(cond, vars)` at L186 — conditions in the shipped runbooks (e.g., `disk_full.yaml` L20: `"{{ current_usage }} >= {{ threshold_percent }}"`) embed computed values from previous steps via `save_as`. The mechanism by which a prior step's output becomes a variable value is not present in `format_execution_plan` — that would require actual execution and output capture, which is explicitly out of scope here (the handler only produces a plan). The condition with `{{ current_usage }}` in the plan would therefore display as a literal token unless `current_usage` was supplied as a param by the caller.
  3. `step.on_false` at L188–L190 is printed verbatim and NOT passed through `apply_template`. This is an inconsistency: commands and conditions are substituted, but `on_false` is not. If `on_false` contained a template reference, it would appear unreplaced in the output.
- **5 Whys — Why is `on_false` not passed through `apply_template`?** (1) `on_false` is a flow-control directive (e.g., `"skip_to_end"`) rather than a shell command; (2) the designer likely considered it an opaque label, not a command string; (3) the shipped runbooks use literal strings like `"skip_to_end"` for this field; (4) therefore there was no concrete need for substitution; (5) the inconsistency is a structural gap that would matter if a runbook author used `{{ key }}` in `on_false`.

### 5. Cross-Function Dependencies

- **Calls:** `apply_template` (L181, L186, L202) — analyzed above.
- **Called by:** `SshRunbookExecuteHandler::execute` (L151–L157).
- **Shared state:** None.
- **Invariant couplings:**
  1. The output is the final string returned to the MCP client. The client (Claude or human) then manually calls `ssh_exec` with each command. There is no programmatic handoff — the sanitization responsibility lies entirely with the human/AI reading the plan.
  2. `vars` is fully merged before `format_execution_plan` is called. The `args.params` values from the MCP request body overwrite runbook defaults at L113, and `format_execution_plan` operates on the merged result.
  3. The `save_as` label (L197–L199) is a name that would be meaningful only in a stateful execution engine. In the current plan-only model, it is displayed as metadata, not acted upon.

---

## Call Chain Summary: MCP Request → Command String

The end-to-end data flow from MCP client to shell command text:

```
MCP client JSON-RPC request
  └─ args.yaml_content (validate path) OR args.runbook_name + args.params (execute path)
       │
       ├─ [VALIDATE PATH] ssh_runbook_validate.rs L75
       │    serde_saphyr::from_str::<Runbook>(yaml)   ← bare defaults, no Budget
       │    → validate_runbook(&rb)
       │    → ToolCallResult::text (structural report only, no command execution)
       │
       └─ [EXECUTE PATH] ssh_runbook_execute.rs L95–L113
            builtin_runbooks()  ← L188 from_str bare defaults (trusted content)
            load_runbooks_from_dir(user_dir)  ← L160 from_str bare defaults (filesystem)
            args.params  ← attacker-controlled string values, no sanitization
            vars = defaults + args.params  ← merged, no sanitization
            │
            └─ format_execution_plan(steps, vars)
                 apply_template(cmd, vars)   ← values inserted verbatim
                 → String returned to MCP client (the plan)
                 → Human/Claude reads plan and calls ssh_exec manually
```

Three structural observations on this chain:

1. **No sanitization layer exists between `args.params` values and the `apply_template` output.** The `vars` map carries attacker-supplied strings directly from the MCP request to the rendered command text.

2. **`apply_template` is not the SSH executor.** The plan is text output. The actual execution requires a separate `ssh_exec` call by the operator. This indirection means the bridge itself does not execute the substituted command — the risk is in what the operator is shown and whether they inspect it before executing.

3. **The `save_as` mechanism (runbook step output capture) is not implemented in the current codebase.** The shipped runbooks use `save_as: current_usage` (disk_full.yaml L17) and then reference `{{ current_usage }}` in a later condition (L20). In a plan-only model, `current_usage` would never be populated in `vars` by a prior step, so the condition would display the unreplaced token `{{ current_usage }}` unless the user manually supplied it as a param.

---

## `serde_saphyr::from_str` Call Site Inventory

| Location | YAML origin | `Budget`? | `Options`? | `deny_unknown_fields`? |
|---|---|---|---|---|
| `runbook.rs` L160 (`load_runbook`) | Filesystem file | No | No | No |
| `runbook.rs` L188 (`builtin_runbooks`) | Compile-time constant | No | No | No |
| `ssh_runbook_validate.rs` L75 | MCP request body | No | No | No |
| `config/loader.rs` L45 | Config file | No | No | Unclear; need to inspect |

The validate handler's call at `ssh_runbook_validate.rs` L75 is the highest-trust-boundary crossing: raw text from an MCP network request is parsed directly with bare `from_str` defaults.

---

## Key Invariants Per Function

| Function | Invariant 1 | Invariant 2 | Invariant 3 |
|---|---|---|---|
| `validate_runbook` | Non-empty `name` (L87) | Non-empty `steps` (L90) | Each step has `command` or `condition` (L97) |
| `apply_template` | All recognized tokens are replaced | Unreferenced vars are silently ignored | Unreferenced template slots are silently preserved |
| `load_runbooks_from_dir` | Only `.yaml`/`.yml` extensions processed | Failed files are silently skipped | Returned runbooks have passed `validate_runbook` |
| `load_runbook` | Returned runbook passes `validate_runbook` | File content is unbounded pre-parse | `from_str` runs under bare default budget |
| `builtin_runbooks` | Content is compile-time constant | `validate_runbook` is NOT called | Returns 0–5 elements, caller cannot distinguish |
| `format_execution_plan` | `vars` values inserted verbatim | `on_false` NOT substituted | Output is display text, not executed by this function |

---

## Open Questions

1. **What are saphyr's internal default budget values for `max_anchors`, `max_depth`, `max_nodes`, and `max_reader_input_bytes`?** The upstream audit document (`serde-saphyr.md` line 19) explicitly defers to "verify those defaults in the saphyr source." These values determine the practical blast radius of the billion-laughs vector at L160 and L75.

2. **Is `validate_runbook` called on built-in runbooks anywhere other than the test at L302?** The production path in `builtin_runbooks` (L176–L193) skips `validate_runbook`. If a built-in YAML is edited to have a step with neither `command` nor `condition`, that malformed step would survive into the execution plan.

3. **What does `ssh_exec` do with an empty command string?** `validate_runbook` at L97 catches `command: None`, but `command: Some("")` passes. The empty string would be substituted verbatim through `apply_template` and appear in the plan. The downstream `ssh_exec` behavior for an empty command is unclear; need to inspect `src/domain/use_cases/` for the `ssh_exec` builder.

4. **Does the `save_as` capture mechanism exist anywhere in the codebase?** The shipped runbooks reference `save_as` to feed prior step output into later conditions (e.g., `current_usage` in `disk_full.yaml`). The plan-only model in `ssh_runbook_execute.rs` does not implement runtime execution or output capture. If a stateful execution engine is ever added, the `vars` merge point (L108–L113 of `ssh_runbook_execute.rs`) would need to incorporate step outputs — at which point the substitution trust model changes significantly.

5. **Can `load_runbooks_from_dir` be invoked with an attacker-controlled path?** Currently, both callers use `default_runbooks_dir()`. If any future tool handler accepts a user-supplied runbook directory, the filesystem reading path (including the bare-budget `from_str` at L160) would become directly attacker-reachable without needing to plant files in the config directory.

6. **Is the HashMap iteration order non-determinism in `apply_template` observable in practice?** This requires a concrete test case: a runbook where param A's default value is `{{ B }}` and param B is user-supplied. Current tests (`test_apply_template`, `test_apply_template_no_spaces`) do not exercise cross-variable reference.

7. **Is `#[serde(deny_unknown_fields)]` absent on `Runbook` by design?** The upstream guidance (`serde-saphyr.md` line 22) recommends `deny_unknown_fields` for belt-and-suspenders. The current `Runbook`, `RunbookParam`, and `RunbookStep` structs have no such annotation. Unknown YAML keys are silently ignored, which prevents a parse error but also silently swallows typos and future-schema probing.

8. **Is the `require_elicitation_on_destructive` gate applied to `ssh_runbook_execute`?** The handler is annotated `annotation = "destructive"` (L31 of `ssh_runbook_execute.rs`). The `check_destructive_elicitation` path in `server.rs` L1241–1243 checks `destructive_hint`. Whether the macro sets `destructive_hint: true` for the `"destructive"` annotation value is unclear without inspecting the `mcp_tool` proc macro expansion.


---

## Phase 3 — Global Synthesis (anchored facts)

### State & invariant reconstruction (cross-section)

- **Per-session isolation enforced structurally** in `src/mcp/server.rs:L641,L646` for both `PendingRequests` and `SessionCapabilities`. Server struct (`McpServer` L46-L92) carries NO `pending_requests` / `client_supports_*` fields — absence is the structural enforcement.
- **`Arc::clone` is the publish point** for atomic stores in `SessionCapabilities` (relies on standard library `Arc` AcqRel ref-count semantics; `Ordering::Relaxed` on per-flag stores/loads is sound).
- **UUID v4 (`simple()` 32-hex-char)** is the per-session-internal request-id mechanism in `PendingRequests::create_request` (L47), preventing within-session id-prediction even though session-scoping is the structural primary defense.
- **`SecurityValidator` two-gate model**: `validate()` (whitelist+blacklist) for raw user `ssh_exec` paths, `validate_builtin()` (blacklist only) for domain-builder-constructed commands. Both share the `normalize_for_blacklist_match` step (validator.rs L55-L63) covering `${IFS}`, `$IFS`, `$'\t'`, `$'\n'`, `$' '`, `\\\n`. The `Standard` mode default + empty default whitelist (`SecurityConfig::default().whitelist == []`) means `validate()` denies ALL raw commands by default — only `validate_builtin()` paths succeed.

### Workflow reconstruction (end-to-end command execution)

```
MCP JSON-RPC client (untrusted)
   │
   ├─ stdio / unix-socket / http(+oauth) transport       [src/mcp/transport/*]
   │     ↳ HTTP only: oauth_middleware → OAuthValidator::validate_token  [oauth.rs L179-L241]
   │       (alg-allowlist L184-L194 → kid lookup → DecodingKey → Validation::new(header.alg) → decode → scopes)
   │
   ├─ McpServer::serve_session (server.rs L635)
   │     ↳ alloc Arc<PendingRequests> (L641) + Arc<SessionCapabilities> (L646)  ← per-session
   │     ↳ reader loop (L678) → route_incoming_message (L695)
   │     ↳ handle_initialize → set_supports_*  (L1134-L1153, single writer pre-spawn)
   │     ↳ tools/call → tokio::spawn handler task with Arc::clone of per-session state
   │           ↳ ToolContext.execute_use_case
   │                ↳ ExecuteCommandUseCase::execute
   │                     ↳ CommandValidator::validate (validator.rs L141)         ← raw ssh_exec gate
   │                          → normalize_for_blacklist_match → blacklist regex → whitelist regex (Standard/Strict)
   │                ↳ ExecuteCommandUseCase::validate_builtin
   │                     ↳ CommandValidator::validate_builtin (validator.rs L201) ← builtin gate (no whitelist)
   │           ↳ executor.exec → SshClient.handle.exec_request → russh
   │
   └─ Server-initiated (elicitation / sampling / roots/list)
         ↳ ClientRequester::send_request (client_requester.rs L78-L103)
              ↳ session_pending.create_request (UUID id + oneshot rx)
              ↳ awaits oneshot rx (with timeout)
         ↳ client response arrives via reader loop → resolve(id, response) [pending_requests.rs L59-L68]
```

### Trust boundary mapping

| Boundary | Trusted side | Untrusted side | Crossing point |
|---|---|---|---|
| MCP JSON-RPC body | server | any MCP client | `serve_session` reader loop |
| HTTP transport headers | server | any HTTP peer | `oauth_middleware` |
| OAuth Bearer token bytes | server config (issuer/audience/scopes/keys) | client | `OAuthValidator::validate_token` |
| Command string in `ssh_exec` | none | full | `CommandValidator::validate` |
| Command string built by domain builder | partially (template + args) | embedded user vars | `CommandValidator::validate_builtin` |
| SSH server's host public key | none | full | `Handler::check_server_key` → `known_hosts::verify_host_key` |
| SSH passphrase | trusted (config-loaded) | n/a | `load_secret_key(path, Some(passphrase))` |
| YAML config file | trusted | n/a | `serde_saphyr::from_str` (loader.rs L45) |
| YAML runbook from MCP request body | none | full | `serde_saphyr::from_str::<Runbook>(yaml)` (ssh_runbook_validate.rs L75) |
| Runbook param values from request | none | full | `apply_template(cmd, vars)` (runbook.rs L116-L120) |
| jump-host SSH session | trusted (after `check_server_key`) | direct-tcpip data is server-controlled | `client::connect_stream` over `ChannelStream` |

### Complexity & fragility clusters (anchor for vulnerability-hunting phase that runs OUTSIDE this skill)

1. **Command-construction surfaces** that consume user input AND call `validate_builtin` (whitelist-exempt): need to verify each call site escapes embedded values before calling `validate_builtin`. Identified callers per validator.rs section 5: `standard_tool.rs:L296`, `ssh_disk_usage.rs:L116`, `ssh_find.rs:L154`, `ssh_tail.rs:L137`, `ssh_metrics.rs:L145`, `ssh_metrics_multi.rs:L197`, `ssh_file_write.rs:L220`. (Inventory only — no severity assigned.)
2. **YAML budget gap** — `serde_saphyr::from_str` (no `_with_options`) is used at three sites: `src/config/loader.rs:L45`, `src/domain/runbook.rs:L160,L188`, `src/mcp/tool_handlers/ssh_runbook_validate.rs:L75`. The validate handler is the only one that parses fully-attacker-controlled YAML.
3. **OAuth wiring gap (per oauth.rs section)** — `oauth_middleware` constructs `OAuthValidator::new((*config).clone())` per request (L275 of `http.rs` per oauth-section open question), starting with `keys` empty. Production key population is "left for a follow-up" per module doc L9-L18.
4. **`ssh/client.rs` `Config { ..Default::default() }` at L339, L285** — leaves `Preferred` algorithms and `Limits` rekey thresholds at russh 0.60 defaults. SOCKS proxy password is `Option<String>` (NOT `Zeroizing<String>`) per `config/types.rs:L420-L421`.
5. **Server-singleton overlap surfaces (cross-session contamination distinct from Vuln 8/9)** — `runtime_max_output_chars` (server.rs L65/L1125), `roots` (L79/L942), `client_info` (L64/L1155), `notification_tx` (L68/L653). Documented as pre-existing by the session_capabilities subagent (OQ-2).

---

## Open questions (consolidated, for Tasks 8/9/11/13)

(Each subagent's `## Open questions` block is preserved verbatim in the per-section text above. Consolidated highlights below.)

### From validator.rs
- `$'\x09'` / `$'\011'` (octal/hex tab encodings) and `${IFS:-" "}` default-value expansion not normalized.
- `validate_builtin` caller discipline is documented but not type-enforced.
- Production wiring of `CommandValidator` (avoiding `SecurityConfig::default()` which would block all `validate()` calls) needs inspection in `src/main.rs` / `src/mcp/server.rs`.

### From pending_requests.rs (Vuln 8)
- Cross-session isolation enforced by absence of server field. Task 13 (variant-analysis) must enumerate every `Arc<Mutex<HashMap<...>>>` in `McpServer` to confirm no other surface still uses cross-session keying.

### From session_capabilities.rs (Vuln 9)
- OQ-1: Re-init guard — `handle_initialize` does not visibly check `self.initialized` before re-writing capability flags. Inspect server.rs L1083-L1160.
- OQ-2: `runtime_max_output_chars` last-writer-wins across concurrent HTTP sessions.
- OQ-3: `supports_roots` not propagated into `ToolContext`.
- OQ-5: HTTP transport's SSE-reconnect path may dispatch handlers with `session_caps = None` if not threaded correctly.

### From oauth.rs
- 9 open questions identified by subagent (preserved in section). Highest-leverage: per-request empty-key-map structural gap, missing `set_required_spec_claims` interaction with jsonwebtoken 9.x defaults, `kid` echo in error responses, EdDSA omission from allowlist.

### From ssh/client.rs
- 10 open questions preserved. Highest-leverage: `Config { ..Default::default() }` algorithm/Limits gap, SOCKS password not zeroized, `originator_address` hardcoded `127.0.0.1:0`, `sanitize_ssh_error` coverage gap on connection-phase errors.

### From runbook.rs
- 8 open questions preserved. Highest-leverage: saphyr internal Budget defaults, `command: Some("")` evasion of validation, `save_as` mechanism not implemented despite shipped runbooks referencing it, missing `deny_unknown_fields` on `Runbook`/`RunbookStep`/`RunbookParam`.

---

## Plugin version

- **Skill**: `audit-context-building:audit-context-building` (trailofbits)
- **Skill base directory**: `/home/muchini/.claude/plugins/cache/trailofbits/audit-context-building/1.1.0/skills/audit-context-building`
- **Function-analyzer subagent type**: `audit-context-building:function-analyzer` (read-only: Read, Grep, Glob)
- **Subagent dispatch**: 6 parallel function-analyzer agents (validator.rs, pending_requests.rs, session_capabilities.rs, oauth.rs, ssh/client.rs, runbook.rs), each completing the per-function microstructure checklist with quality thresholds (≥3 invariants/fn, ≥5 assumptions, ≥3 risk considerations, ≥1 First Principles, ≥3 combined 5-Whys/5-Hows).
