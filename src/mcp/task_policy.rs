//! Which tool calls this server elects to run as tasks (MCP 2026-07-28).
//!
//! 2025-11-25 let the CLIENT ask, through a `params.task` object on
//! `tools/call`. The 2026-07-28 tasks extension deleted that field and moved
//! the decision to the server, verbatim: "The server is the sole decider;
//! clients do not signal task preference on the request itself." So the
//! decision has to live somewhere on the server side, and this module is it.
//!
//! Two rules govern what may enter [`LONG_RUNNING_TOOLS`]. The second is
//! enforced by a test rather than by care:
//!
//! 1. **Long by construction, not by accident.** `ssh_exec_multi` can take an
//!    hour or a millisecond depending on the command it is handed; promoting
//!    it would make `echo hello` on three hosts asynchronous. Only tools whose
//!    duration is a property of the tool — not of its arguments — belong here.
//!
//! 2. **Non-destructive, mechanically.** No entry may carry
//!    `destructive_hint: true`. The spec is explicit that the polling flow is
//!    implementable today while destructive-confirmation-then-task is not
//!    ("you cannot implement destructive-op confirmation-then-task without
//!    reading the MRTR page first"), and
//!    `long_running_tools_are_never_destructive` enforces the rule against the
//!    REGISTRY — so it survives someone forgetting it, which a comment does
//!    not.
//!
//! `ssh_runbook_execute` is the best functional candidate in the repository —
//! a multi-step runbook is long with certainty — and it is held out by rule 2
//! alone. When the MRTR item closes, it is the first name to reconsider.

/// Tools this server runs asynchronously, returning a task handle instead of
/// a result.
///
/// Per-entry justification, since the reasoning is worth more later than the
/// list is:
///
/// - `ssh_awx_job_follow` — waiting IS its function. It polls an AWX job's
///   status on a `poll_interval` clamped to 2..30 s; its duration is
///   intrinsic, never a function of its arguments.
/// - `ssh_ansible_playbook` — the case the spec itself describes: the long
///   playbook that returns a handle in milliseconds. A multi-task play over an
///   inventory is long by nature.
/// - `ssh_vuln_scan` — a host vulnerability scan: minutes, read-only, no side
///   effects.
/// - `ssh_log_aggregate` — multi-host aggregation whose cost grows with the
///   window and the host count, structurally.
///
/// Deliberately NOT here, and the refusals matter as much as the entries:
/// `ssh_runbook_execute` and `ssh_ansible_adhoc` are annotated `destructive`
/// (rule 2); `ssh_exec_multi` is long only by accident (rule 1);
/// `ssh_security_audit`, `ssh_incident_triage`, `ssh_k8s_triage` and
/// `ssh_port_scan` are all plausible read-only candidates held in reserve —
/// four entries are easier to defend than eight.
pub const LONG_RUNNING_TOOLS: &[&str] = &[
    "ssh_awx_job_follow",
    "ssh_ansible_playbook",
    "ssh_vuln_scan",
    "ssh_log_aggregate",
];

/// Whether the server elects to run `tool_name` as a task.
#[must_use]
pub fn is_long_running(tool_name: &str) -> bool {
    LONG_RUNNING_TOOLS.contains(&tool_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::registry::create_all_enabled_registry;

    /// Rule 2, enforced against the registry rather than against a copy of it.
    ///
    /// Asserting over a hand-written table of expected annotations would pin
    /// the copy, not the truth: re-annotating a tool as `destructive` would
    /// leave the table — and the test — untouched.
    ///
    /// The lookup assertion is not decoration. `LONG_RUNNING_TOOLS.contains()`
    /// answers `false` for a misspelled name, so a typo would silently
    /// disable the promotion AND sail through the destructive check, which
    /// only ever inspects tools it managed to find. Requiring each name to
    /// resolve is what makes the second half of this test mean anything. It
    /// also rejects a meta-tool name outright: the three discovery meta-tools
    /// are not registry entries.
    #[test]
    fn long_running_tools_are_never_destructive() {
        let tools = create_all_enabled_registry().list_tools();

        for name in LONG_RUNNING_TOOLS {
            let tool = tools
                .iter()
                .find(|t| t.name == *name)
                .unwrap_or_else(|| panic!("{name} is not a registered tool"));

            let destructive = tool
                .annotations
                .as_ref()
                .and_then(|a| a.destructive_hint)
                .unwrap_or(false);

            assert!(
                !destructive,
                "{name} is annotated destructive_hint: true and must not be promoted to a \
                 task: the spec's MRTR page has to be read before destructive-op \
                 confirmation-then-task can be implemented at all"
            );
        }
    }

    /// The list is a policy, not a lookup table of every tool.
    #[test]
    fn is_long_running_is_false_for_an_ordinary_tool() {
        assert!(is_long_running("ssh_ansible_playbook"));
        assert!(!is_long_running("ssh_status"));
        assert!(!is_long_running("ssh_exec"));
        // Held out by rule 2, and the first name to revisit after MRTR.
        assert!(!is_long_running("ssh_runbook_execute"));
    }
}
