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
//!    `destructive_hint: true`, and
//!    `long_running_tools_are_never_destructive` enforces it against the
//!    REGISTRY — so it survives someone forgetting it, which a comment does
//!    not.
//!
//! **Rule 2's justification has been corrected against the spec, and the
//! correction matters more than the rule.** Earlier revisions of this file
//! claimed the spec forbade confirmation-then-task until its multi-round-trip
//! page was read. The page has now been read
//! (`/specification/2026-07-28/basic/patterns/mrtr`), and it says nothing
//! whatsoever about tasks or about destructive operations — it is the
//! mechanism for server-to-client requests, nothing more. No spec rule ties
//! `destructiveHint` to task eligibility. The blocker was a guess.
//!
//! The REAL blocker is one this repository owns. MRTR opens with a breaking
//! change: *"Servers **MUST** send server-to-client requests (such as
//! `roots/list`, `sampling/createMessage`, or `elicitation/create`) using the
//! MRTR pattern. The previous pattern of server-initiated requests is no
//! longer supported."* This server's destructive-confirmation gate
//! (`check_destructive_elicitation`) still uses that deleted pattern: it
//! sends `elicitation/create` as a server-initiated JSON-RPC request through
//! `ClientRequester` and blocks on the reply. Promoting a destructive tool to
//! a task would therefore build confirmation-then-task on top of a flow the
//! revision removed. Rule 2 holds until the gate itself is MRTR-shaped —
//! `resultType: "input_required"` plus an integrity-protected `requestState`,
//! answered by a client retry under a NEW request id.
//!
//! `ssh_runbook_execute` and `ssh_ansible_playbook` are the best functional
//! candidates in the repository — a multi-step runbook and a multi-task play
//! are both long with certainty — and both are held out by rule 2 alone. They
//! are the first names to reconsider once the elicitation gate moves to MRTR.

/// Tools this server runs asynchronously, returning a task handle instead of
/// a result.
///
/// Per-entry justification, since the reasoning is worth more later than the
/// list is:
///
/// - `ssh_awx_job_follow` — waiting IS its function. It polls an AWX job's
///   status on a `poll_interval` clamped to 2..30 s; its duration is
///   intrinsic, never a function of its arguments.
/// - `ssh_vuln_scan` — a host vulnerability scan: minutes, read-only, no side
///   effects.
/// - `ssh_log_aggregate` — multi-host aggregation whose cost grows with the
///   window and the host count, structurally.
///
/// Deliberately NOT here, and the refusals matter as much as the entries:
/// `ssh_runbook_execute`, `ssh_ansible_adhoc` and `ssh_ansible_playbook` are
/// annotated `destructive` (rule 2); `ssh_exec_multi` is long only by accident
/// (rule 1); `ssh_security_audit`, `ssh_incident_triage`, `ssh_k8s_triage` and
/// `ssh_port_scan` are all plausible read-only candidates held in reserve —
/// three entries are easier to defend than eight.
///
/// `ssh_ansible_playbook` was an entry here until its annotation was
/// corrected. It ran an arbitrary Ansible playbook — `rm -rf`, service
/// shutdown, fleet reconfiguration — under `mutating`, while
/// `ssh_ansible_adhoc`, which runs a single module and is strictly less
/// powerful, was already `destructive`. The less capable tool was marked the
/// more dangerous one, so the elicitation gate never fired on the playbook.
/// Fixing the annotation evicts it from this list by rule 2, and that eviction
/// is a real loss: it is the exact case the tasks extension describes, the
/// long play that should return a handle in milliseconds. It comes back when
/// the elicitation gate moves to MRTR.
pub const LONG_RUNNING_TOOLS: &[&str] =
    &["ssh_awx_job_follow", "ssh_vuln_scan", "ssh_log_aggregate"];

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
                 task: this server's confirmation gate still sends `elicitation/create` as \
                 a server-initiated request, which 2026-07-28 replaced with MRTR, so \
                 confirmation-then-task would be built on a deleted flow"
            );
        }
    }

    /// The list is a policy, not a lookup table of every tool.
    ///
    /// The positive assertion is not decoration: `is_long_running` returning
    /// `false` for everything would satisfy every negative below on its own.
    #[test]
    fn is_long_running_is_false_for_an_ordinary_tool() {
        assert!(is_long_running("ssh_vuln_scan"));
        assert!(!is_long_running("ssh_status"));
        assert!(!is_long_running("ssh_exec"));
        // Both held out by rule 2, and the first names to revisit once the
        // elicitation gate speaks MRTR.
        assert!(!is_long_running("ssh_runbook_execute"));
        assert!(!is_long_running("ssh_ansible_playbook"));
    }

    /// `ssh_ansible_playbook` runs an arbitrary playbook and MUST be
    /// `destructive`, so that `security.require_elicitation_on_destructive`
    /// can actually gate it.
    ///
    /// This asserts the annotation directly rather than leaning on
    /// `long_running_tools_are_never_destructive`, which only ever inspects
    /// names that ARE in the list: now that the playbook has been evicted,
    /// that test would stay green if the annotation were reverted to
    /// `mutating` tomorrow. The comparison against `ssh_ansible_adhoc` is what
    /// makes the requirement legible — a single module is strictly less
    /// powerful than a whole play, so the play can never be the milder of the
    /// two.
    #[test]
    fn an_arbitrary_playbook_is_annotated_destructive() {
        let tools = create_all_enabled_registry().list_tools();

        let destructive_hint = |name: &str| -> bool {
            tools
                .iter()
                .find(|t| t.name == name)
                .unwrap_or_else(|| panic!("{name} is not a registered tool"))
                .annotations
                .as_ref()
                .and_then(|a| a.destructive_hint)
                .unwrap_or(false)
        };

        assert!(
            destructive_hint("ssh_ansible_playbook"),
            "ssh_ansible_playbook runs an arbitrary playbook and must carry \
             destructive_hint: true, or the elicitation gate never fires on it"
        );
        assert!(
            destructive_hint("ssh_ansible_adhoc"),
            "ssh_ansible_adhoc is the weaker of the pair; if IT is not destructive \
             the comparison above proves nothing"
        );
        assert!(
            !destructive_hint("ssh_ansible_inventory"),
            "a read-only inventory listing must not be destructive, or this test \
             would pass against a registry that marks everything destructive"
        );
    }
}
