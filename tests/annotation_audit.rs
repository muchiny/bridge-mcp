//! Annotation/Group audit — guards against silent regressions where a
//! tool is registered with an annotation that doesn't match its name.
//!
//! Rules are based on suffixes in the tool name. They are intentionally
//! coarse and ride a small allowlist for legitimate exceptions
//! (`*_show_run` is a CLI command that READS the running config — read-only
//! despite the `_run` suffix).
//!
//! When you add a tool that violates a rule, fix the annotation. If the
//! tool is a true exception, add it to ALLOWLIST with a comment explaining
//! why.

use bridge_mcp::mcp::registry::{ToolAnnotationKind, ToolRegistryEntry};

const MUTATION_SUFFIXES: &[&str] = &[
    "_apply",
    "_set",
    "_enable",
    "_disable",
    "_install",
    "_remove",
    "_restart",
    "_reload",
    "_start",
    "_write",
    "_chmod",
    "_chown",
    "_patch",
    "_create",
    "_add",
    "_modify",
    "_update",
    "_distribute",
    "_trigger",
    "_allow",
    "_deny",
    "_mount",
    "_umount",
];

const DESTRUCTIVE_SUFFIXES: &[&str] = &["_delete", "_kill", "_uninstall", "_rollback", "_destroy"];

const ALLOWLIST: &[(&str, ToolAnnotationKind)] = &[
    ("ssh_net_equip_show_run", ToolAnnotationKind::ReadOnly),
    ("ssh_recording_start", ToolAnnotationKind::Mutating),
    ("ssh_recording_stop", ToolAnnotationKind::Mutating),
    ("ssh_session_create", ToolAnnotationKind::Mutating),
    ("ssh_session_close", ToolAnnotationKind::Mutating),
    ("ssh_tunnel_create", ToolAnnotationKind::Mutating),
    ("ssh_tunnel_close", ToolAnnotationKind::Mutating),
    ("ssh_runbook_execute", ToolAnnotationKind::Mutating),
    ("ssh_helm_rollback", ToolAnnotationKind::Destructive),
    ("ssh_helm_uninstall", ToolAnnotationKind::Destructive),
    ("ssh_helm_install", ToolAnnotationKind::Mutating),
    ("ssh_pkg_install", ToolAnnotationKind::Mutating),
    ("ssh_pkg_remove", ToolAnnotationKind::Destructive),
    ("ssh_user_delete", ToolAnnotationKind::Destructive),
    ("ssh_group_delete", ToolAnnotationKind::Destructive),
    ("ssh_process_kill", ToolAnnotationKind::Destructive),
    ("ssh_win_process_kill", ToolAnnotationKind::Destructive),
    ("ssh_storage_umount", ToolAnnotationKind::Mutating),
    ("ssh_storage_mount", ToolAnnotationKind::Mutating),
    ("ssh_crictl_rmi", ToolAnnotationKind::Destructive), // crictl rmi: image deletion — irreversible, _rmi suffix not in auto list
    ("ssh_k3s_etcd_snapshot_save", ToolAnnotationKind::Mutating), // etcd snapshot save: _save suffix not in MUTATION_SUFFIXES
    ("ssh_k3s_ctr_images", ToolAnnotationKind::Mutating), // ctr images: _images suffix not in any auto list; import mutates containerd image store
    ("ssh_k3s_cert_rotate", ToolAnnotationKind::Destructive), // cert rotate: irreversible cert regen, _rotate not auto-detected
    ("ssh_k3s_killall", ToolAnnotationKind::Destructive), // killall: kills all k3s processes+containers, _killall not auto-detected
    ("ssh_k3s_upgrade", ToolAnnotationKind::Destructive), // upgrade: re-runs installer, can break node, _upgrade not auto-detected
];

fn allowed(name: &str, kind: ToolAnnotationKind) -> bool {
    ALLOWLIST
        .iter()
        .any(|(allowed_name, allowed_kind)| *allowed_name == name && *allowed_kind == kind)
}

fn matches_suffix(name: &str, suffixes: &[&str]) -> bool {
    suffixes.iter().any(|suf| name.ends_with(suf))
}

#[test]
fn no_tool_has_empty_group() {
    let mut violations = vec![];
    for entry in inventory::iter::<ToolRegistryEntry>() {
        if entry.group.is_empty() {
            violations.push(entry.name);
        }
    }
    assert!(
        violations.is_empty(),
        "tools registered with empty group: {violations:?}"
    );
}

#[test]
fn no_tool_has_empty_name() {
    let mut violations = vec![];
    for entry in inventory::iter::<ToolRegistryEntry>() {
        if entry.name.is_empty() {
            violations.push(entry.group);
        }
    }
    assert!(
        violations.is_empty(),
        "tools registered with empty name in groups: {violations:?}"
    );
}

#[test]
fn mutation_suffix_implies_not_read_only() {
    let mut violations = vec![];
    for entry in inventory::iter::<ToolRegistryEntry>() {
        if entry.annotation_kind != ToolAnnotationKind::ReadOnly {
            continue;
        }
        if matches_suffix(entry.name, MUTATION_SUFFIXES)
            && !allowed(entry.name, ToolAnnotationKind::ReadOnly)
        {
            violations.push(entry.name);
        }
    }
    assert!(
        violations.is_empty(),
        "tools with mutation-suffixed names but `read_only` annotation \
         (should be `mutating` or `mutating_idempotent`): {violations:#?}\n\
         If a tool is a legitimate exception, add it to ALLOWLIST in \
         tests/annotation_audit.rs with a justification."
    );
}

#[test]
fn destructive_suffix_implies_destructive() {
    let mut violations = vec![];
    for entry in inventory::iter::<ToolRegistryEntry>() {
        if entry.annotation_kind == ToolAnnotationKind::Destructive {
            continue;
        }
        if matches_suffix(entry.name, DESTRUCTIVE_SUFFIXES)
            && !allowed(entry.name, entry.annotation_kind)
        {
            violations.push((entry.name, entry.annotation_kind));
        }
    }
    assert!(
        violations.is_empty(),
        "tools with destructive-suffixed names but non-destructive annotation: {violations:#?}\n\
         If a tool is reversible/idempotent, add it to ALLOWLIST in \
         tests/annotation_audit.rs with a justification."
    );
}

/// Tools whose NAME does not carry a destructive suffix but whose normal
/// operation can irreversibly destroy/overwrite data or run arbitrary
/// commands. The suffix-based rules above cannot catch these, so they are
/// pinned here: each MUST be annotated `destructive` so the
/// `require_elicitation_on_destructive` gate can confirm before they run.
/// (Audit 2026-06-20.)
const BEHAVIORAL_DESTRUCTIVE: &[&str] = &[
    "ssh_exec",            // arbitrary shell (rm -rf, mkfs, dd)
    "ssh_aws_cli",         // raw AWS passthrough (ec2 terminate, s3 rm, iam delete)
    "ssh_ansible_adhoc",   // arbitrary module exec (shell -a "rm ...")
    "ssh_db_restore",      // overwrites the target database
    "ssh_backup_restore",  // overwrites files at the restore destination
    "ssh_docker_compose",  // `down` removes containers + networks
    "ssh_esxi_snapshot",   // `remove_all` permanently deletes snapshots
    "ssh_ldap_modify",     // LDIF `changetype: delete` removes entries
    "ssh_vault_write",     // overwrites a secret (KV v1 has no versioning)
    "ssh_pkg_update",      // full system upgrade can remove/replace packages
    "ssh_k8s_drain", // kubectl drain evicts all pods from a node — irreversible workload disruption
    "ssh_crictl_rmi", // crictl rmi: image deletion is irreversible without a fresh pull
    "ssh_k3s_cert_rotate", // regenerates TLS certs; botched rotate can lock the API server
    "ssh_k3s_killall", // kills ALL k3s processes + containers + network namespaces
    "ssh_k3s_upgrade", // re-runs installer, swaps binary, can break the node
];

#[test]
fn behavioral_destructive_tools_are_destructive() {
    use std::collections::HashMap;
    let kinds: HashMap<&str, ToolAnnotationKind> = inventory::iter::<ToolRegistryEntry>()
        .map(|e| (e.name, e.annotation_kind))
        .collect();
    let mut violations = vec![];
    for name in BEHAVIORAL_DESTRUCTIVE {
        match kinds.get(name) {
            Some(ToolAnnotationKind::Destructive) => {}
            Some(other) => violations.push(format!("{name}: {other:?} (expected Destructive)")),
            None => violations.push(format!("{name}: not registered (stale entry?)")),
        }
    }
    assert!(
        violations.is_empty(),
        "behaviorally-destructive tools must be annotated `destructive` \
         (edit the handler macro, or remove from BEHAVIORAL_DESTRUCTIVE if \
         intentionally downgraded): {violations:#?}"
    );
}

#[test]
fn report_annotation_distribution() {
    let mut read_only = 0usize;
    let mut mutating = 0usize;
    let mut mutating_idempotent = 0usize;
    let mut destructive = 0usize;
    let mut total = 0usize;
    for entry in inventory::iter::<ToolRegistryEntry>() {
        total += 1;
        match entry.annotation_kind {
            ToolAnnotationKind::ReadOnly => read_only += 1,
            ToolAnnotationKind::Mutating => mutating += 1,
            ToolAnnotationKind::MutatingIdempotent => mutating_idempotent += 1,
            ToolAnnotationKind::Destructive => destructive += 1,
        }
    }
    assert_eq!(
        read_only + mutating + mutating_idempotent + destructive,
        total,
        "annotation kinds must sum to total tool count"
    );
    eprintln!(
        "annotation distribution: read_only={read_only} mutating={mutating} \
         mutating_idempotent={mutating_idempotent} destructive={destructive} total={total}"
    );
}
