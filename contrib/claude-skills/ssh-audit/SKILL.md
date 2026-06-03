---
name: ssh-audit
description: This skill should be used when the user asks to "run a security scan", "check for vulnerabilities", "audit compliance", "check certificate expiry", "scan open ports", or mentions security reviews, CIS benchmarks, or compliance assessments on remote servers.
argument-hint: <host> [quick|full|network|compliance]
compatibility: "2.1+"
---

# Security Audit

Run security audits on a remote server via bridge-mcp CLI.

**Delegation**: Use a general-purpose agent (via the Agent tool) to run these commands in isolation, so verbose scan output does not pollute the main conversation.

Parse `$ARGUMENTS`: first word = host, second word (optional) = scope (default: quick).

## Scope: quick (~2 min)

Fast security overview — run this first:

```bash
# Open ports
bridge-mcp tool ssh_port_scan host=HOST --json

# Certificate expiry
bridge-mcp tool ssh_cert_expiry host=HOST --json

# Fail2ban status
bridge-mcp tool ssh_fail2ban_status host=HOST --json

# Firewall rules
bridge-mcp tool ssh_firewall_list host=HOST --json

# Listening services
bridge-mcp tool ssh_exec host=HOST command="ss -tlnp" --json
```

## Scope: network

Network-focused security assessment:

```bash
# SSL/TLS audit
bridge-mcp tool ssh_ssl_audit host=HOST --json

# Port scan
bridge-mcp tool ssh_port_scan host=HOST --json

# Active connections
bridge-mcp tool ssh_net_connections host=HOST --json

# DNS configuration
bridge-mcp tool ssh_net_dns host=HOST --json
```

## Scope: compliance

Standards-based compliance check:

```bash
# CIS Benchmark
bridge-mcp tool ssh_cis_benchmark host=HOST --json

# STIG check
bridge-mcp tool ssh_stig_check host=HOST --json

# Compliance score
bridge-mcp tool ssh_compliance_score host=HOST --json

# Full compliance report
bridge-mcp tool ssh_compliance_report host=HOST --json
```

## Scope: full

Comprehensive audit — combines all scopes plus vulnerability scanning:

Run all commands from `quick`, `network`, and `compliance` scopes, then add:

```bash
# SBOM generation
bridge-mcp tool ssh_sbom_generate host=HOST --json

# Vulnerability scan
bridge-mcp tool ssh_vuln_scan host=HOST --json

# SELinux / AppArmor status
bridge-mcp tool ssh_selinux_status host=HOST --json
bridge-mcp tool ssh_apparmor_status host=HOST --json

# Security audit log
bridge-mcp tool ssh_security_audit host=HOST --json

# SSH key audit
bridge-mcp tool ssh_key_audit host=HOST --json

# User accounts review
bridge-mcp tool ssh_user_list host=HOST --json
```

## Audit Report Format

Produce a structured report:

1. **Risk Level**: critical / high / medium / low
2. **Findings**: list each issue with severity
   - Critical: exposed services, expired certs, no firewall
   - High: weak SSL, default passwords, no fail2ban
   - Medium: missing CIS controls, outdated packages
   - Low: informational, best-practice suggestions
3. **Compliance Score**: percentage if CIS/STIG was run
4. **Recommendations**: prioritized action items
5. **Next Steps**: specific commands to remediate each finding
