#![no_main]

use bridge_mcp::domain::use_cases::network_equipment::{
    EquipmentType, NetworkEquipmentCommandBuilder,
};
use libfuzzer_sys::fuzz_target;

/// Characters that change what a command means, on a POSIX shell or on a
/// device CLI.
///
/// A builder that accepts any of these inside an identifier has let the caller
/// write part of the command. That is exactly what happened before
/// `validate_identifier` existed:
///
/// ```text
/// build_show_interfaces_command(Juniper, Some("eth0; id"))
///   -> "show interfaces eth0; id extensive"
/// ```
const METACHARACTERS: &[char] = &[
    ';', '&', '|', '$', '`', '\n', '\r', '>', '<', '"', '\'', '\\', '(', ')', '{', '}', '*', '?',
    '!', '#', '\t', '\0',
];

const EQUIPMENT: &[EquipmentType] = &[
    EquipmentType::Cisco,
    EquipmentType::Juniper,
    EquipmentType::MikroTik,
    EquipmentType::Fortinet,
    EquipmentType::Generic,
];

// The invariant is NOT "does not panic".
//
// A builder that never panics while splicing `; rm -rf /` into a command is
// working perfectly and is still a hole. The property worth fuzzing is:
//
// > if the builder ACCEPTED an identifier, that identifier carried nothing
// > that could change the meaning of the command it was placed in.
//
// Refusal is always acceptable — the fuzzer is looking for inputs that get
// through, not for inputs that get rejected.
//
// Run with the dictionary, or this explores nothing interesting:
// `cargo +nightly fuzz run fuzz_network_equipment_builder -- -dict=fuzz/dicts/shell.dict`
fuzz_target!(|data: &str| {
    for &equipment in EQUIPMENT {
        if let Ok(cmd) = NetworkEquipmentCommandBuilder::build_show_interfaces_command(
            equipment,
            Some(data),
        ) {
            for &bad in METACHARACTERS {
                assert!(
                    !data.contains(bad),
                    "interface {data:?} was ACCEPTED for {equipment:?} despite carrying {bad:?}; \
                     built: {cmd:?}"
                );
            }
        }

        if let Ok(cmd) =
            NetworkEquipmentCommandBuilder::build_show_run_command(equipment, Some(data))
        {
            for &bad in METACHARACTERS {
                assert!(
                    !data.contains(bad),
                    "section {data:?} was ACCEPTED for {equipment:?} despite carrying {bad:?}; \
                     built: {cmd:?}"
                );
            }
        }
    }
});
