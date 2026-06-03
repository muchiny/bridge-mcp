#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::{ceil_char_boundary, floor_char_boundary};

fuzz_target!(|data: (&str, u16)| {
    let (s, idx_raw) = data;
    let idx = idx_raw as usize;

    // Test floor_char_boundary
    let floor = floor_char_boundary(s, idx);

    // Invariants for floor:
    // 1. Result must be <= index (or == len if index > len)
    assert!(floor <= idx || floor == s.len());
    // 2. Result must be a valid char boundary
    assert!(s.is_char_boundary(floor));
    // 3. Result must be <= string length
    assert!(floor <= s.len());

    // Test ceil_char_boundary
    let ceil = ceil_char_boundary(s, idx);

    // Invariants for ceil:
    // 1. Result must be >= index (bounded by len)
    assert!(ceil >= idx.min(s.len()));
    // 2. Result must be a valid char boundary
    assert!(s.is_char_boundary(ceil));
    // 3. Result must be <= string length
    assert!(ceil <= s.len());
});
