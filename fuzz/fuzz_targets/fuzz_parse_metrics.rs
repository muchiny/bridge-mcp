#![no_main]

use bridge_mcp::{parse_cpu, parse_disk, parse_load, parse_memory};
use libfuzzer_sys::fuzz_target;

// The old target threw raw bytes at all four parsers and asserted "did not
// panic". Every one of them is written to return `None` rather than panic, so
// the assertion was structurally unfailable: `parse_disk` reads `parts[2]` and
// `parts[3]` only after checking `parts.len() < 6`, and swapping those two
// indices — turning every reported `used` into `available` and back — leaves
// the target green forever.
//
// That swap is not hypothetical. These four read the output of `/proc/stat`,
// `free -b`, `df -B1` and `/proc/loadavg` from a REMOTE host, by column
// position, with no header parsing and no keying by name. A column index is
// the entire contract, and nothing else in this crate checks it.
//
// So this target BUILDS a record, renders it in the exact format the command
// emits, parses that text back, and compares the parsed fields against the
// values AS WRITTEN IN THE TEXT.
//
// "As written in the text" is the load-bearing part, and it is why the record
// is constrained rather than arbitrary. A filesystem name carrying a space
// shifts every column after it, and the parser would then be right to report
// different numbers — an oracle comparing against the values that went IN
// would fail on healthy code. Two constraints remove that whole class:
//
//   * names are drawn from an alphabet with no whitespace, and are prefixed
//     so they can never collide with the pseudo-filesystems `parse_disk`
//     skips (`tmpfs`, `devtmpfs`, `none`, `overlay*`). What that skip does is
//     left to the unit tests: re-deriving it here would mean re-deriving four
//     string comparisons the parser already makes, which is how a
//     near-miss oracle gets written.
//   * every number is rendered from an integer, and every fractional field's
//     expected value is obtained by PARSING THE RENDERED TEXT rather than by
//     recomputing a float. A f64 read back from its own decimal form is the
//     value the parser sees; a float recomputed alongside it is a second
//     implementation, and this project has already shipped three oracles that
//     were the wrong one of the two.
//
// The CPU half asks its question differently, because CPU percentages are
// derived rather than copied and an oracle that redid the division would just
// be the same division twice. Instead it loads exactly ONE jiffy counter and
// leaves the other six at zero, so the answer is 100.00 or 0.00 by
// construction — no arithmetic in the oracle at all, and the assertion is
// purely about WHICH counter feeds WHICH percentage.

/// Characters a filesystem or mount-point name may be built from.
///
/// No whitespace, so column positions are fixed; no `%`, so a name cannot be
/// read as a percentage if a column ever shifts anyway.
const SAFE: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-";

fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if data.len() < n {
        return None;
    }
    let (head, tail) = data.split_at(n);
    *data = tail;
    Some(head)
}

fn take_u32(data: &mut &[u8]) -> Option<u32> {
    take(data, 4).map(|b| u32::from_be_bytes(b.try_into().expect("4 bytes")))
}

fn take_u64(data: &mut &[u8]) -> Option<u64> {
    take(data, 8).map(|b| u64::from_be_bytes(b.try_into().expect("8 bytes")))
}

/// A name built only from [`SAFE`], `prefix`-ed so it cannot be a pseudo-fs.
fn take_name(data: &mut &[u8], prefix: &str, len: usize) -> Option<String> {
    let bytes = take(data, len)?;
    let mut name = prefix.to_string();
    for b in bytes {
        name.push(char::from(SAFE[usize::from(*b) % SAFE.len()]));
    }
    Some(name)
}

/// A decimal with two fractional digits, and the f64 that text parses to.
///
/// Returned as a pair on purpose: the expected value must come from the string
/// the parser will read, never from arithmetic performed alongside it.
fn take_fixed_point(data: &mut &[u8]) -> Option<(String, f64)> {
    let whole = take_u32(data)?;
    let frac = take(data, 1)?[0] % 100;
    let text = format!("{whole}.{frac:02}");
    let value = text.parse::<f64>().ok()?;
    Some((text, value))
}

fn cpu_half(rest: &mut &[u8]) {
    let Some(cores) = take_u32(rest) else { return };
    let Some(which) = take(rest, 1).map(|b| usize::from(b[0]) % 8) else {
        return;
    };
    let Some(value) = take_u32(rest) else { return };

    // Seven jiffy counters; exactly one of them is loaded. `which == 7` loads
    // none, which is how the "no time has passed at all" refusal is reached.
    let mut counters = [0u32; 7];
    if which < 7 {
        counters[which] = value;
    }
    let raw = format!(
        "cpu  {} {} {} {} {} {} {}\n{cores}\n",
        counters[0], counters[1], counters[2], counters[3], counters[4], counters[5], counters[6],
    );

    let Some(cpu) = parse_cpu(&raw) else {
        assert!(
            which == 7 || value == 0,
            "a `cpu` line with a non-zero counter must parse: {raw:?}"
        );
        return;
    };
    assert!(
        which < 7 && value != 0,
        "every counter is zero, so no time has passed and no percentage is \
         defined; the parser must refuse it: {raw:?}"
    );

    assert_eq!(
        cpu.cores, cores,
        "`nproc` is the second line and is copied verbatim: {raw:?}"
    );

    // The whole budget sits in one counter, so each percentage is exactly
    // 100.0 or exactly 0.0 — `v / v` is 1.0 for every finite non-zero f64,
    // and `round2(100.0)` is 100.0. Column index 0 is `user`, 1 `nice`,
    // 2 `system`, 3 `idle`, 4 `iowait`, 5 `irq`, 6 `softirq`.
    let (user, system, idle) = match which {
        0 | 1 => (100.0, 0.0, 0.0),
        2 | 5 | 6 => (0.0, 100.0, 0.0),
        3 => (0.0, 0.0, 100.0),
        // `iowait` is counted in the total and in none of the three reported
        // buckets. A host pinned on I/O reports 0% user, 0% system, 0% idle,
        // and that is the truth `/proc/stat` states.
        _ => (0.0, 0.0, 0.0),
    };
    assert_eq!(
        (cpu.user_percent, cpu.system_percent, cpu.idle_percent),
        (user, system, idle),
        "column {which} of the `cpu` line reached the wrong percentage. \
         user+nice is `user`, system+irq+softirq is `system`, idle is `idle`, \
         iowait is none of them: {raw:?}"
    );
}

fn memory_half(rest: &mut &[u8]) {
    let Some(total) = take_u64(rest) else { return };
    let Some(used) = take_u64(rest) else { return };
    let Some(free) = take_u64(rest) else { return };
    let Some(shared) = take_u64(rest) else { return };
    let Some(buff_cache) = take_u64(rest) else {
        return;
    };
    let Some(available) = take_u64(rest) else {
        return;
    };
    let Some(swap_total) = take_u64(rest) else {
        return;
    };
    let Some(swap_used) = take_u64(rest) else {
        return;
    };

    let raw = format!(
        "              total        used        free      shared  buff/cache   available\n\
         Mem:  {total} {used} {free} {shared} {buff_cache} {available}\n\
         Swap: {swap_total} {swap_used} {}\n",
        swap_total.saturating_sub(swap_used),
    );

    let Some(memory) = parse_memory(&raw) else {
        assert_eq!(
            total, 0,
            "a `Mem:` line with a non-zero total must parse: {raw:?}"
        );
        return;
    };
    assert_ne!(
        total, 0,
        "a total of zero makes every ratio undefined; the parser must refuse \
         it: {raw:?}"
    );

    // `free -b` columns: 1 total, 2 used, 3 free, 4 shared, 5 buff/cache,
    // 6 available. Only three of the six are reported, and `available` — the
    // one an operator acts on — is the LAST, six columns away from the first.
    assert_eq!(
        (
            memory.total_bytes,
            memory.used_bytes,
            memory.available_bytes
        ),
        (total, used, available),
        "a `Mem:` column reached the wrong field: {raw:?}"
    );
    assert_eq!(
        (memory.swap_total_bytes, memory.swap_used_bytes),
        (swap_total, swap_used),
        "a `Swap:` column reached the wrong field: {raw:?}"
    );
    assert!(
        memory.usage_percent.is_finite() && memory.usage_percent >= 0.0,
        "usage is a percentage of a non-zero total, so it is finite and \
         non-negative whatever `used` says: got {}, {raw:?}",
        memory.usage_percent
    );
}

fn disk_half(rest: &mut &[u8]) {
    let Some(row_count) = take(rest, 1).map(|b| usize::from(b[0]) % 5) else {
        return;
    };

    struct Row {
        filesystem: String,
        mount_point: String,
        total: u64,
        used: u64,
        available: u64,
        percent_text: String,
        percent: f64,
    }

    let mut rows = Vec::new();
    for _ in 0..row_count {
        let Some(name_len) = take(rest, 1).map(|b| usize::from(b[0]) % 12) else {
            return;
        };
        // `/dev/` and `/` prefixes: neither can be `tmpfs`, `devtmpfs` or
        // `none`, and neither starts with `overlay`, so no row is skipped and
        // this target never has to model that skip.
        let Some(filesystem) = take_name(rest, "/dev/", name_len + 1) else {
            return;
        };
        let Some(mount_point) = take_name(rest, "/", name_len + 1) else {
            return;
        };
        let Some(total) = take_u64(rest) else { return };
        let Some(used) = take_u64(rest) else { return };
        let Some(available) = take_u64(rest) else {
            return;
        };
        let Some((percent_text, percent)) = take_fixed_point(rest) else {
            return;
        };
        rows.push(Row {
            filesystem,
            mount_point,
            total,
            used,
            available,
            percent_text,
            percent,
        });
    }

    let mut raw = String::from("Filesystem 1B-blocks Used Available Use% Mounted on\n");
    for row in &rows {
        raw.push_str(&format!(
            "{} {} {} {} {}% {}\n",
            row.filesystem, row.total, row.used, row.available, row.percent_text, row.mount_point,
        ));
    }

    let Some(disks) = parse_disk(&raw) else {
        assert!(
            rows.is_empty(),
            "every row is well-formed and none is a pseudo-filesystem, so the \
             parser must return them: {raw:?}"
        );
        return;
    };
    assert_eq!(
        disks.len(),
        rows.len(),
        "the parser returned a different number of filesystems than `df` \
         listed: {raw:?}"
    );

    for (parsed, row) in disks.iter().zip(&rows) {
        // `df -B1` columns: 0 filesystem, 1 total, 2 USED, 3 AVAILABLE,
        // 4 use%, 5 mount point. 2 and 3 are adjacent, same type, same
        // magnitude, and swapping them tells an operator a full disk is empty.
        assert_eq!(
            (
                parsed.filesystem.as_str(),
                parsed.mount_point.as_str(),
                parsed.total_bytes,
                parsed.used_bytes,
                parsed.available_bytes,
                parsed.usage_percent,
            ),
            (
                row.filesystem.as_str(),
                row.mount_point.as_str(),
                row.total,
                row.used,
                row.available,
                row.percent,
            ),
            "a `df` column reached the wrong field: {raw:?}"
        );
    }
}

fn load_half(rest: &mut &[u8]) {
    let Some((text_1, load_1)) = take_fixed_point(rest) else {
        return;
    };
    let Some((text_5, load_5)) = take_fixed_point(rest) else {
        return;
    };
    let Some((text_15, load_15)) = take_fixed_point(rest) else {
        return;
    };
    let Some(uptime) = take_u32(rest) else { return };
    let Some(uptime_frac) = take(rest, 1).map(|b| b[0] % 100) else {
        return;
    };

    let raw = format!(
        "{text_1} {text_5} {text_15} 1/234 5678\n{uptime}.{uptime_frac:02} 98765.43\n"
    );

    let Some(load) = parse_load(&raw) else {
        panic!("a well-formed /proc/loadavg pair must parse: {raw:?}");
    };

    assert_eq!(
        (load.load_1min, load.load_5min, load.load_15min),
        (load_1, load_5, load_15),
        "the three load averages are positional and in ascending window order; \
         one of them reached the wrong field: {raw:?}"
    );
    // `/proc/uptime`'s first field is seconds with two decimals, and the
    // parser truncates rather than rounds. The generated whole part fits in a
    // u32, so the cast is exact and this says truncation, not rounding.
    assert_eq!(
        load.uptime_seconds,
        u64::from(uptime),
        "uptime is the FIRST field of the second line, truncated to whole \
         seconds: {raw:?}"
    );
}

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    let Some(selector) = take(&mut rest, 1).map(|b| b[0]) else {
        return;
    };

    match selector % 4 {
        0 => cpu_half(&mut rest),
        1 => memory_half(&mut rest),
        2 => disk_half(&mut rest),
        _ => load_half(&mut rest),
    }
});
