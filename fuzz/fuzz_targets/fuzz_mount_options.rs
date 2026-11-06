#![no_main]
use bridge_mcp::domain::use_cases::storage::StorageCommandBuilder;
use libfuzzer_sys::fuzz_target;

// What `ssh_storage_mount` owes its caller: a `mount` on a network file system
// is never built with an option that makes the host's own identity
// authenticate to the server the caller named, nor with an option the mount
// helpers would read differently from the check; and `mount.cifs` never runs
// with the ambient passwords of the host in its environment.
//
// Whatever the builder ACCEPTED is checked:
//
// - on a network file system (`cifs`, `smb3`, `nfs`, `nfs4`, `ceph`, or a type
//   left to `mount` -- absent, `auto`, `none` -- with a `//server/share` or
//   `host:path` device), `options` holds no quote character;
// - on the helper they apply to, `options` has none of the keys that pick a
//   credential source of the host: `credentials`, `cred`, `cruid`,
//   `multiuser`, `upcall_target` (CIFS), `sec=` with a Kerberos flavor (CIFS,
//   NFS), `xprtsec=mtls` (NFS), `secretfile`, `conf`, `key` (Ceph);
// - when `fs_type` lists `ceph`, `options` has exactly one `secret=` whose
//   value is 1 to 40 base64 characters (what `mount.ceph` keeps);
// - `none` is never accepted for a device of a network form (`//`, `:`, `@`),
//   and a device with `@` is never accepted without a fixed type, unless
//   `options` has `bind`, `rbind` or `move` (no helper runs then);
// - when `mount` can run `mount.cifs` (`fs_type` lists `cifs` or `smb3`, or
//   the type is left to `mount` and the device starts with `//`) the command
//   starts with the `unset` of the PASSWD variables, and every other command
//   starts with `mount ` (unchanged).
//
// The oracle restates the key lists and the rules; it does not call the
// builder's own helpers. The input is text in three lines:
//
//   fs_type   (`-` for no type)
//   device
//   options   (the rest of the input; absent for no options)
//
// Refusal is always fine; the fuzzer is looking for a call that gets THROUGH.
//
// Run with: `cargo +nightly fuzz run fuzz_mount_options`

// cifs-utils 7.4 `mount.cifs.c` reads exactly these variables with `getenv`
// (besides `SUDO_UID`, on the Kerberos path, which the options rule refuses).
const CIFS_UNSET: &str =
    "unset PASSWD PASSWD_FD PASSWD_FILE PASSWD2 PASSWD2_FD PASSWD2_FILE USER && ";

fuzz_target!(|data: &str| {
    let mut lines = data.splitn(3, '\n');
    let fs_line = lines.next().unwrap_or("");
    let device = lines.next().unwrap_or("");
    let options = lines.next();
    let fs_type = if fs_line == "-" { None } else { Some(fs_line) };

    let Ok(cmd) = StorageCommandBuilder::build_mount_command(device, "/mnt", fs_type, options)
    else {
        return;
    };

    let listed: Vec<&str> = fs_type.map(|l| l.split(',').collect()).unwrap_or_default();
    let has = |t: &str| listed.iter().any(|l| *l == t);
    let autodetect = fs_type.is_none() || has("auto") || has("none");
    let network_device = device.starts_with("//") || device.contains(':');
    let guessed = autodetect && network_device;
    let cifs = has("cifs") || has("smb3") || guessed;
    let nfs = has("nfs") || has("nfs4") || guessed;
    let ceph = has("ceph") || guessed;
    let opts = options.unwrap_or("");

    let moves = opts
        .split(',')
        .any(|o| matches!(o.trim(), "bind" | "rbind" | "move"));
    let network_form = network_device || device.contains('@');
    assert!(
        moves || !(network_form && has("none")),
        "accepted fs_type none for a network device: {data:?}\n  built: {cmd:?}"
    );
    assert!(
        moves || !(device.contains('@') && (fs_type.is_none() || has("auto"))),
        "accepted a device with '@' without a fixed type: {data:?}\n  built: {cmd:?}"
    );

    if cifs || nfs || ceph {
        assert!(
            !opts.contains(['"', '\'']),
            "accepted a quote in the options of a network file system: {data:?}\n  built: {cmd:?}"
        );
        for opt in opts.split(',') {
            let opt = opt.trim();
            let (key, value) = opt.split_once('=').unwrap_or((opt, ""));
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_ascii_lowercase();
            let key = key.as_str();
            if cifs {
                assert!(
                    !["credentials", "cred", "cruid", "multiuser", "upcall_target"].contains(&key),
                    "accepted the CIFS credential-source key {key:?}: {data:?}\n  built: {cmd:?}"
                );
            }
            if cifs || nfs {
                assert!(
                    key != "sec"
                        || !value.split(':').any(|f| {
                            f.starts_with("krb5") || f.starts_with("lkey") || f.starts_with("spkm3")
                        }),
                    "accepted a Kerberos sec= flavor: {data:?}\n  built: {cmd:?}"
                );
            }
            if nfs {
                assert!(
                    !(key == "xprtsec" && value == "mtls"),
                    "accepted xprtsec=mtls: {data:?}\n  built: {cmd:?}"
                );
            }
            if ceph {
                assert!(
                    key != "secretfile" && key != "conf" && key != "key",
                    "accepted the Ceph file key {key:?}: {data:?}\n  built: {cmd:?}"
                );
            }
        }
    }

    if has("ceph") {
        // `mount.ceph` compares the key with `strcmp`: only the exact key
        // `secret` counts, and there must be one and a value for it.
        let secrets: Vec<Option<&str>> = opts
            .split(',')
            .filter(|o| o.split_once('=').map_or(*o, |(key, _)| key) == "secret")
            .map(|o| o.split_once('=').map(|(_, value)| value))
            .collect();
        let cephx = |v: &str| {
            (1..=40).contains(&v.len())
                && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        };
        assert!(
            matches!(secrets.as_slice(), [Some(value)] if cephx(value)),
            "accepted a ceph mount without exactly one non-empty secret=: {data:?}\n  \
             built: {cmd:?}"
        );
    }

    let reaches_cifs = has("cifs") || has("smb3") || (autodetect && device.starts_with("//"));
    if reaches_cifs {
        assert!(
            cmd.starts_with(CIFS_UNSET),
            "a command that can run mount.cifs does not start with the unset: {data:?}\n  \
             built: {cmd:?}"
        );
    } else {
        assert!(
            cmd.starts_with("mount "),
            "a command that cannot run mount.cifs does not start with mount: {data:?}\n  \
             built: {cmd:?}"
        );
    }
});
