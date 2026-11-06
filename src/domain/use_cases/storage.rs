//! Storage Command Builder
//!
//! Builds commands for disk, filesystem, and LVM operations.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Filesystem types `mount -t` may be given.
///
/// An allowlist, not a character check: `fuse.<prog>` (and the `prog#source`
/// device form) makes `mount.fuse` run `<prog>` through `/bin/sh -c`, so any
/// name that could select a mount helper program is refused. Every entry is a
/// kernel filesystem or one whose `/sbin/mount.<type>` helper is a fixed
/// program that takes no program from the caller. Left out on purpose:
/// `glusterfs` (its helper loads a caller-supplied volfile), and every
/// `fuse*` type (`fuse.sshfs` runs `-o ssh_command=`).
const MOUNT_FS_TYPES: &[&str] = &[
    "auto",
    "none",
    "ext2",
    "ext3",
    "ext4",
    "xfs",
    "btrfs",
    "zfs",
    "f2fs",
    "jfs",
    "reiserfs",
    "nilfs2",
    "bcachefs",
    "vfat",
    "msdos",
    "exfat",
    "ntfs",
    "ntfs3",
    "ntfs-3g",
    "hfs",
    "hfsplus",
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "9p",
    "virtiofs",
    "ceph",
    "vboxsf",
    "tmpfs",
    "ramfs",
    "overlay",
    "hugetlbfs",
    "mqueue",
    "iso9660",
    "udf",
    "squashfs",
    "erofs",
    "proc",
    "sysfs",
    "devpts",
    "devtmpfs",
    "cgroup",
    "cgroup2",
    "bpf",
    "debugfs",
    "tracefs",
    "securityfs",
];

/// Mount-option keys of `mount.cifs` that choose where the credentials come
/// from instead of giving them: a credentials file on the host, the Kerberos
/// ticket cache of a uid, per-user sessions and the upcall namespace. Matched
/// case-insensitively, as `mount.cifs` does.
const CIFS_CREDENTIAL_KEYS: &[&str] =
    &["credentials", "cred", "cruid", "multiuser", "upcall_target"];

/// Mount-option keys of `mount.ceph` that read the `CephX` key or the cluster
/// configuration (and the keyring it names) from a file of the host, and
/// `key=`, which `mount.ceph` passes to the kernel as is: the kernel then
/// takes the named key from the keyrings of the mounting process.
///
/// `mount.ceph` (18.2, `parse_options`) handles `secretfile`, `secret`,
/// `conf`, `name`, `ms_mode`, `mon_addr`, `fs` and `nofallback` itself and
/// passes every other option to the kernel. Of the kernel's options (Linux
/// 6.18, `net/ceph/ceph_common.c` and `fs/ceph/super.c`), `key` is the one
/// that looks a key up (`request_key`); `secret` is the key itself.
const CEPH_CREDENTIAL_KEYS: &[&str] = &["secretfile", "conf", "key"];

/// Longest `secret=` value `mount.ceph` keeps (`MAX_SECRET_LEN` in
/// `mount.ceph.h`, ceph 18.2): a longer value is dropped without an error,
/// and `mount.ceph` then looks the key up in the host's keyring.
const CEPH_SECRET_MAX_LEN: usize = 40;

/// Shell prefix of a `mount` that can run `mount.cifs`: drops the ambient
/// credentials of the client. `mount.cifs` reads `PASSWD`, `PASSWD_FD` and
/// `PASSWD_FILE` (and `PASSWD2`, `PASSWD2_FD`, `PASSWD2_FILE` for the second
/// password) from its environment before it parses `-o`, and prefers them
/// over a `password=` of the call. Without `username=` it also takes the
/// whole of `USER` as the user name, and `USER` can carry a password
/// (`user%password`, read so by the Samba tools); without `USER` it uses the
/// login name of its uid. Nothing of the SSH host would reach a server the
/// caller chose with these variables left set. `unset` is a POSIX
/// builtin; the command runs in the SSH user's shell, so nothing outlives it.
/// It is joined with `&&`, not `;`: `unset` of a `readonly` variable fails,
/// and `mount` must not start then (a surviving variable would be sent to the
/// server). `unset` of a variable that is not set succeeds.
const MOUNT_CIFS_UNSET: &str =
    "unset PASSWD PASSWD_FD PASSWD_FILE PASSWD2 PASSWD2_FD PASSWD2_FILE USER && ";

/// Whether `mount` can end up running `mount.cifs` for this call: `fs_type`
/// lists `cifs` or `smb3`, or the type is left to `mount` (absent, `auto` or
/// `none`) and `device` is a `//server/share`.
///
/// Source: `mnt_context_guess_srcpath_fstype` of the util-linux libmount
/// (`libmount/src/context.c`, current release). With no type given, a device
/// that does not exist as a path is read as `nfs` when it contains a `:` (the
/// test comes first) and as `cifs` when it starts with `//`. Any other device
/// falls back to the types listed in `/etc/filesystems` and then to the
/// non-`nodev` types of `/proc/filesystems`; `none` is not autodetection but
/// a negative pattern (`no` + `ne`) that tries the same lists. A host may list
/// a network type in `/etc/filesystems`, so [`validate_mount_args`] refuses
/// those two ways for a device of a network form (`//`, `:` or `@`), and a
/// `host:path` device left to `mount` reaches `mount.nfs` only.
fn reaches_mount_cifs(device: &str, fs_type: Option<&str>) -> bool {
    let mut autodetect = fs_type.is_none();
    for t in fs_type.into_iter().flat_map(|list| list.split(',')) {
        match t {
            "cifs" | "smb3" => return true,
            "auto" | "none" => autodetect = true,
            _ => {}
        }
    }
    autodetect && device.starts_with("//")
}

/// Whether `fs_type` lists `ceph`.
///
/// Only an explicit type reaches `mount.ceph`: the autodetection of
/// `mnt_context_guess_srcpath_fstype` (util-linux libmount, see
/// [`reaches_mount_cifs`]) maps a `host:path` device to `nfs` and a
/// `//server/share` device to `cifs`, never to `ceph`. Requiring `secret=`
/// for an autodetected device would therefore only break `nfs` mounts.
fn names_ceph(fs_type: Option<&str>) -> bool {
    fs_type.is_some_and(|list| list.split(',').any(|t| t == "ceph"))
}

/// Which network filesystem helpers a `mount` call can reach.
#[derive(Clone, Copy, Default)]
struct NetworkFs {
    /// `cifs`, `smb3`.
    cifs: bool,
    /// `nfs`, `nfs4`.
    nfs: bool,
    /// `ceph`.
    ceph: bool,
}

impl NetworkFs {
    /// The helpers `fs_type` names, and all of them when the type is left to
    /// `mount` (absent, `auto` or `none`) and `device` has a network form
    /// (`//server/share` or `host:path`).
    fn of(device: &str, fs_type: Option<&str>) -> Self {
        let mut net = Self::default();
        let mut autodetect = fs_type.is_none();
        for t in fs_type.into_iter().flat_map(|list| list.split(',')) {
            match t {
                "cifs" | "smb3" => net.cifs = true,
                "nfs" | "nfs4" => net.nfs = true,
                "ceph" => net.ceph = true,
                "auto" | "none" => autodetect = true,
                _ => {}
            }
        }
        if autodetect && (device.starts_with("//") || device.contains(':')) {
            net = Self {
                cifs: true,
                nfs: true,
                ceph: true,
            };
        }
        net
    }

    fn any(self) -> bool {
        self.cifs || self.nfs || self.ceph
    }
}

/// Refuse the mount options of a network filesystem that make the host's own
/// identity authenticate to the server in `device`.
///
/// `mount.cifs`, the NFS client and `mount.ceph` can take the secret from a
/// file, a Kerberos ticket or keytab, or a TLS certificate of the host
/// instead of from the caller. With a server the caller chose that presents
/// the host's identity to it. The caller's own `username=` and `password=` stay
/// allowed.
///
/// Two more rules close the ways round the key list:
/// - no quote character (`"` or `'`) in `options` of a network filesystem:
///   the mount helpers do not read a quoted key or value as written (it fails
///   or is ignored), so the check below could not see what the helper sees;
/// - `ceph` must be given its key: without `secret=`, `mount.ceph` looks up
///   the key of the client name (`name=`, `admin` by default) in a keyring of
///   the host, and in the kernel keyring, and hands it to the monitor named
///   by the caller.
fn validate_network_mount_options(
    device: &str,
    fs_type: Option<&str>,
    options: &str,
) -> Result<()> {
    let net = NetworkFs::of(device, fs_type);
    if !net.any() {
        return Ok(());
    }
    if options.contains(['"', '\'']) {
        return Err(BridgeError::CommandDenied {
            reason: "options must not contain a quote character (\" or ') for a network \
                     filesystem: the mount helpers do not read a quoted key or value as \
                     written. Write the options without quotes"
                .to_string(),
        });
    }
    for opt in options.split(',') {
        let opt = opt.trim();
        let (key, value) = opt.split_once('=').unwrap_or((opt, ""));
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_ascii_lowercase();
        let what = if net.cifs && CIFS_CREDENTIAL_KEYS.contains(&key.as_str()) {
            "reads the credentials from a file, a Kerberos ticket cache or a per-user \
             session of the host"
        } else if net.ceph && CEPH_CREDENTIAL_KEYS.contains(&key.as_str()) {
            "reads the CephX key or the cluster configuration from a file of the host"
        } else if (net.cifs || net.nfs)
            && key == "sec"
            && value
                .split(':')
                .any(|f| f.starts_with("krb5") || f.starts_with("lkey") || f.starts_with("spkm3"))
        {
            "authenticates with the Kerberos credentials of the host"
        } else if net.nfs && key == "xprtsec" && value == "mtls" {
            "presents the TLS client certificate of the host"
        } else {
            continue;
        };
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "options '{opt}' {what}, which a network filesystem must not use with a server \
                 chosen by the caller. Pass username= and password= explicitly, or use an \
                 entry of /etc/fstab"
            ),
        });
    }
    if names_ceph(fs_type) {
        validate_ceph_secret(options)?;
    }
    Ok(())
}

/// Refuse `options` of a `ceph` mount that do not carry exactly one `secret=`
/// with a value. `mount.ceph` compares the key with `strcmp`, so only the
/// exact lowercase key `secret` counts (no trimming, no other case). The
/// value must be a `CephX` key that `mount.ceph` keeps: at most
/// [`CEPH_SECRET_MAX_LEN`] base64 characters. A longer value is dropped, and
/// `<hidden>` makes `mount.ceph` send `key=` instead; both end with a key of
/// the host.
fn validate_ceph_secret(options: &str) -> Result<()> {
    let mut secrets = options
        .split(',')
        .filter(|o| o.split_once('=').map_or(*o, |(key, _)| key) == "secret");
    let given = match (secrets.next(), secrets.next()) {
        (Some(opt), None) => opt.split_once('=').is_some_and(|(_, value)| {
            (1..=CEPH_SECRET_MAX_LEN).contains(&value.len())
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        }),
        _ => false,
    };
    if given {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: "options of a ceph mount must contain exactly one secret= with a value: \
                     a CephX key, at most 40 characters of A-Z, a-z, 0-9, +, / and =. Without \
                     it mount.ceph looks up the key of the client name in a keyring of the \
                     host and hands it to the monitor chosen by the caller. Pass secret= \
                     explicitly"
                .to_string(),
        })
    }
}

/// Refuse the `mount` arguments that would make `mount` run a program the
/// caller chose, or authenticate to a server the caller chose with a
/// credential of the host.
///
/// Where and what a filesystem is mounted (bind mounts, overlay layers, the
/// mount point) is the tool's job and is not restricted here: run with
/// `sudo`, this tool acts as root, as the other elevated tools do.
///
/// # Errors
///
/// [`BridgeError::CommandDenied`] when:
/// - `fs_type` (or an element of its comma-separated list) is not a type of
///   [`MOUNT_FS_TYPES`] (every `fuse*` type and every name with a `.`
///   included): `mount -t fuse.prog` runs `prog`;
/// - `device` contains `#` while no allowlisted type is fixed (`fs_type`
///   absent, `auto` or `none`): `mount.fuse` reads `prog#source` as a program
///   to run, and only those cases can still end in a FUSE type;
/// - the filesystem is a network one (`cifs`, `smb3`, `nfs`, `nfs4`, `ceph`,
///   or an absent/`auto`/`none` type with a `//server/share` or `host:path`
///   device) and `options` has a key that picks a credential source of the
///   host: `credentials`, `cred`, `cruid`, `multiuser`, `upcall_target`
///   (CIFS), `sec=` with a Kerberos flavor (`krb5`, `krb5i`, `krb5p`; CIFS and
///   NFS), `xprtsec=mtls` (NFS), `secretfile`, `conf`, `key` (Ceph). Keys are
///   matched case-insensitively after splitting on `,`;
/// - the filesystem is a network one and `options` contains a quote
///   character (`"` or `'`);
/// - `fs_type` lists `ceph` and `options` (possibly absent) does not contain
///   exactly one `secret=` whose value is a `CephX` key (1 to 40 base64
///   characters). A `host:path` device left to `mount` is read as `nfs`,
///   never `ceph`, so the rule does not apply to it;
/// - `fs_type` lists `none` and `device` has a network form (`//`, `:` or
///   `@`), or no type is fixed and `device` contains `@`: `mount` would try
///   every type listed in `/etc/filesystems`. A bind or move mount (`bind`,
///   `rbind` or `move` in `options`) is exempt: it runs no helper.
fn validate_mount_args(device: &str, fs_type: Option<&str>, options: Option<&str>) -> Result<()> {
    let mut autodetect = fs_type.is_none();
    if let Some(list) = fs_type {
        for t in list.split(',') {
            if !MOUNT_FS_TYPES.contains(&t) {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "fs_type '{t}' is not an allowed filesystem type (fuse and subtype \
                         names such as 'fuse.prog' would make mount run a helper program)"
                    ),
                });
            }
            if t == "auto" || t == "none" {
                autodetect = true;
            }
        }
    }
    if autodetect && device.contains('#') {
        return Err(BridgeError::CommandDenied {
            reason: "device must not contain '#' unless fs_type names a filesystem: mount.fuse \
                     reads 'prog#source' as a program to run"
                .to_string(),
        });
    }
    // A bind or move mount never runs a helper: libmount sets the type to
    // `none` itself for `MS_BIND` and `MS_MOVE` (`mnt_context_guess_fstype`).
    let moves = options.is_some_and(|list| {
        list.split(',')
            .any(|o| matches!(o.trim(), "bind" | "rbind" | "move"))
    });
    let network_form = device.starts_with("//") || device.contains([':', '@']);
    if !moves && network_form && fs_type.is_some_and(|list| list.split(',').any(|t| t == "none")) {
        return Err(BridgeError::CommandDenied {
            reason: "fs_type 'none' is refused for a network device: mount reads it as a \
                     pattern that tries every type listed in /etc/filesystems. Give the type \
                     of the filesystem (cifs, nfs, ceph...)"
                .to_string(),
        });
    }
    if !moves && autodetect && device.contains('@') {
        return Err(BridgeError::CommandDenied {
            reason: "a device with '@' (the ceph name@fsid.fs=/path form) needs fs_type: \
                     left to mount, it tries every type listed in /etc/filesystems. Give \
                     fs_type ceph"
                .to_string(),
        });
    }
    validate_network_mount_options(device, fs_type, options.unwrap_or(""))
}

/// Builds storage management commands.
pub struct StorageCommandBuilder;

impl StorageCommandBuilder {
    /// Build lsblk command.
    ///
    /// `LC_ALL=C` forces stable English column names so the columnar parser
    /// in `tool_handlers/utils.rs` can match user-supplied `columns=[...]`
    /// case-insensitively. `--list` disables the default tree-drawing
    /// branch glyphs (`└─`, `├─`) — those Unicode box-drawing characters
    /// shift byte alignment vs the header line and break gutter detection.
    #[must_use]
    pub fn build_lsblk_command(json: bool) -> String {
        if json {
            "LC_ALL=C lsblk -J -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID,MODEL".to_string()
        } else {
            "LC_ALL=C lsblk --list -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID,MODEL".to_string()
        }
    }

    /// Build detailed df command.
    ///
    /// `LC_ALL=C` forces stable English column names (`Filesystem`, `Size`,
    /// `Use%`, `Mounted on`) so the columnar parser can match user-supplied
    /// `columns=[...]` regardless of the host locale.
    #[must_use]
    pub fn build_df_command(path: Option<&str>, inodes: bool) -> String {
        let mut cmd = String::from("LC_ALL=C df -h");
        if inodes {
            cmd.push_str(" -i");
        }
        cmd.push_str(" -T"); // show filesystem type
        if let Some(p) = path {
            cmd.push_str(" -- ");
            cmd.push_str(&shell_escape(p));
        }
        cmd
    }

    /// Build mount command.
    ///
    /// # Errors
    ///
    /// [`BridgeError::CommandDenied`] when `fs_type` is not an allowed
    /// filesystem type (every `fuse*` type included), when `device`
    /// contains `#` and no filesystem type is fixed, or when a network
    /// filesystem is given an option that picks a credential source of the
    /// host, a quote character, or (`ceph`) no `secret=` (see
    /// `validate_mount_args`).
    ///
    /// When `mount` can run `mount.cifs` (type `cifs`/`smb3`, or a
    /// `//server/share` device left to `mount`) the command starts with
    /// `MOUNT_CIFS_UNSET`; every other command is unchanged.
    pub fn build_mount_command(
        device: &str,
        mount_point: &str,
        fs_type: Option<&str>,
        options: Option<&str>,
    ) -> Result<String> {
        validate_mount_args(device, fs_type, options)?;
        let mut cmd = String::new();
        if reaches_mount_cifs(device, fs_type) {
            cmd.push_str(MOUNT_CIFS_UNSET);
        }
        cmd.push_str("mount");
        if let Some(t) = fs_type {
            cmd.push_str(" -t ");
            cmd.push_str(&shell_escape(t));
        }
        if let Some(o) = options {
            cmd.push_str(" -o ");
            cmd.push_str(&shell_escape(o));
        }
        // `--` so a device or mount point starting with '-' is an operand.
        cmd.push_str(" -- ");
        cmd.push_str(&shell_escape(device));
        cmd.push(' ');
        cmd.push_str(&shell_escape(mount_point));
        Ok(cmd)
    }

    /// Build umount command.
    #[must_use]
    pub fn build_umount_command(path: &str, lazy: bool) -> String {
        let escaped = shell_escape(path);
        if lazy {
            format!("umount -l -- {escaped}")
        } else {
            format!("umount -- {escaped}")
        }
    }

    /// Build LVM listing command (PV, VG, LV).
    #[must_use]
    pub fn build_lvm_list_command() -> String {
        "pvs --noheadings 2>/dev/null; echo '---'; vgs --noheadings 2>/dev/null; echo '---'; lvs --noheadings 2>/dev/null".to_string()
    }

    /// Build fdisk list command (read-only).
    #[must_use]
    pub fn build_fdisk_command(device: Option<&str>) -> String {
        if let Some(d) = device {
            format!("fdisk -l -- {}", shell_escape(d))
        } else {
            "fdisk -l".to_string()
        }
    }

    /// Build fstab read command.
    #[must_use]
    pub fn build_fstab_command() -> String {
        "cat /etc/fstab".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsblk_json() {
        let cmd = StorageCommandBuilder::build_lsblk_command(true);
        assert!(cmd.contains("-J"));
        assert!(cmd.starts_with("LC_ALL=C"));
    }

    #[test]
    fn test_lsblk_text() {
        let cmd = StorageCommandBuilder::build_lsblk_command(false);
        assert!(!cmd.contains("-J"));
        assert!(cmd.contains("lsblk"));
        // --list disables tree-drawing glyphs that break columnar parsing.
        assert!(cmd.contains("--list"));
        assert!(cmd.starts_with("LC_ALL=C"));
    }

    #[test]
    fn test_df_default() {
        let cmd = StorageCommandBuilder::build_df_command(None, false);
        assert!(cmd.contains("df -h"));
        assert!(cmd.contains("-T"));
        // LC_ALL=C ensures English column headers regardless of host locale.
        assert!(cmd.starts_with("LC_ALL=C"));
    }

    #[test]
    fn test_df_inodes() {
        let cmd = StorageCommandBuilder::build_df_command(None, true);
        assert!(cmd.contains("-i"));
    }

    #[test]
    fn test_df_path() {
        let cmd = StorageCommandBuilder::build_df_command(Some("/home"), false);
        assert!(cmd.contains("/home"));
    }

    #[test]
    fn test_mount() {
        let cmd = StorageCommandBuilder::build_mount_command(
            "/dev/sda1",
            "/mnt",
            Some("ext4"),
            Some("ro"),
        )
        .unwrap();
        assert!(cmd.contains("mount"));
        assert!(cmd.contains("-t"));
        assert!(cmd.contains("-o"));
    }

    #[test]
    fn test_umount() {
        let cmd = StorageCommandBuilder::build_umount_command("/mnt", false);
        assert!(cmd.contains("umount"));
        assert!(!cmd.contains("-l"));
    }

    #[test]
    fn test_umount_lazy() {
        let cmd = StorageCommandBuilder::build_umount_command("/mnt", true);
        assert!(cmd.contains("-l"));
    }

    #[test]
    fn test_lvm_list() {
        let cmd = StorageCommandBuilder::build_lvm_list_command();
        assert!(cmd.contains("pvs"));
        assert!(cmd.contains("vgs"));
        assert!(cmd.contains("lvs"));
    }

    #[test]
    fn test_fdisk_all() {
        let cmd = StorageCommandBuilder::build_fdisk_command(None);
        assert_eq!(cmd, "fdisk -l");
    }

    #[test]
    fn test_fdisk_device() {
        let cmd = StorageCommandBuilder::build_fdisk_command(Some("/dev/sda"));
        assert!(cmd.contains("/dev/sda"));
    }

    #[test]
    fn test_fstab() {
        let cmd = StorageCommandBuilder::build_fstab_command();
        assert!(cmd.contains("/etc/fstab"));
    }

    #[test]
    fn operands_come_after_end_of_options() {
        let df = StorageCommandBuilder::build_df_command(Some("-x"), false);
        assert!(df.ends_with("-T -- '-x'"), "{df}");
        let mount = StorageCommandBuilder::build_mount_command("-a", "-b", None, None).unwrap();
        assert_eq!(mount, "mount -- '-a' '-b'");
        let fdisk = StorageCommandBuilder::build_fdisk_command(Some("-x"));
        assert_eq!(fdisk, "fdisk -l -- '-x'");
    }

    #[test]
    fn umount_a_dashed_path_is_not_the_all_option() {
        assert_eq!(
            StorageCommandBuilder::build_umount_command("-a", true),
            "umount -l -- '-a'"
        );
        assert_eq!(
            StorageCommandBuilder::build_umount_command("-A", false),
            "umount -- '-A'"
        );
    }

    #[test]
    fn mount_refuses_fuse_and_subtype_fs_types() {
        for bad in [
            "fuse.sh",
            "fuse",
            "fuseblk",
            "fuse3",
            "ext4.x",
            "sh",
            "",
            "ext4 -o x",
        ] {
            let r =
                StorageCommandBuilder::build_mount_command("/tmp/p.sh", "/mnt", Some(bad), None);
            assert!(
                matches!(r, Err(BridgeError::CommandDenied { .. })),
                "fs_type {bad:?} must be refused: {r:?}"
            );
        }
    }

    #[test]
    fn mount_refuses_a_hash_in_the_device_when_no_type_is_fixed() {
        for fs in [
            None,
            Some("fuse"),
            Some("auto"),
            Some("none"),
            Some("ext4,auto"),
        ] {
            let r = StorageCommandBuilder::build_mount_command("sh#/tmp/p.sh", "/mnt", fs, None);
            assert!(r.is_err(), "device with '#' must be refused for {fs:?}");
        }
    }

    #[test]
    fn mount_accepts_a_hash_in_the_device_for_a_fixed_type() {
        let r =
            StorageCommandBuilder::build_mount_command("//srv/share#1", "/mnt", Some("cifs"), None);
        assert_eq!(
            r.unwrap(),
            "unset PASSWD PASSWD_FD PASSWD_FILE PASSWD2 PASSWD2_FD PASSWD2_FILE USER && \
             mount -t 'cifs' -- '//srv/share#1' '/mnt'"
        );
    }

    /// Bind mounts, overlay layers and the mount point are the tool's own
    /// job: only a program chosen through the type or the device is refused.
    #[test]
    fn mount_leaves_bind_overlay_and_mount_points_to_the_caller() {
        for (device, mp, fs, opts) in [
            ("/srv/a", "/mnt/b", None, Some("bind,ro")),
            ("/srv/a", "/mnt/b", None, Some("rbind")),
            (
                "overlay",
                "/mnt/merged",
                Some("overlay"),
                Some("lowerdir=/srv/l,upperdir=/srv/u,workdir=/srv/w"),
            ),
            ("/dev/sda1", "/boot/efi", Some("vfat"), None),
            (
                "/dev/sdb1",
                "/mnt/data",
                Some("ext4"),
                Some("ro,x-systemd.automount"),
            ),
        ] {
            let r = StorageCommandBuilder::build_mount_command(device, mp, fs, opts);
            assert!(r.is_ok(), "{device} {mp} {fs:?} {opts:?}: {r:?}");
        }
    }

    #[test]
    fn mount_still_accepts_ordinary_options() {
        let r = StorageCommandBuilder::build_mount_command(
            "/dev/sdb1",
            "/mnt/data",
            None,
            Some("ro,noexec,nosuid,uid=1000,x-systemd.automount"),
        );
        assert_eq!(
            r.unwrap(),
            "mount -o 'ro,noexec,nosuid,uid=1000,x-systemd.automount' -- '/dev/sdb1' '/mnt/data'"
        );
    }

    #[test]
    fn mount_accepts_kernel_and_fixed_helper_types_and_lists() {
        for fs in [
            "zfs",
            "virtiofs",
            "ntfs-3g",
            "cgroup2",
            "bpf",
            "debugfs",
            "tracefs",
            "hugetlbfs",
            "mqueue",
            "nilfs2",
            "bcachefs",
            "vboxsf",
            "devtmpfs",
            "ext4,xfs",
        ] {
            let r =
                StorageCommandBuilder::build_mount_command("tank/data", "/data", Some(fs), None);
            assert_eq!(
                r.unwrap(),
                format!("mount -t '{fs}' -- 'tank/data' '/data'")
            );
        }
    }

    #[test]
    fn mount_refuses_helper_selecting_types_in_a_list_and_glusterfs() {
        for bad in [
            "ext4,fuse.sh",
            "ext4,",
            ",ext4",
            "ext4, xfs",
            "fuse.sshfs",
            "sshfs",
            "glusterfs",
        ] {
            let r =
                StorageCommandBuilder::build_mount_command("/dev/sdb1", "/mnt", Some(bad), None);
            assert!(
                matches!(r, Err(BridgeError::CommandDenied { .. })),
                "fs_type {bad:?} must be refused: {r:?}"
            );
        }
    }

    #[test]
    fn mount_still_accepts_plain_filesystem_types() {
        for fs in ["ext4", "xfs", "nfs", "nfs4", "tmpfs", "vfat"] {
            let r = StorageCommandBuilder::build_mount_command(
                "//server/share",
                "/mnt",
                Some(fs),
                Some("ro"),
            );
            assert_eq!(
                r.unwrap(),
                format!("mount -t '{fs}' -o 'ro' -- '//server/share' '/mnt'")
            );
        }
    }

    // ── ambient passwords of mount.cifs ─────────────────────────────

    #[test]
    fn mount_cifs_drops_the_ambient_passwords_first() {
        for (device, fs, opts, want) in [
            (
                "//server/share",
                Some("cifs"),
                Some("ro"),
                "unset PASSWD PASSWD_FD PASSWD_FILE PASSWD2 PASSWD2_FD PASSWD2_FILE USER && \
                 mount -t 'cifs' -o 'ro' -- '//server/share' '/mnt'",
            ),
            (
                "//server/share",
                Some("smb3"),
                Some("username=svc,password=pw"),
                "unset PASSWD PASSWD_FD PASSWD_FILE PASSWD2 PASSWD2_FD PASSWD2_FILE USER && \
                 mount -t 'smb3' -o 'username=svc,password=pw' -- '//server/share' '/mnt'",
            ),
            (
                "//server/share",
                None,
                None,
                "unset PASSWD PASSWD_FD PASSWD_FILE PASSWD2 PASSWD2_FD PASSWD2_FILE USER && \
                 mount -- '//server/share' '/mnt'",
            ),
            (
                "//server/share",
                Some("auto"),
                Some("ro"),
                "unset PASSWD PASSWD_FD PASSWD_FILE PASSWD2 PASSWD2_FD PASSWD2_FILE USER && \
                 mount -t 'auto' -o 'ro' -- '//server/share' '/mnt'",
            ),
            (
                "//server/share",
                Some("ext4,cifs"),
                None,
                "unset PASSWD PASSWD_FD PASSWD_FILE PASSWD2 PASSWD2_FD PASSWD2_FILE USER && \
                 mount -t 'ext4,cifs' -- '//server/share' '/mnt'",
            ),
            (
                "/srv/x",
                Some("smb3"),
                None,
                "unset PASSWD PASSWD_FD PASSWD_FILE PASSWD2 PASSWD2_FD PASSWD2_FILE USER && \
                 mount -t 'smb3' -- '/srv/x' '/mnt'",
            ),
        ] {
            let r = StorageCommandBuilder::build_mount_command(device, "/mnt", fs, opts);
            assert_eq!(r.unwrap(), want, "{device} {fs:?} {opts:?}");
        }
    }

    /// `mnt_context_guess_srcpath_fstype` (util-linux libmount) reads a
    /// `host:path` device as `nfs`, so it never reaches `mount.cifs`; the
    /// types that name another helper or a kernel filesystem are unchanged.
    #[test]
    fn mount_without_mount_cifs_has_no_prefix() {
        for (device, fs, opts, want) in [
            (
                "server:/export",
                None,
                None,
                "mount -- 'server:/export' '/mnt'",
            ),
            (
                "server:/export",
                Some("auto"),
                Some("ro"),
                "mount -t 'auto' -o 'ro' -- 'server:/export' '/mnt'",
            ),
            (
                "server:/export",
                Some("nfs"),
                Some("vers=4.2"),
                "mount -t 'nfs' -o 'vers=4.2' -- 'server:/export' '/mnt'",
            ),
            (
                "server:/export",
                Some("nfs4"),
                None,
                "mount -t 'nfs4' -- 'server:/export' '/mnt'",
            ),
            (
                "/dev/sdb1",
                None,
                Some("ro"),
                "mount -o 'ro' -- '/dev/sdb1' '/mnt'",
            ),
            (
                "//server/share",
                Some("ext4"),
                None,
                "mount -t 'ext4' -- '//server/share' '/mnt'",
            ),
            (
                "//server/share",
                Some("nfs"),
                None,
                "mount -t 'nfs' -- '//server/share' '/mnt'",
            ),
            (
                "10.0.0.1:6789:/",
                Some("ceph"),
                Some("name=u,secret=AQ=="),
                "mount -t 'ceph' -o 'name=u,secret=AQ==' -- '10.0.0.1:6789:/' '/mnt'",
            ),
        ] {
            let r = StorageCommandBuilder::build_mount_command(device, "/mnt", fs, opts);
            assert_eq!(r.unwrap(), want, "{device} {fs:?} {opts:?}");
        }
    }

    // ── ceph needs its key in the call ──────────────────────────────

    #[test]
    fn mount_refuses_ceph_without_a_secret() {
        for opts in [
            "name=admin",
            "secret=",
            "secret",
            "ro",
            "",
            "name=admin,secret=",
            "SECRET=AQ==",
            "Secret=AQ==",
            " secret=AQ==",
            "secretkey=AQ==",
            "mon_addr=10.0.0.1,fsid=x",
            "secret=AQ==,secret=BQ==",
            "secret=AQ==,secret=",
        ] {
            for fs in ["ceph", "ext4,ceph", "ceph,nfs"] {
                let reason = mount_err("10.0.0.1:6789:/", Some(fs), opts);
                assert!(
                    reason.contains("exactly one secret= with a value"),
                    "{fs} {opts:?}: {reason}"
                );
                assert!(reason.contains("Pass secret= explicitly"), "{reason}");
            }
        }
    }

    #[test]
    fn mount_refuses_ceph_without_any_options() {
        for device in ["10.0.0.1:6789:/", "admin@fsid.cephfs=/"] {
            let r = StorageCommandBuilder::build_mount_command(device, "/mnt", Some("ceph"), None);
            match r {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.contains("Pass secret= explicitly"), "{reason}");
                }
                other => panic!("{device} must be refused: {other:?}"),
            }
        }
    }

    #[test]
    fn mount_refuses_the_ceph_file_sources_with_a_secret_present() {
        for opts in [
            "secret=AQ==,secretfile=/srv/x",
            "secretfile=/srv/x,secret=AQ==",
            "secret=AQ==,conf=/srv/x",
        ] {
            let reason = mount_err("10.0.0.1:6789:/", Some("ceph"), opts);
            assert!(reason.contains("CephX"), "{reason}");
        }
    }

    #[test]
    fn mount_accepts_ceph_with_one_secret() {
        for (opts, want) in [
            (
                "secret=AQ==",
                "mount -t 'ceph' -o 'secret=AQ==' -- '10.0.0.1:6789:/' '/mnt'",
            ),
            (
                "name=admin,secret=AQBx==,ro",
                "mount -t 'ceph' -o 'name=admin,secret=AQBx==,ro' -- '10.0.0.1:6789:/' '/mnt'",
            ),
        ] {
            let r = StorageCommandBuilder::build_mount_command(
                "10.0.0.1:6789:/",
                "/mnt",
                Some("ceph"),
                Some(opts),
            );
            assert_eq!(r.unwrap(), want);
        }
    }

    /// Autodetection maps `host:path` to `nfs` only (see `names_ceph`): no
    /// `secret=` is asked of a device left to `mount`.
    #[test]
    fn mount_does_not_ask_a_secret_of_an_autodetected_device() {
        for (device, fs) in [
            ("server:/export", None),
            ("server:/export", Some("auto")),
            ("10.0.0.1:6789:/", None),
            ("server:/export", Some("nfs")),
        ] {
            let r = StorageCommandBuilder::build_mount_command(device, "/mnt", fs, Some("ro"));
            assert!(r.is_ok(), "{device} {fs:?}: {r:?}");
        }
    }

    // ── quotes in the options of a network filesystem ───────────────

    #[test]
    fn mount_refuses_quotes_in_the_options_of_a_network_filesystem() {
        for (device, fs) in [
            ("server:/export", Some("nfs")),
            ("server:/export", Some("nfs4")),
            ("//server/share", Some("cifs")),
            ("//server/share", Some("smb3")),
            ("10.0.0.1:6789:/", Some("ceph")),
            ("server:/export", None),
            ("//server/share", None),
            ("//server/share", Some("auto")),
        ] {
            for opts in [
                "sec=\"sys\"",
                "\"sec\"=sys",
                "ro,\"xprtsec\"=none",
                "'ro'",
                "username=u,password='p'",
                "\"secretfile\"=/srv/x",
                "name=u,\"secretfile\"=/srv/x,secret=AQ==",
                "ro,x=\"a,b\"",
            ] {
                let reason = mount_err(device, fs, opts);
                assert!(
                    reason.contains("quote character"),
                    "{device} {fs:?} {opts}: {reason}"
                );
                assert!(!reason.contains("password"), "{reason}");
            }
        }
    }

    #[test]
    fn mount_leaves_quotes_alone_off_the_network_filesystems() {
        for (device, fs, opts) in [
            (
                "/dev/sdb1",
                Some("ext4"),
                "ro,x-systemd.device-timeout=\"5\"",
            ),
            ("/dev/sdb1", None, "'ro'"),
            ("/srv/x", None, "bind,\"ro\""),
            ("tank/data", Some("zfs"), "\"ro\""),
        ] {
            let r = StorageCommandBuilder::build_mount_command(device, "/mnt", fs, Some(opts));
            assert!(r.is_ok(), "{device} {fs:?} {opts}: {r:?}");
        }
    }

    // ── credential-source options of network filesystems ────────────

    fn mount_err(device: &str, fs: Option<&str>, opts: &str) -> String {
        match StorageCommandBuilder::build_mount_command(device, "/mnt", fs, Some(opts)) {
            Err(BridgeError::CommandDenied { reason }) => reason,
            other => panic!("{device} {fs:?} {opts:?} must be refused: {other:?}"),
        }
    }

    #[test]
    fn mount_refuses_cifs_credential_sources() {
        for opts in [
            "credentials=/etc/samba/creds",
            "cred=/root/.smbcreds",
            "ro,credentials=/x",
            "CREDENTIALS=/x",
            "ro, Cred=/x",
            "username=a,cred=/x",
            "cruid=0",
            "multiuser",
            "ro,multiuser,sec=ntlmssp",
            "upcall_target=mount",
            "sec=krb5",
            "sec=krb5i",
            "sec=krb5p",
            "SEC=KRB5",
            "sec = krb5i",
            "vers=3.0,sec=krb5",
        ] {
            for fs in [Some("cifs"), Some("smb3")] {
                let reason = mount_err("//server/share", fs, opts);
                assert!(reason.contains("Pass username= and password="), "{reason}");
            }
        }
    }

    #[test]
    fn mount_refuses_the_same_options_when_mount_picks_a_network_type() {
        for fs in [None, Some("auto"), Some("ext4,auto")] {
            for (device, opts) in [
                ("//server/share", "credentials=/x"),
                ("//server/share", "sec=krb5"),
                ("//server/share", "multiuser"),
                ("server:/export", "sec=krb5p"),
                ("server:/export", "xprtsec=mtls"),
                ("10.0.0.1:/", "secretfile=/etc/ceph/key"),
            ] {
                let reason = mount_err(device, fs, opts);
                assert!(reason.contains(opts.split('=').next().unwrap()), "{reason}");
            }
        }
    }

    #[test]
    fn mount_refuses_none_and_an_untyped_at_device_for_a_network_device() {
        for (device, fs) in [
            ("//server/share", Some("none")),
            ("server:/export", Some("none")),
            ("10.0.0.1:6789:/", Some("ext4,none")),
            ("admin@fsid.cephfs=/", Some("none")),
        ] {
            let reason = mount_err(device, fs, "ro");
            assert!(
                reason.contains("fs_type 'none' is refused"),
                "{device}: {reason}"
            );
        }
        for fs in [None, Some("auto")] {
            let reason = mount_err("admin@fsid.cephfs=/", fs, "mon_addr=10.0.0.1,conf=/srv/x");
            assert!(reason.contains("needs fs_type"), "{fs:?}: {reason}");
        }
        // A local device keeps `none` (bind and special mounts).
        assert_eq!(
            StorageCommandBuilder::build_mount_command(
                "/srv/a",
                "/mnt",
                Some("none"),
                Some("bind")
            )
            .unwrap(),
            "mount -t 'none' -o 'bind' -- '/srv/a' '/mnt'"
        );
        // A bind or move mount keeps `none` whatever the path holds.
        for (device, opts) in [
            ("/srv/backup@2026", "bind"),
            ("/srv/a:b", "rbind,ro"),
            ("/srv/x@y", "move"),
        ] {
            for fs in [Some("none"), None] {
                assert!(
                    StorageCommandBuilder::build_mount_command(device, "/mnt", fs, Some(opts))
                        .is_ok(),
                    "{device} {fs:?} {opts}"
                );
            }
        }
    }

    #[test]
    fn mount_refuses_a_ceph_secret_that_mount_ceph_would_not_keep() {
        let forty = "A".repeat(40);
        let forty_one = "A".repeat(41);
        for opts in [
            format!("name=admin,secret={forty_one}"),
            format!("secret={}", "A".repeat(60)),
            "secret=<hidden>".to_string(),
            "secret=AQ==;x".to_string(),
            "secret=AQ== ".to_string(),
        ] {
            let reason = mount_err("10.0.0.1:6789:/", Some("ceph"), &opts);
            assert!(reason.contains("a CephX key"), "{opts}: {reason}");
        }
        for opts in [
            "secret=AQ==,key=client.admin",
            "name=u,secret=AQ==,KEY=client.x",
        ] {
            let reason = mount_err("10.0.0.1:6789:/", Some("ceph"), opts);
            assert!(reason.contains("CephX"), "{opts}: {reason}");
        }
        assert_eq!(
            StorageCommandBuilder::build_mount_command(
                "10.0.0.1:6789:/",
                "/mnt",
                Some("ceph"),
                Some(&format!("name=u,secret={forty}")),
            )
            .unwrap(),
            format!("mount -t 'ceph' -o 'name=u,secret={forty}' -- '10.0.0.1:6789:/' '/mnt'")
        );
    }

    #[test]
    fn mount_refuses_nfs_kerberos_and_mtls() {
        for fs in ["nfs", "nfs4"] {
            for opts in [
                "sec=krb5",
                "sec=krb5i",
                "sec=krb5p",
                "sec=sys:krb5",
                "sec=krb5:krb5i:krb5p",
                "sec=KRB5P",
                "sec=lkey",
                "sec=spkm3",
                "vers=4.2,sec=krb5,ro",
                "xprtsec=mtls",
                "ro,XPRTSEC=mtls",
            ] {
                let reason = mount_err("server:/export", Some(fs), opts);
                assert!(reason.contains("must not use"), "{opts}: {reason}");
            }
        }
    }

    #[test]
    fn mount_refuses_ceph_key_and_config_files() {
        for opts in [
            "secretfile=/etc/ceph/admin.secret",
            "name=admin,conf=/etc/ceph/c.conf",
        ] {
            let reason = mount_err("10.0.0.1:6789:/", Some("ceph"), opts);
            assert!(reason.contains("CephX"), "{reason}");
        }
    }

    #[test]
    fn mount_error_names_the_option_and_not_the_rest() {
        let reason = mount_err("//server/share", Some("cifs"), "username=u,cred=/etc/creds");
        assert!(
            reason.starts_with("options 'cred=/etc/creds' reads the credentials"),
            "{reason}"
        );
        assert!(!reason.contains("username=u"), "{reason}");
    }

    #[test]
    fn mount_keeps_explicit_credentials_and_other_network_options() {
        for (device, fs, opts, want) in [
            (
                "//server/share",
                Some("cifs"),
                "username=svc,password=s3cret,domain=CORP,vers=3.1.1",
                "unset PASSWD PASSWD_FD PASSWD_FILE PASSWD2 PASSWD2_FD PASSWD2_FILE USER && \
                 mount -t 'cifs' -o 'username=svc,password=s3cret,domain=CORP,vers=3.1.1' \
                 -- '//server/share' '/mnt'",
            ),
            (
                "//server/share",
                Some("smb3"),
                "user=svc,pass=x,sec=ntlmssp,guest,ro",
                "unset PASSWD PASSWD_FD PASSWD_FILE PASSWD2 PASSWD2_FD PASSWD2_FILE USER && \
                 mount -t 'smb3' -o 'user=svc,pass=x,sec=ntlmssp,guest,ro' \
                 -- '//server/share' '/mnt'",
            ),
            (
                "//server/share",
                Some("cifs"),
                "sec=none,seal,soft",
                "unset PASSWD PASSWD_FD PASSWD_FILE PASSWD2 PASSWD2_FD PASSWD2_FILE USER && \
                 mount -t 'cifs' -o 'sec=none,seal,soft' -- '//server/share' '/mnt'",
            ),
            (
                "server:/export",
                Some("nfs"),
                "sec=sys,vers=4.1,ro,xprtsec=tls",
                "mount -t 'nfs' -o 'sec=sys,vers=4.1,ro,xprtsec=tls' -- 'server:/export' '/mnt'",
            ),
            (
                "server:/export",
                Some("nfs4"),
                "sec=none,xprtsec=none",
                "mount -t 'nfs4' -o 'sec=none,xprtsec=none' -- 'server:/export' '/mnt'",
            ),
            (
                "10.0.0.1:6789:/",
                Some("ceph"),
                "name=u,secret=AQ==",
                "mount -t 'ceph' -o 'name=u,secret=AQ==' -- '10.0.0.1:6789:/' '/mnt'",
            ),
        ] {
            let r = StorageCommandBuilder::build_mount_command(device, "/mnt", fs, Some(opts));
            assert_eq!(r.unwrap(), want);
        }
    }

    #[test]
    fn mount_does_not_apply_network_rules_to_local_filesystems() {
        for (device, fs, opts) in [
            (
                "/dev/sdb1",
                Some("ext4"),
                "cred=/x,multiuser,sec=krb5,secretfile=/y",
            ),
            ("/dev/sdb1", None, "credentials=/x"),
            ("/dev/sdb1", Some("auto"), "sec=krb5"),
            ("tank/data", Some("zfs"), "conf=/x"),
            ("/srv/a", None, "bind,cruid=0"),
            ("//server/share", Some("cifs"), "ro"),
            ("server:/export", Some("nfs"), "credentials=/x"),
            (
                "server:/export",
                Some("nfs"),
                "secretfile=/x,conf=/y,cruid=0",
            ),
            ("//server/share", Some("cifs"), "xprtsec=mtls,secretfile=/x"),
        ] {
            let r = StorageCommandBuilder::build_mount_command(device, "/mnt", fs, Some(opts));
            assert!(r.is_ok(), "{device} {fs:?} {opts:?}: {r:?}");
        }
    }

    #[test]
    fn mount_without_options_is_unchanged_for_a_host_path_device() {
        let r = StorageCommandBuilder::build_mount_command("server:/export", "/mnt", None, None);
        assert_eq!(r.unwrap(), "mount -- 'server:/export' '/mnt'");
    }
}
