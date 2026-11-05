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

/// Refuse the `mount` arguments that would make `mount` run a program the
/// caller chose.
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
///   to run, and only those cases can still end in a FUSE type.
fn validate_mount_args(device: &str, fs_type: Option<&str>) -> Result<()> {
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
    Ok(())
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
    /// filesystem type (every `fuse*` type included), or when `device`
    /// contains `#` and no filesystem type is fixed.
    pub fn build_mount_command(
        device: &str,
        mount_point: &str,
        fs_type: Option<&str>,
        options: Option<&str>,
    ) -> Result<String> {
        validate_mount_args(device, fs_type)?;
        let mut cmd = String::from("mount");
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
        assert_eq!(r.unwrap(), "mount -t 'cifs' -- '//srv/share#1' '/mnt'");
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
            "ceph",
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
        for fs in [
            "ext4", "xfs", "nfs", "nfs4", "cifs", "tmpfs", "auto", "vfat",
        ] {
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
}
