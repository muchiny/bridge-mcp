//! Terraform Command Builder
//!
//! Builds Terraform CLI commands for remote execution via SSH.
//! Supports init, plan, apply, state, and output operations.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate that a Terraform directory path contains only safe characters.
/// Allows: alphanumeric, slashes, hyphens, underscores, dots.
pub fn validate_terraform_dir(dir: &str) -> Result<()> {
    if dir.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Terraform directory cannot be empty".to_string(),
        });
    }
    if dir.split('/').any(|component| component == "..") {
        return Err(BridgeError::CommandDenied {
            reason: "Path traversal ('..') is not allowed in Terraform directory paths".to_string(),
        });
    }
    Ok(())
}

/// Validate the `out` file of `terraform plan`.
///
/// Terraform replaces whatever file the path names, so `out` must be a plain
/// file name that lands inside the working directory: no `/` or `\` (no
/// absolute path, no sub-directory, no escape), no leading `-` (an option) and
/// neither `.` nor `..`.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] naming `out` when the name is empty,
/// is `.` or `..`, starts with `-`, or contains `/` or `\`.
pub fn validate_plan_out(out: &str) -> Result<()> {
    super::shell::refuse_option_like("out", out)?;
    if out.is_empty() || out == "." || out == ".." || out.contains(['/', '\\']) {
        return Err(BridgeError::CommandDenied {
            reason: "'out' must be a plain file name inside the Terraform directory: no '/' or \
                     '\\', and not empty, '.' or '..'"
                .to_string(),
        });
    }
    Ok(())
}

/// Builds Terraform CLI commands for remote execution.
pub struct TerraformCommandBuilder;

impl TerraformCommandBuilder {
    /// Check the arguments of `terraform plan` that are refused rather than
    /// escaped. Run by the tool's `validate` (so the refusal is audited) and
    /// again by [`Self::build_plan_command`].
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `dir` or `out` is refused.
    pub fn validate_plan_args(dir: &str, out: Option<&str>) -> Result<()> {
        validate_terraform_dir(dir)?;
        out.map_or(Ok(()), validate_plan_out)
    }

    /// Check the arguments of `terraform apply` that are refused rather than
    /// escaped (see [`Self::validate_plan_args`]).
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `dir` is refused or `plan_file`
    /// starts with `-`.
    pub fn validate_apply_args(dir: &str, plan_file: Option<&str>) -> Result<()> {
        validate_terraform_dir(dir)?;
        // A leading '-' would be read as an option (`-destroy`, `-auto-approve`).
        plan_file.map_or(Ok(()), |pf| {
            super::shell::refuse_option_like("plan_file", pf)
        })
    }

    /// Check the arguments of `terraform state` that are refused rather than
    /// escaped (see [`Self::validate_plan_args`]).
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `dir` is refused, the
    /// subcommand is not allowed or `args` starts with `-`.
    pub fn validate_state_args(dir: &str, subcommand: &str, args: Option<&str>) -> Result<()> {
        validate_terraform_dir(dir)?;
        Self::validate_state_subcommand(subcommand)?;
        args.map_or(Ok(()), |a| super::shell::refuse_option_like("args", a))
    }

    /// Check the arguments of `terraform output` that are refused rather than
    /// escaped (see [`Self::validate_plan_args`]).
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `dir` is refused or `name`
    /// starts with `-`.
    pub fn validate_output_args(dir: &str, name: Option<&str>) -> Result<()> {
        validate_terraform_dir(dir)?;
        name.map_or(Ok(()), |n| super::shell::refuse_option_like("name", n))
    }

    /// Build a `terraform init` command.
    ///
    /// Constructs: `cd -- {dir} && terraform init [-backend=false] [-upgrade]`
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `dir` contains unsafe characters.
    pub fn build_init_command(dir: &str, backend: bool, upgrade: bool) -> Result<String> {
        validate_terraform_dir(dir)?;
        let mut cmd = format!("cd -- {} && terraform init", shell_escape(dir));

        if !backend {
            cmd.push_str(" -backend=false");
        }

        if upgrade {
            cmd.push_str(" -upgrade");
        }

        Ok(cmd)
    }

    /// Build a `terraform plan` command.
    ///
    /// Constructs: `cd -- {dir} && terraform plan [-var {k=v}]... [-var-file {f}]
    /// [-target {t}]... [-out {file}] [-no-color]`
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `dir` contains unsafe characters
    /// or `out` is not a plain file name (see [`validate_plan_out`]).
    #[allow(clippy::too_many_arguments)]
    pub fn build_plan_command(
        dir: &str,
        vars: Option<&[String]>,
        var_file: Option<&str>,
        targets: Option<&[String]>,
        out: Option<&str>,
        destroy: bool,
    ) -> Result<String> {
        Self::validate_plan_args(dir, out)?;
        let mut cmd = format!(
            "cd -- {} && terraform plan -no-color -input=false",
            shell_escape(dir)
        );

        if let Some(v) = vars {
            for var in v {
                let _ = write!(cmd, " -var {}", shell_escape(var));
            }
        }

        if let Some(vf) = var_file {
            let _ = write!(cmd, " -var-file={}", shell_escape(vf));
        }

        if let Some(t) = targets {
            for target in t {
                let _ = write!(cmd, " -target={}", shell_escape(target));
            }
        }

        if let Some(o) = out {
            let _ = write!(cmd, " -out={}", shell_escape(o));
        }

        if destroy {
            cmd.push_str(" -destroy");
        }

        Ok(cmd)
    }

    /// Build a `terraform apply` command.
    ///
    /// Constructs: `cd -- {dir} && terraform apply [-auto-approve] [-var {k=v}]...
    /// [-var-file {f}] [-target {t}]... [plan_file] [-no-color]`
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `dir` contains unsafe characters.
    #[allow(clippy::too_many_arguments)]
    pub fn build_apply_command(
        dir: &str,
        auto_approve: bool,
        vars: Option<&[String]>,
        var_file: Option<&str>,
        targets: Option<&[String]>,
        plan_file: Option<&str>,
    ) -> Result<String> {
        Self::validate_apply_args(dir, plan_file)?;
        let mut cmd = format!(
            "cd -- {} && terraform apply -no-color -input=false",
            shell_escape(dir)
        );

        if auto_approve {
            cmd.push_str(" -auto-approve");
        }

        if let Some(v) = vars {
            for var in v {
                let _ = write!(cmd, " -var {}", shell_escape(var));
            }
        }

        if let Some(vf) = var_file {
            let _ = write!(cmd, " -var-file={}", shell_escape(vf));
        }

        if let Some(t) = targets {
            for target in t {
                let _ = write!(cmd, " -target={}", shell_escape(target));
            }
        }

        if let Some(pf) = plan_file {
            let _ = write!(cmd, " {}", shell_escape(pf));
        }

        Ok(cmd)
    }

    /// Validate a `terraform state` subcommand.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the subcommand is not allowed.
    pub fn validate_state_subcommand(subcommand: &str) -> Result<()> {
        const ALLOWED: &[&str] = &["list", "show", "pull"];
        if ALLOWED.contains(&subcommand) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Terraform state subcommand '{}' is not allowed. Allowed: {}",
                    subcommand,
                    ALLOWED.join(", ")
                ),
            })
        }
    }

    /// Build a `terraform state` command.
    ///
    /// Constructs: `cd -- {dir} && terraform state {subcommand} [{args}]`
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `dir` contains unsafe characters
    /// or the subcommand is not allowed.
    pub fn build_state_command(dir: &str, subcommand: &str, args: Option<&str>) -> Result<String> {
        Self::validate_state_args(dir, subcommand, args)?;
        let mut cmd = format!(
            "cd -- {} && terraform state {}",
            shell_escape(dir),
            shell_escape(subcommand)
        );

        if let Some(a) = args {
            let _ = write!(cmd, " {}", shell_escape(a));
        }

        Ok(cmd)
    }

    /// Build a `terraform output` command.
    ///
    /// Constructs: `cd -- {dir} && terraform output [-json] [{name}]`
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `dir` contains unsafe characters.
    pub fn build_output_command(dir: &str, name: Option<&str>, json: bool) -> Result<String> {
        Self::validate_output_args(dir, name)?;
        let mut cmd = format!("cd -- {} && terraform output", shell_escape(dir));

        if json {
            cmd.push_str(" -json");
        }

        if let Some(n) = name {
            let _ = write!(cmd, " {}", shell_escape(n));
        }

        Ok(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_terraform_dir_valid() {
        assert!(validate_terraform_dir("/opt/infra").is_ok());
        assert!(validate_terraform_dir("/home/user/terraform").is_ok());
        assert!(validate_terraform_dir("./modules/vpc").is_ok());
    }

    #[test]
    fn test_validate_terraform_dir_invalid() {
        assert!(validate_terraform_dir("").is_err());
        assert!(validate_terraform_dir("/opt/../etc").is_err());
        assert!(validate_terraform_dir("../../etc").is_err());
    }

    #[test]
    fn test_init_default() {
        let cmd = TerraformCommandBuilder::build_init_command("/opt/infra", true, false).unwrap();
        assert!(cmd.starts_with("cd -- '/opt/infra' && terraform init"));
        assert!(!cmd.contains("-backend=false"));
    }

    #[test]
    fn test_init_no_backend() {
        let cmd = TerraformCommandBuilder::build_init_command("/opt/infra", false, false).unwrap();
        assert!(cmd.contains("-backend=false"));
    }

    #[test]
    fn test_init_upgrade() {
        let cmd = TerraformCommandBuilder::build_init_command("/opt/infra", true, true).unwrap();
        assert!(cmd.contains("-upgrade"));
    }

    #[test]
    fn test_plan_minimal() {
        let cmd = TerraformCommandBuilder::build_plan_command(
            "/opt/infra",
            None,
            None,
            None,
            None,
            false,
        )
        .unwrap();
        assert!(cmd.contains("terraform plan -no-color -input=false"));
    }

    #[test]
    fn test_plan_with_vars() {
        let vars = vec!["region=us-east-1".to_string()];
        let cmd = TerraformCommandBuilder::build_plan_command(
            "/opt/infra",
            Some(&vars),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        assert!(cmd.contains("-var 'region=us-east-1'"));
    }

    #[test]
    fn test_plan_destroy() {
        let cmd =
            TerraformCommandBuilder::build_plan_command("/opt/infra", None, None, None, None, true)
                .unwrap();
        assert!(cmd.contains("-destroy"));
    }

    #[test]
    fn test_apply_auto_approve() {
        let cmd = TerraformCommandBuilder::build_apply_command(
            "/opt/infra",
            true,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(cmd.contains("-auto-approve"));
    }

    #[test]
    fn test_apply_plan_file() {
        let cmd = TerraformCommandBuilder::build_apply_command(
            "/opt/infra",
            true,
            None,
            None,
            None,
            Some("plan.out"),
        )
        .unwrap();
        assert!(cmd.contains("'plan.out'"));
    }

    #[test]
    fn test_state_list() {
        let cmd = TerraformCommandBuilder::build_state_command("/opt/infra", "list", None).unwrap();
        assert!(cmd.contains("terraform state 'list'"));
    }

    #[test]
    fn test_state_show() {
        let cmd = TerraformCommandBuilder::build_state_command(
            "/opt/infra",
            "show",
            Some("aws_instance.web"),
        )
        .unwrap();
        assert!(cmd.contains("state 'show'"));
        assert!(cmd.contains("'aws_instance.web'"));
    }

    #[test]
    fn test_output_default() {
        let cmd = TerraformCommandBuilder::build_output_command("/opt/infra", None, false).unwrap();
        assert!(cmd.contains("terraform output"));
        assert!(!cmd.contains("-json"));
    }

    #[test]
    fn test_output_json() {
        let cmd = TerraformCommandBuilder::build_output_command("/opt/infra", None, true).unwrap();
        assert!(cmd.contains("-json"));
    }

    #[test]
    fn test_output_specific() {
        let cmd = TerraformCommandBuilder::build_output_command("/opt/infra", Some("vpc_id"), true)
            .unwrap();
        assert!(cmd.contains("-json"));
        assert!(cmd.contains("'vpc_id'"));
    }

    // ============== Shell Injection Prevention ==============

    #[test]
    fn test_plan_injection_in_var() {
        let vars = vec!["region=$(whoami)".to_string()];
        let cmd = TerraformCommandBuilder::build_plan_command(
            "/opt/infra",
            Some(&vars),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        assert!(cmd.contains("-var 'region=$(whoami)'"));
    }

    #[test]
    fn test_plan_injection_in_var_file() {
        let cmd = TerraformCommandBuilder::build_plan_command(
            "/opt/infra",
            None,
            Some("/tmp/vars; rm -rf /"),
            None,
            None,
            false,
        )
        .unwrap();
        assert!(cmd.contains("-var-file='/tmp/vars; rm -rf /'"));
    }

    #[test]
    fn test_plan_injection_in_target() {
        let targets = vec!["module.$(id)".to_string()];
        let cmd = TerraformCommandBuilder::build_plan_command(
            "/opt/infra",
            None,
            None,
            Some(&targets),
            None,
            false,
        )
        .unwrap();
        assert!(cmd.contains("-target='module.$(id)'"));
    }

    #[test]
    fn test_apply_injection_in_plan_file() {
        let cmd = TerraformCommandBuilder::build_apply_command(
            "/opt/infra",
            true,
            None,
            None,
            None,
            Some("plan.out; cat /etc/shadow"),
        )
        .unwrap();
        assert!(cmd.contains("'plan.out; cat /etc/shadow'"));
    }

    #[test]
    fn test_state_injection_in_subcommand_rejected() {
        let result =
            TerraformCommandBuilder::build_state_command("/opt/infra", "list; whoami", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_state_rm_rejected() {
        let result = TerraformCommandBuilder::build_state_command(
            "/opt/infra",
            "rm",
            Some("aws_instance.web"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_state_push_rejected() {
        let result = TerraformCommandBuilder::build_state_command("/opt/infra", "push", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_state_injection_in_args() {
        let cmd = TerraformCommandBuilder::build_state_command(
            "/opt/infra",
            "show",
            Some("aws_instance.web && cat /etc/passwd"),
        )
        .unwrap();
        assert!(cmd.contains("'aws_instance.web && cat /etc/passwd'"));
    }

    // ============== All-Options Combination ==============

    #[test]
    fn test_plan_all_options() {
        let vars = vec!["region=us-east-1".to_string(), "env=prod".to_string()];
        let targets = vec!["module.vpc".to_string(), "module.rds".to_string()];
        let cmd = TerraformCommandBuilder::build_plan_command(
            "/opt/infra",
            Some(&vars),
            Some("/tmp/vars.tfvars"),
            Some(&targets),
            Some("plan.out"),
            true,
        )
        .unwrap();
        assert!(cmd.contains("-var 'region=us-east-1'"));
        assert!(cmd.contains("-var 'env=prod'"));
        assert!(cmd.contains("-var-file='/tmp/vars.tfvars'"));
        assert!(cmd.contains("-target='module.vpc'"));
        assert!(cmd.contains("-target='module.rds'"));
        assert!(cmd.contains("-out='plan.out'"));
        assert!(cmd.contains("-destroy"));
    }

    #[test]
    fn test_apply_all_options() {
        let vars = vec!["env=staging".to_string()];
        let targets = vec!["module.vpc".to_string()];
        let cmd = TerraformCommandBuilder::build_apply_command(
            "/opt/infra",
            true,
            Some(&vars),
            Some("/tmp/vars.tfvars"),
            Some(&targets),
            Some("plan.out"),
        )
        .unwrap();
        assert!(cmd.contains("-auto-approve"));
        assert!(cmd.contains("-var 'env=staging'"));
        assert!(cmd.contains("-var-file='/tmp/vars.tfvars'"));
        assert!(cmd.contains("-target='module.vpc'"));
        assert!(cmd.contains("'plan.out'"));
    }

    #[test]
    fn test_init_all_options() {
        let cmd = TerraformCommandBuilder::build_init_command("/opt/infra", false, true).unwrap();
        assert!(cmd.contains("-backend=false"));
        assert!(cmd.contains("-upgrade"));
    }

    // ============== Edge Cases ==============

    #[test]
    fn test_plan_empty_vars_array() {
        let vars: Vec<String> = vec![];
        let cmd = TerraformCommandBuilder::build_plan_command(
            "/opt/infra",
            Some(&vars),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        assert!(!cmd.contains("-var "));
    }

    #[test]
    fn test_plan_empty_targets_array() {
        let targets: Vec<String> = vec![];
        let cmd = TerraformCommandBuilder::build_plan_command(
            "/opt/infra",
            None,
            None,
            Some(&targets),
            None,
            false,
        )
        .unwrap();
        assert!(!cmd.contains("-target="));
    }

    #[test]
    fn test_plan_multiple_vars() {
        let vars = vec!["a=1".to_string(), "b=2".to_string(), "c=3".to_string()];
        let cmd = TerraformCommandBuilder::build_plan_command(
            "/opt/infra",
            Some(&vars),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        assert!(cmd.contains("-var 'a=1'"));
        assert!(cmd.contains("-var 'b=2'"));
        assert!(cmd.contains("-var 'c=3'"));
    }

    #[test]
    fn test_apply_no_auto_approve() {
        let cmd = TerraformCommandBuilder::build_apply_command(
            "/opt/infra",
            false,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!cmd.contains("-auto-approve"));
    }

    #[test]
    fn test_apply_minimal() {
        let cmd = TerraformCommandBuilder::build_apply_command(
            "/opt/infra",
            false,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            cmd,
            "cd -- '/opt/infra' && terraform apply -no-color -input=false"
        );
    }

    #[test]
    fn test_output_name_with_special_chars() {
        let cmd = TerraformCommandBuilder::build_output_command(
            "/opt/infra",
            Some("vpc-id.value"),
            false,
        )
        .unwrap();
        assert!(cmd.contains("'vpc-id.value'"));
    }

    // ============== validate_terraform_dir Additional Tests ==============

    #[test]
    fn test_validate_terraform_dir_with_tilde() {
        assert!(validate_terraform_dir("~/terraform").is_ok());
    }

    #[test]
    fn test_validate_terraform_dir_dot_in_component() {
        assert!(validate_terraform_dir("/opt/v1.0/infra").is_ok());
        assert!(validate_terraform_dir("./current").is_ok());
    }

    #[test]
    fn test_validate_terraform_dir_traversal_in_middle() {
        assert!(validate_terraform_dir("/opt/infra/../secrets").is_err());
    }

    #[test]
    fn test_validate_terraform_dir_error_message() {
        let result = validate_terraform_dir("/opt/../etc");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains(".."));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    // ============== Option injection ==============

    #[test]
    fn test_dir_goes_after_double_dash_in_cd() {
        let cmd = TerraformCommandBuilder::build_output_command("-x", None, false).unwrap();
        assert_eq!(cmd, "cd -- '-x' && terraform output");
    }

    #[test]
    fn test_apply_refuses_option_shaped_plan_file() {
        let err = TerraformCommandBuilder::build_apply_command(
            "/opt/infra",
            false,
            None,
            None,
            None,
            Some("-auto-approve"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("'plan_file'"), "{err}");
    }

    #[test]
    fn test_plan_out_must_be_a_plain_file_name() {
        for out in [
            "/home/deploy/.ssh/authorized_keys",
            "/tmp/plan.out",
            "sub/plan.out",
            "./plan.out",
            "../plan.out",
            "a\\b",
            "\\\\host\\share",
            "-out",
            "-",
            "",
            ".",
            "..",
        ] {
            let err = TerraformCommandBuilder::build_plan_command(
                "/opt/infra",
                None,
                None,
                None,
                Some(out),
                false,
            )
            .expect_err(out);
            assert!(err.to_string().contains("'out'"), "{out}: {err}");
            TerraformCommandBuilder::validate_plan_args("/opt/infra", Some(out)).expect_err(out);
        }
    }

    #[test]
    fn test_plan_out_plain_names_pass() {
        for out in [
            "plan.out",
            "tfplan",
            "my plan.tfplan",
            "a-b_c.1",
            "..plan",
            ".plan",
        ] {
            let cmd = TerraformCommandBuilder::build_plan_command(
                "/opt/infra",
                None,
                None,
                None,
                Some(out),
                false,
            )
            .expect(out);
            assert!(cmd.contains(&format!("-out='{out}'")), "{cmd}");
        }
    }

    #[test]
    fn test_validate_args_refuse_what_the_builders_refuse() {
        let b = TerraformCommandBuilder::validate_apply_args("/opt/infra", Some("-destroy"));
        assert!(b.unwrap_err().to_string().contains("'plan_file'"));
        TerraformCommandBuilder::validate_apply_args("/opt/infra", Some("plan.out")).unwrap();
        TerraformCommandBuilder::validate_apply_args("/opt/infra", None).unwrap();
        TerraformCommandBuilder::validate_apply_args("../x", None).unwrap_err();

        let b =
            TerraformCommandBuilder::validate_state_args("/opt/infra", "show", Some("-state=/x"));
        assert!(b.unwrap_err().to_string().contains("'args'"));
        TerraformCommandBuilder::validate_state_args("/opt/infra", "rm", None).unwrap_err();
        TerraformCommandBuilder::validate_state_args("/opt/infra", "show", Some("aws_instance.a"))
            .unwrap();

        let b = TerraformCommandBuilder::validate_output_args("/opt/infra", Some("-raw"));
        assert!(b.unwrap_err().to_string().contains("'name'"));
        TerraformCommandBuilder::validate_output_args("/opt/infra", Some("vpc_id")).unwrap();
        TerraformCommandBuilder::validate_output_args("/opt/infra", None).unwrap();
    }

    #[test]
    fn test_output_refuses_option_shaped_name() {
        let err = TerraformCommandBuilder::build_output_command("/opt/infra", Some("-raw"), false)
            .unwrap_err();
        assert!(err.to_string().contains("'name'"), "{err}");
    }

    #[test]
    fn test_state_refuses_option_shaped_args() {
        let err =
            TerraformCommandBuilder::build_state_command("/opt/infra", "show", Some("-state=/x"))
                .unwrap_err();
        assert!(err.to_string().contains("'args'"), "{err}");
    }
}
