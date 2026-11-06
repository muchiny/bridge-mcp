//! Cloud Provider Command Builder
//!
//! Builds cloud CLI commands (AWS, GCP, Azure) for remote execution via SSH.
//! Supports AWS CLI invocation, cloud metadata detection, tag retrieval,
//! and cost analysis.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// What to use instead of a refused AWS operation, for the error text.
const AWS_USE_INSTEAD: &str = "ssh_aws_cli runs with the AWS identity of the host, never \
    returns that identity or a credential derived from it, and does not read or write files \
    of the host; run the command in an operator session on the host (ssh_exec, under its own \
    policy) if you really need it";

/// Services that read or write the identity of the host: `configure` (keys,
/// profiles, `export-credentials`), `sso` and `sso-oidc` (tokens and role
/// credentials), `login` and `logout` (console sign-in), `history` (the
/// recorded calls and their responses).
const AWS_REFUSED_SERVICES: &[&str] =
    &["configure", "history", "login", "logout", "sso", "sso-oidc"];

/// `(service, subcommand)` pairs that print or issue a credential, a key
/// pair or a bearer token, or that write a file of the host, from the AWS CLI
/// reference.
const AWS_REFUSED_OPERATIONS: &[(&str, &str)] = &[
    ("acm", "export-certificate"),
    ("apigateway", "create-api-key"),
    // Print the API key values when the CLI reads the allowed `--include` as
    // `--include-value(s)` (the AWS CLI expands a unique option prefix per
    // operation).
    ("apigateway", "get-api-key"),
    ("apigateway", "get-api-keys"),
    ("appstream", "create-streaming-url"),
    // They write a file of the host: the `outfile` positional (also
    // `s3api get-object`, `s3api get-object-torrent`, `lambda invoke` and
    // `iotwireless get-position-estimate` below).
    ("cloudfront", "get-function"),
    ("cloudfront", "sign"),
    ("codeartifact", "login"),
    ("codecommit", "credential-helper"),
    ("connect", "get-federation-token"),
    ("ec2", "create-key-pair"),
    ("ec2", "get-password-data"),
    ("ec2-instance-connect", "open-tunnel"),
    ("ec2-instance-connect", "send-serial-console-ssh-public-key"),
    ("ec2-instance-connect", "send-ssh-public-key"),
    ("ec2-instance-connect", "ssh"),
    ("ecr", "get-login"),
    // Writes (merges into) the kubeconfig file of the host.
    ("eks", "update-kubeconfig"),
    ("emr", "get"),
    ("emr", "put"),
    ("emr", "socks"),
    ("emr", "ssh"),
    ("gamelift", "get-instance-access"),
    ("grafana", "create-workspace-api-key"),
    ("grafana", "create-workspace-service-account-token"),
    ("iam", "create-access-key"),
    ("iam", "create-login-profile"),
    ("iam", "create-service-specific-credential"),
    ("iam", "create-virtual-mfa-device"),
    ("iam", "reset-service-specific-credential"),
    ("iam", "update-login-profile"),
    ("iot", "create-keys-and-certificate"),
    ("iotwireless", "get-position-estimate"),
    ("lambda", "invoke"),
    ("lightsail", "create-key-pair"),
    ("lightsail", "download-default-key-pair"),
    ("lightsail", "get-instance-access-details"),
    ("lightsail", "get-relational-database-master-user-password"),
    ("quicksight", "generate-embed-url-for-anonymous-user"),
    ("quicksight", "generate-embed-url-for-registered-user"),
    (
        "quicksight",
        "generate-embed-url-for-registered-user-with-identity",
    ),
    ("quicksight", "get-dashboard-embed-url"),
    ("quicksight", "get-session-embed-url"),
    ("s3", "presign"),
    ("s3api", "get-object"),
    ("s3api", "get-object-torrent"),
    ("s3control", "get-data-access"),
    ("sts", "assume-role"),
    ("sts", "assume-role-with-saml"),
    ("sts", "assume-role-with-web-identity"),
    ("sts", "assume-root"),
    ("sts", "get-federation-token"),
    ("sts", "get-session-token"),
    ("sts", "get-web-identity-token"),
];

/// Fragments of a subcommand name that mark an operation returning a
/// credential or a bearer token, whatever the service: `ecr
/// get-authorization-token`, `eks get-token`, `rds generate-db-auth-token`,
/// `sagemaker create-presigned-domain-url`, `redshift
/// get-cluster-credentials`, `cognito-identity get-open-id-token`, `dsql
/// generate-db-connect-auth-token`, `bedrock-agentcore
/// get-workload-access-token`.
const AWS_REFUSED_SUBCOMMAND_MARKERS: &[&str] = &[
    "access-token",
    "auth-token",
    "authorization-token",
    "credentials",
    "federation-token",
    "get-token",
    "login-password",
    "open-id-token",
    "presign",
    "session-token",
];

/// Options of the AWS CLI that `ssh_aws_cli` accepts in `args`, matched
/// exactly: paging and filtering of the output, and the selectors (names,
/// identifiers, ARNs, time windows) of the common read operations. None of
/// them chooses the endpoint, the profile, the certificate checks, the
/// request signing or the logging of the AWS CLI, and none takes a file. The
/// AWS CLI may read an allowed name as a longer option of the same operation
/// (it expands a unique prefix per operation, awscli 1.46.3); none of those
/// longer options chooses the endpoint, the profile, the signing or a file,
/// and the ones that print a credential belong to operations in
/// `AWS_REFUSED_OPERATIONS`.
/// `--output` is not in the list: `--output json` is appended to every command.
const AWS_ALLOWED_OPTIONS: &[&str] = &[
    "--alarm-name-prefix",
    "--alarm-names",
    "--bucket",
    "--cluster",
    "--clusters",
    "--db-cluster-identifier",
    "--db-instance-identifier",
    "--db-snapshot-identifier",
    "--delimiter",
    "--dimensions",
    "--dry-run",
    "--end-time",
    "--exclude",
    "--filter",
    "--filters",
    "--function-name",
    "--granularity",
    "--group-by",
    "--group-ids",
    "--group-name",
    "--hosted-zone-id",
    "--human-readable",
    "--id",
    "--image-ids",
    "--include",
    "--instance-id",
    "--instance-ids",
    "--key",
    "--limit",
    "--load-balancer-arn",
    "--load-balancer-arns",
    "--log-group-name",
    "--log-group-name-prefix",
    "--log-stream-name",
    "--log-stream-name-prefix",
    "--max-items",
    "--max-keys",
    "--max-records",
    "--max-results",
    "--metric-name",
    "--metrics",
    "--name",
    "--names",
    "--namespace",
    "--next-token",
    "--no-dry-run",
    "--no-paginate",
    "--owners",
    "--page-size",
    "--period",
    "--policy-arn",
    "--prefix",
    "--query",
    "--queue-name-prefix",
    "--queue-url",
    "--recursive",
    "--region",
    "--repository-name",
    "--repository-names",
    "--resource-arn",
    "--resource-arns",
    "--resource-type-filters",
    "--role-name",
    "--service",
    "--services",
    "--snapshot-ids",
    "--stack-name",
    "--stack-status-filter",
    "--start-time",
    "--starting-token",
    "--statistics",
    "--subnet-ids",
    "--summarize",
    "--table-name",
    "--tag-filters",
    "--target-group-arn",
    "--target-group-arns",
    "--task",
    "--tasks",
    "--time-period",
    "--topic-arn",
    "--unit",
    "--user-name",
    "--version-id",
    "--volume-ids",
    "--vpc-ids",
];

/// The options of `AWS_ALLOWED_OPTIONS` that take no value: the word after one
/// of them is a positional argument, not its value.
const AWS_FLAG_OPTIONS: &[&str] = &[
    "--dry-run",
    "--human-readable",
    "--no-dry-run",
    "--no-paginate",
    "--recursive",
    "--summarize",
];

/// The options of `AWS_ALLOWED_OPTIONS` that take a list: the words that
/// follow one of them, up to the next option, are all its values (the AWS CLI
/// reads a list parameter as `nargs='+'`). Every other option that is not in
/// `AWS_FLAG_OPTIONS` takes exactly one value.
const AWS_LIST_OPTIONS: &[&str] = &[
    "--alarm-names",
    "--clusters",
    "--dimensions",
    "--filters",
    "--group-by",
    "--group-ids",
    "--image-ids",
    "--instance-ids",
    "--load-balancer-arns",
    "--metrics",
    "--names",
    "--owners",
    "--repository-names",
    "--resource-arns",
    "--resource-type-filters",
    "--services",
    "--snapshot-ids",
    "--stack-status-filter",
    "--statistics",
    "--subnet-ids",
    "--tag-filters",
    "--target-group-arns",
    "--tasks",
    "--volume-ids",
    "--vpc-ids",
];

/// What `validate_aws_args` expects after the previous word.
#[derive(Clone, Copy)]
enum Expect<'a> {
    /// A positional argument, an option or a flag.
    Nothing,
    /// The one value of the option.
    One(&'a str),
    /// One or more values of the list option.
    Many(&'a str),
}

/// The global options of the AWS CLI (v1 and v2) that are not in
/// `AWS_ALLOWED_OPTIONS`, for the error text: the AWS CLI accepts any
/// unambiguous prefix of these, so a prefix of one of them is named as such.
const AWS_REFUSED_GLOBAL_OPTIONS: &[&str] = &[
    "--ca-bundle",
    "--cli-auto-prompt",
    "--cli-binary-format",
    "--cli-connect-timeout",
    "--cli-input-json",
    "--cli-input-yaml",
    "--cli-read-timeout",
    "--color",
    "--debug",
    "--endpoint-url",
    "--generate-cli-skeleton",
    "--no-cli-auto-prompt",
    "--no-cli-pager",
    "--no-sign-request",
    "--no-verify-ssl",
    "--output",
    "--profile",
    "--v2-debug",
    "--version",
];

fn args_denied(why: &str) -> BridgeError {
    BridgeError::CommandDenied {
        reason: format!("'args' {why}"),
    }
}

/// Split `args` into words as `CloudCommandBuilder::validate_aws_args`
/// describes; `false` when a quote is left open (the open section then runs
/// to the end of the text).
fn split_aws_args(args: &str) -> (Vec<String>, bool) {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    for c in args.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => word.push(c),
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                in_word = true;
            }
            None if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            None => {
                word.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(word);
    }
    (words, quote.is_none())
}

/// Refuse the option `name` (`--something`, without `=value`) unless it is in
/// `AWS_ALLOWED_OPTIONS`; the name is matched exactly.
fn check_option_name(name: &str) -> Result<()> {
    if AWS_ALLOWED_OPTIONS.contains(&name) {
        return Ok(());
    }
    if name == "--output" {
        return Err(args_denied(
            "must not contain --output: '--output json' is appended to every command",
        ));
    }
    let abbreviates_global = name.len() > 2
        && name.starts_with("--")
        && AWS_REFUSED_GLOBAL_OPTIONS
            .iter()
            .any(|g| g.starts_with(name));
    if abbreviates_global {
        return Err(args_denied(&format!(
            "option '{name}' is refused: it is, or abbreviates, an AWS CLI global option that \
             chooses the endpoint, the profile, the certificate checks, the request signing, \
             the input files or the logging. The tool always uses the AWS identity and the \
             endpoint configured on the host. Accepted options: {}",
            AWS_ALLOWED_OPTIONS.join(" ")
        )));
    }
    Err(args_denied(&format!(
        "option '{name}' is not accepted: write it in full (abbreviations are not accepted) \
         and use one of: {}",
        AWS_ALLOWED_OPTIONS.join(" ")
    )))
}

/// Refuse a value (of `option`, or a positional argument when `option` is
/// empty) that the AWS CLI would read from a file or a URL, or a malformed
/// region.
fn check_value(option: &str, value: &str) -> Result<()> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("file://")
        || lower.contains("fileb://")
        || lower.starts_with("http://")
        || lower.starts_with("https://")
    {
        return Err(args_denied(&format!(
            "value '{value}' is refused: the AWS CLI would load a parameter that starts with \
             file://, fileb://, http:// or https:// from a file or a URL. Pass the value itself"
        )));
    }
    if option == "--region" {
        let name_like = (2..=32).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !name_like {
            return Err(args_denied(&format!(
                "value '{value}' of --region is not a region name: lower-case letters, digits \
                 and - only (for example eu-west-1)"
            )));
        }
    }
    Ok(())
}

/// Refuse a positional argument that is not an `s3://` location: the tool does
/// not read or write files of the host. The prefix is matched in lower case
/// only, as the AWS CLI does: any other spelling is a path of the host. A
/// location with a `.` or `..` segment is refused too: an operation whose
/// positional is an output file (more than sixty in awscli 1.46, beyond the
/// ones refused by name) opens the word as a local path. Such a path stays
/// under a directory named `s3:` of the working directory when no segment
/// climbs out of it, and the write fails when that directory does not exist
/// (these operations open the file without creating directories).
fn check_location(word: &str) -> Result<()> {
    if let Some(path) = word.strip_prefix("s3://") {
        if path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        {
            return Err(args_denied(&format!(
                "word '{word}' is refused: an s3:// location must not have a '.' or '..' \
                 segment. Name the bucket and the key as they are"
            )));
        }
        return Ok(());
    }
    Err(args_denied(&format!(
        "word '{word}' is refused: it is neither an option nor the value of the preceding \
         option, and a positional argument must be an s3:// location. ssh_aws_cli does not \
         read or write files of the host: use ssh_exec for transfers to or from the host"
    )))
}

/// Builds cloud provider commands for remote execution.
pub struct CloudCommandBuilder;

impl CloudCommandBuilder {
    /// Validate an AWS service name (alphanumeric, hyphens only).
    ///
    /// # Errors
    ///
    /// Returns `CommandDenied` if the service name contains invalid characters
    /// or starts with `-`.
    pub fn validate_aws_service(service: &str) -> Result<()> {
        super::shell::refuse_option_like("service", service)?;
        if service.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "AWS service name cannot be empty".to_string(),
            });
        }
        if !service
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid AWS service name '{service}': only alphanumeric and hyphens allowed"
                ),
            });
        }
        Ok(())
    }

    /// Validate a subcommand (no shell metacharacters).
    ///
    /// # Errors
    ///
    /// Returns `CommandDenied` if the subcommand contains shell injection characters
    /// or starts with `-`.
    pub fn validate_subcommand(cmd: &str) -> Result<()> {
        super::shell::refuse_option_like("subcommand", cmd)?;
        if cmd.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Subcommand cannot be empty".to_string(),
            });
        }
        let forbidden = ['|', ';', '&', '`', '$', '(', ')', '{', '}', '<', '>'];
        for ch in &forbidden {
            if cmd.contains(*ch) {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Subcommand contains forbidden character '{ch}': possible shell injection"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Validate the `(service, subcommand)` pair of an AWS CLI call.
    ///
    /// The command runs with the AWS identity of the SSH host (environment,
    /// `~/.aws`, instance role). The tool therefore refuses what reads or
    /// writes that identity (`configure`, `sso`, `login`, ...) and the
    /// operations that print or issue a credential or a bearer token
    /// (`sts get-session-token`, `ecr get-login-password`, `eks get-token`,
    /// `s3 presign`, `iam create-access-key`, ...). Call it with the values
    /// that [`Self::build_aws_cli_command`] will receive.
    ///
    /// # Errors
    ///
    /// `CommandDenied` naming `service` or `subcommand` and saying what to use
    /// instead.
    pub fn validate_aws_operation(service: &str, subcommand: &str) -> Result<()> {
        let service = service.to_ascii_lowercase();
        let sub = subcommand.to_ascii_lowercase();
        if AWS_REFUSED_SERVICES.contains(&service.as_str()) {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "'service' {service} is refused: it reads or changes the AWS identity of \
                     the host (credentials, profiles, sign-in). {AWS_USE_INSTEAD}"
                ),
            });
        }
        let refused = AWS_REFUSED_OPERATIONS
            .iter()
            .any(|&(s, c)| s == service && c == sub)
            || AWS_REFUSED_SUBCOMMAND_MARKERS
                .iter()
                .any(|m| sub.contains(m));
        if refused {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "'subcommand' {service} {sub} is refused: it prints or issues a credential \
                     or a bearer token of the AWS identity of the host, or writes a file of the \
                     host. {AWS_USE_INSTEAD}"
                ),
            });
        }
        Ok(())
    }

    /// Validate the `args` of an AWS CLI call: the words that
    /// [`Self::build_aws_cli_command`] passes after the subcommand.
    ///
    /// `args` is split into words: white space (any Unicode white space)
    /// separates them; a `'...'` or `"..."` section groups characters,
    /// spaces included, into the current word, and its quotes are removed; a
    /// backslash is a plain character; `$`, `;` and the like have no meaning
    /// because every word reaches the shell quoted. A word that starts
    /// with `-` is an option: it must be one of `AWS_ALLOWED_OPTIONS`, matched
    /// exactly (the AWS CLI also accepts any unambiguous prefix of a global
    /// option, so `--end=...` is `--endpoint-url`), optionally as
    /// `--name=value`. The AWS CLI may also read an allowed name as a longer
    /// option of the same operation; none of those chooses the endpoint, the
    /// profile, the signing or a file (awscli 1.46.3), and the operations
    /// where one prints a credential are in `AWS_REFUSED_OPERATIONS`. A word
    /// that does not start with `-` is the value of the preceding option
    /// (one word, or several after a list option of `AWS_LIST_OPTIONS`; none
    /// after a flag of `AWS_FLAG_OPTIONS` or after `--name=value`) or else a
    /// positional argument, which must start with `s3://`: the tool does not
    /// read or write files of the host. Nothing in the list changes where the
    /// request goes or which credentials sign it: those come from the host's
    /// own configuration. A value is refused when the AWS CLI would load it
    /// from a file or a URL (`file://`, `fileb://`, `http://`, `https://`),
    /// and the value of `--region` must be a region name.
    ///
    /// # Errors
    ///
    /// `CommandDenied` naming `args` and the offending word.
    pub fn validate_aws_args(args: &str) -> Result<()> {
        let (words, balanced) = split_aws_args(args);
        if !balanced {
            return Err(args_denied(
                "has an unterminated quote: close every ' and \" (a quote groups words; \
                 a backslash is a plain character)",
            ));
        }
        let mut expect = Expect::Nothing;
        for word in &words {
            if word.starts_with('-') {
                let (name, value) = match word.split_once('=') {
                    Some((n, v)) => (n, Some(v)),
                    None => (word.as_str(), None),
                };
                check_option_name(name)?;
                expect = if let Some(v) = value {
                    check_value(name, v)?;
                    Expect::Nothing
                } else if AWS_FLAG_OPTIONS.contains(&name) {
                    Expect::Nothing
                } else if AWS_LIST_OPTIONS.contains(&name) {
                    Expect::Many(name)
                } else {
                    Expect::One(name)
                };
            } else {
                match expect {
                    Expect::One(name) => {
                        check_value(name, word)?;
                        expect = Expect::Nothing;
                    }
                    Expect::Many(name) => check_value(name, word)?,
                    Expect::Nothing => {
                        check_value("", word)?;
                        check_location(word)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Build an AWS CLI command.
    ///
    /// Constructs: `aws SERVICE SUBCOMMAND [WORD...] --output json 2>&1`,
    /// where each WORD is one word of `args` (split as
    /// [`Self::validate_aws_args`] describes), quoted on its own.
    /// `--output json` always comes last.
    ///
    /// This builder does not judge `args`: run [`Self::validate_aws_operation`]
    /// and [`Self::validate_aws_args`] first, as the tool handler does. An
    /// `args` with an unterminated quote is split at the quote as if it were
    /// closed at the end of the text.
    #[must_use]
    pub fn build_aws_cli_command(service: &str, subcommand: &str, args: Option<&str>) -> String {
        let mut cmd = format!("aws {} {}", shell_escape(service), shell_escape(subcommand));
        if let Some(extra) = args {
            for word in split_aws_args(extra).0 {
                cmd.push(' ');
                cmd.push_str(&shell_escape(&word));
            }
        }
        cmd.push_str(" --output json 2>&1");
        cmd
    }

    /// Build a cloud metadata detection command.
    ///
    /// Auto-detects the cloud provider by querying metadata endpoints.
    #[must_use]
    pub fn build_cloud_metadata_command() -> String {
        "curl -s -m 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null && echo AWS \
         || curl -s -m 2 -H 'Metadata-Flavor: Google' \
         http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null && echo GCP \
         || curl -s -m 2 -H 'Metadata: true' \
         'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null \
         && echo Azure || echo 'No cloud metadata available'"
            .to_string()
    }

    /// Build a cloud tags retrieval command.
    ///
    /// Queries instance tags from the cloud provider metadata endpoint.
    #[must_use]
    pub fn build_cloud_tags_command(provider: Option<&str>) -> String {
        match provider.unwrap_or("aws") {
            "gcp" => "curl -s -H 'Metadata-Flavor: Google' \
                      'http://metadata.google.internal/computeMetadata/v1/instance/tags' \
                      2>/dev/null"
                .to_string(),
            "azure" => "curl -s -H 'Metadata: true' \
                        'http://169.254.169.254/metadata/instance/compute/tagsList\
                        ?api-version=2021-02-01' 2>/dev/null"
                .to_string(),
            _ => "curl -s http://169.254.169.254/latest/meta-data/tags/instance/ 2>/dev/null"
                .to_string(),
        }
    }

    /// Build a cloud cost retrieval command (AWS Cost Explorer).
    ///
    /// Constructs: `aws ce get-cost-and-usage ...`
    #[must_use]
    pub fn build_cloud_cost_command(service: Option<&str>, period: Option<&str>) -> String {
        let time_period = period.unwrap_or("7d");
        let days = time_period
            .strip_suffix('d')
            .and_then(|d| d.parse::<u32>().ok())
            .unwrap_or(7);
        let mut cmd = format!(
            "aws ce get-cost-and-usage \
             --time-period Start=$(date -d '{days} days ago' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
             --granularity DAILY --metrics BlendedCost"
        );
        if let Some(svc) = service {
            // Build the JSON first (it escapes `svc` for JSON), then quote the
            // whole document once for the shell.
            let filter = serde_json::json!({
                "Dimensions": {"Key": "SERVICE", "Values": [svc]}
            })
            .to_string();
            let _ = write!(cmd, " --filter {}", shell_escape(&filter));
        }
        cmd.push_str(" --output json 2>&1");
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_aws_service ──

    #[test]
    fn test_validate_aws_service_valid() {
        assert!(CloudCommandBuilder::validate_aws_service("s3").is_ok());
        assert!(CloudCommandBuilder::validate_aws_service("ec2").is_ok());
        assert!(CloudCommandBuilder::validate_aws_service("iam").is_ok());
        assert!(CloudCommandBuilder::validate_aws_service("cost-explorer").is_ok());
    }

    #[test]
    fn test_validate_aws_service_empty() {
        assert!(CloudCommandBuilder::validate_aws_service("").is_err());
    }

    #[test]
    fn test_validate_aws_service_shell_injection() {
        assert!(CloudCommandBuilder::validate_aws_service("s3;rm").is_err());
        assert!(CloudCommandBuilder::validate_aws_service("ec2 && echo").is_err());
        assert!(CloudCommandBuilder::validate_aws_service("s3|cat").is_err());
    }

    // ── validate_subcommand ──

    #[test]
    fn test_validate_subcommand_valid() {
        assert!(CloudCommandBuilder::validate_subcommand("describe-instances").is_ok());
        assert!(CloudCommandBuilder::validate_subcommand("list-buckets").is_ok());
        assert!(CloudCommandBuilder::validate_subcommand("get-object").is_ok());
    }

    #[test]
    fn test_validate_subcommand_empty() {
        assert!(CloudCommandBuilder::validate_subcommand("").is_err());
    }

    #[test]
    fn test_validate_subcommand_injection() {
        assert!(CloudCommandBuilder::validate_subcommand("list; rm -rf /").is_err());
        assert!(CloudCommandBuilder::validate_subcommand("list | cat").is_err());
        assert!(CloudCommandBuilder::validate_subcommand("$(whoami)").is_err());
        assert!(CloudCommandBuilder::validate_subcommand("list`id`").is_err());
    }

    // ── build_aws_cli_command ──

    #[test]
    fn test_build_aws_cli_basic() {
        let cmd = CloudCommandBuilder::build_aws_cli_command("s3", "ls", None);
        assert!(cmd.contains("aws 's3' 'ls'"));
        assert!(cmd.contains("--output json"));
        assert!(cmd.ends_with("2>&1"));
    }

    #[test]
    fn test_build_aws_cli_with_args() {
        let cmd = CloudCommandBuilder::build_aws_cli_command(
            "ec2",
            "describe-instances",
            Some("--region us-east-1 --instance-ids i-123"),
        );
        assert_eq!(
            cmd,
            "aws 'ec2' 'describe-instances' '--region' 'us-east-1' '--instance-ids' 'i-123' \
             --output json 2>&1"
        );
    }

    #[test]
    fn test_build_aws_cli_golden_strings() {
        let build = CloudCommandBuilder::build_aws_cli_command;
        assert_eq!(build("s3", "ls", None), "aws 's3' 'ls' --output json 2>&1");
        assert_eq!(
            build("s3", "ls", Some("   ")),
            "aws 's3' 'ls' --output json 2>&1"
        );
        assert_eq!(
            build("s3", "ls", Some("s3://bucket/prefix/ --recursive")),
            "aws 's3' 'ls' 's3://bucket/prefix/' '--recursive' --output json 2>&1"
        );
        assert_eq!(
            build(
                "ec2",
                "describe-instances",
                Some("--query \"Reservations[?State.Name=='running'].InstanceId\" --no-paginate")
            ),
            "aws 'ec2' 'describe-instances' '--query' \
             'Reservations[?State.Name=='\\''running'\\''].InstanceId' '--no-paginate' \
             --output json 2>&1"
        );
        assert_eq!(
            build("ec2", "describe-instances", Some("--region=eu-west-1")),
            "aws 'ec2' 'describe-instances' '--region=eu-west-1' --output json 2>&1"
        );
        assert_eq!(
            build(
                "ec2",
                "describe-instances",
                Some("--filters 'Name=tag:Env,Values=prod'")
            ),
            "aws 'ec2' 'describe-instances' '--filters' 'Name=tag:Env,Values=prod' \
             --output json 2>&1"
        );
    }

    #[test]
    fn test_build_aws_cli_every_word_is_quoted_on_its_own() {
        let cmd = CloudCommandBuilder::build_aws_cli_command(
            "s3",
            "ls",
            Some("a;b $(id) `id` \"c d\" e'f g'h"),
        );
        assert_eq!(
            cmd,
            "aws 's3' 'ls' 'a;b' '$(id)' '`id`' 'c d' 'ef gh' --output json 2>&1"
        );
    }

    // ── split_aws_args ──

    fn words(args: &str) -> (Vec<String>, bool) {
        split_aws_args(args)
    }

    fn owned(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn test_split_aws_args() {
        assert_eq!(words(""), (vec![], true));
        assert_eq!(words(" \t\n "), (vec![], true));
        assert_eq!(words("a  b\tc\nd"), (owned(&["a", "b", "c", "d"]), true));
        assert_eq!(
            words("--q 'a b' \"c d\""),
            (owned(&["--q", "a b", "c d"]), true)
        );
        assert_eq!(words("'it'\"s\""), (owned(&["its"]), true));
        assert_eq!(words("\"it's\" x"), (owned(&["it's", "x"]), true));
        assert_eq!(words("'' x"), (owned(&["", "x"]), true));
        assert_eq!(words("a\\b"), (owned(&["a\\b"]), true));
        // A quote left open runs to the end of the text.
        assert_eq!(words("a 'b c"), (owned(&["a", "b c"]), false));
        assert_eq!(words("\"--end"), (owned(&["--end"]), false));
    }

    // ── validate_aws_args ──

    fn args_err(args: &str) -> String {
        match CloudCommandBuilder::validate_aws_args(args) {
            Err(BridgeError::CommandDenied { reason }) => reason,
            other => panic!("{args:?}: expected CommandDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_aws_args_accepts_the_documented_uses() {
        for args in [
            "",
            "   ",
            "--region us-east-1",
            "--region=eu-west-1",
            "--region us-east-1 --instance-ids i-123 i-456",
            "--filters Name=tag:Env,Values=prod --max-items 10 --no-paginate",
            "--query 'Reservations[].Instances[].InstanceId'",
            "--query \"Reservations[?State.Name=='running'].InstanceId\"",
            "--query=Reservations[0]",
            "--bucket my-bucket --prefix logs/ --max-keys 5",
            "s3://bucket/prefix/ --recursive --human-readable --summarize",
            "--log-group-name /aws/lambda/fn --start-time 1700000000000",
            "--page-size 50 --starting-token abc",
            "--region us-gov-west-1",
            "s3://b/",
            "s3://a/k s3://b/k",
            "--recursive s3://b/p/",
            "--recursive --human-readable --summarize s3://b",
            "--dry-run --no-paginate s3://b/p/ s3://c/p/",
            "--exclude '*' --include '*.log' s3://b/p/ s3://c/p/",
            "--region=eu-west-1 s3://b/",
            "--instance-ids i-1 i-2 --region eu-west-1",
        ] {
            CloudCommandBuilder::validate_aws_args(args)
                .unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
    }

    #[test]
    fn test_validate_aws_args_refuses_the_options_that_move_the_destination() {
        for args in [
            "--endpoint-url=http://rogue.example",
            "--endpoint-url http://rogue.example",
            "--endpoint=http://rogue.example",
            "--end=http://rogue.example",
            "--e=http://rogue.example",
            "--endpoint-url",
            "--profile other",
            "--prof=other",
            "--pro other",
            "--ca-bundle /tmp/ca.pem",
            "--ca=/tmp/ca.pem",
            "--no-verify-ssl",
            "--no-v",
            "--no-sign-request",
            "--no-s",
            "--no-",
            "--debug",
            "--deb",
            "--v2-debug",
            "--v2",
            "--cli-read-timeout 1",
            "--cli-input-json x",
            "--cli-",
            "--c",
            "--generate-cli-skeleton",
            "--region us-east-1 --endpoint-url=http://rogue.example",
            "'--endpoint-url=http://rogue.example'",
            "\"--endpoint-url\" http://rogue.example",
        ] {
            let reason = args_err(args);
            assert!(reason.starts_with("'args'"), "{args:?}: {reason}");
            assert!(reason.contains("global option"), "{args:?}: {reason}");
        }
    }

    #[test]
    fn test_validate_aws_args_refuses_what_is_not_in_the_list() {
        for args in [
            "--output text",
            "--output=text",
            "--outp text",
            "--reg us-east-1",
            "--quer x",
            "--query-all x",
            "--REGION us-east-1",
            "--region-name x",
            "--",
            "--=x",
            "-",
            "-h",
            "-r us-east-1",
            "--no-paginate --x",
            "--max-items -1",
            "--region -x",
            "--with-decryption",
            "--include-values",
        ] {
            let reason = args_err(args);
            assert!(reason.starts_with("'args'"), "{args:?}: {reason}");
        }
        let reason = args_err("--output text");
        assert!(reason.contains("--output json"), "{reason}");
        let reason = args_err("--reg us-east-1");
        assert!(
            reason.contains("abbreviations are not accepted"),
            "{reason}"
        );
        assert!(reason.contains("--region"), "{reason}");
    }

    #[test]
    fn test_validate_aws_args_refuses_values_the_cli_loads_from_a_file_or_a_url() {
        for args in [
            "--instance-ids file:///srv/x",
            "--instance-ids=file:///srv/x",
            "--filters FILE:///srv/x",
            "--name fileb:///srv/x",
            "--name http://198.51.100.7/x",
            "--name=https://rogue.example/x",
            "file:///srv/x",
            "--query 'x file://y'",
        ] {
            let reason = args_err(args);
            assert!(reason.contains("file://"), "{args:?}: {reason}");
        }
    }

    #[test]
    fn test_validate_aws_args_refuses_a_dot_segment_in_an_s3_location() {
        for args in [
            "s3://../x",
            "s3://b/../k",
            "s3://b/./k",
            "s3://b/k/..",
            "--recursive s3://b/.. s3://c/",
            "s3://./",
        ] {
            let reason = args_err(args);
            assert!(reason.contains("'.' or '..' segment"), "{args:?}: {reason}");
        }
        for args in ["s3://b/k..x", "s3://b/.k", "s3://b/...", "s3://b//k"] {
            assert!(
                CloudCommandBuilder::validate_aws_args(args).is_ok(),
                "{args:?} must be accepted"
            );
        }
    }

    #[test]
    fn test_validate_aws_args_refuses_the_words_that_are_files_of_the_host() {
        for args in [
            "cp /srv/x s3://b/k",
            "/srv/x s3://b/k",
            "s3://b/k /srv/x",
            "--recursive /srv/d s3://b/",
            "--recursive s3://b/ /srv/d",
            "--bucket b --key k /srv/x",
            "--function-name f /srv/out",
            "--region eu-west-1 /srv/x",
            "--region=eu-west-1 /srv/x",
            "--dry-run /srv/x",
            "--no-paginate /srv/x",
            "--human-readable /srv/x",
            "--summarize /srv/x",
            "--instance-ids=i-1 /srv/x",
            "--exclude '*' --include '*.log' s3://b/ rel/x",
            "./x",
            "~/x",
            "x",
            "''",
            "S3://b/k",
            " s3://b/k s3:/b/k",
            "s3:/b/k",
            "s3 ://b/k",
            "'s3 ://b/k'",
            "-",
        ] {
            let reason = args_err(args);
            assert!(reason.starts_with("'args'"), "{args:?}: {reason}");
        }
        let reason = args_err("s3://b/k /srv/x");
        assert!(reason.contains("'/srv/x'"), "{reason}");
        assert!(reason.contains("does not read or write files"), "{reason}");
        assert!(reason.contains("ssh_exec"), "{reason}");
        let reason = args_err("--bucket b --key k /srv/x");
        assert!(reason.contains("'/srv/x'"), "{reason}");
    }

    #[test]
    fn test_validate_aws_args_values_of_list_options_and_flags() {
        // A list option takes every word up to the next option; a flag and a
        // single-value option do not.
        CloudCommandBuilder::validate_aws_args("--instance-ids i-1 i-2 i-3 --no-paginate").unwrap();
        CloudCommandBuilder::validate_aws_args("--region eu-west-1 --instance-ids i-1 i-2")
            .unwrap();
        assert!(CloudCommandBuilder::validate_aws_args("--region a-b i-1").is_err());
        assert!(CloudCommandBuilder::validate_aws_args("--no-paginate i-1").is_err());
        // The check on the value of a list option applies to every word.
        let reason = args_err("--instance-ids i-1 file:///srv/x");
        assert!(reason.contains("file://"), "{reason}");
    }

    #[test]
    fn test_validate_aws_args_checks_the_region_name() {
        for region in [
            "x.evil.example",
            "a/b",
            "A",
            "x",
            "us east",
            "e".repeat(33).as_str(),
        ] {
            let reason = args_err(&format!("--region '{region}'"));
            assert!(reason.contains("not a region name"), "{region}: {reason}");
            let reason = args_err(&format!("--region='{region}'"));
            assert!(reason.contains("not a region name"), "{region}: {reason}");
        }
        // Only the value of --region is a region.
        CloudCommandBuilder::validate_aws_args("--name Some.Name --region eu-west-3").unwrap();
    }

    #[test]
    fn test_validate_aws_args_refuses_an_unterminated_quote() {
        for args in ["--query 'x", "--query \"x", "'", "--region us-east-1 \""] {
            let reason = args_err(args);
            assert!(reason.contains("unterminated quote"), "{args:?}: {reason}");
        }
    }

    #[test]
    fn test_aws_flag_and_list_options_are_allowed_sorted_and_disjoint() {
        for list in [AWS_FLAG_OPTIONS, AWS_LIST_OPTIONS] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted, list, "keep the list sorted, no duplicates");
            for opt in list {
                assert!(AWS_ALLOWED_OPTIONS.contains(opt), "{opt}");
            }
        }
        for flag in AWS_FLAG_OPTIONS {
            assert!(!AWS_LIST_OPTIONS.contains(flag), "{flag}");
        }
        // Exact list of the value-less options of the allow-list.
        assert_eq!(
            AWS_FLAG_OPTIONS,
            [
                "--dry-run",
                "--human-readable",
                "--no-dry-run",
                "--no-paginate",
                "--recursive",
                "--summarize"
            ]
        );
    }

    // The prefix guard below covers the global options only: the AWS CLI also
    // expands an allowed name to a longer option of the same operation (for
    // example `--include` to `--include-values` on `apigateway get-api-keys`),
    // and none of those chooses the endpoint, the profile, the signing or a
    // file (awscli 1.46.3). The operations where one prints a credential are
    // in `AWS_REFUSED_OPERATIONS`.
    #[test]
    fn test_aws_allowed_options_are_well_formed_and_destination_neutral() {
        let mut sorted = AWS_ALLOWED_OPTIONS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted, AWS_ALLOWED_OPTIONS,
            "keep the list sorted, no duplicates"
        );
        for &opt in AWS_ALLOWED_OPTIONS {
            assert!(opt.starts_with("--") && opt.len() > 3, "{opt}");
            assert!(
                opt.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{opt}"
            );
            // The AWS CLI reads an unambiguous prefix as the longer option:
            // no accepted option may be a prefix of a refused global one.
            for &global in AWS_REFUSED_GLOBAL_OPTIONS {
                assert!(
                    !global.starts_with(opt),
                    "{opt} is a prefix of the refused {global}"
                );
            }
            assert!(
                !opt.starts_with("--cli-") && !opt.contains("endpoint"),
                "{opt}"
            );
        }
        for &global in AWS_REFUSED_GLOBAL_OPTIONS {
            assert!(!AWS_ALLOWED_OPTIONS.contains(&global), "{global}");
        }
        for must in [
            "--endpoint-url",
            "--profile",
            "--ca-bundle",
            "--no-verify-ssl",
            "--no-sign-request",
            "--debug",
            "--output",
            "--v2-debug",
        ] {
            assert!(AWS_REFUSED_GLOBAL_OPTIONS.contains(&must), "{must}");
        }
    }

    // ── validate_aws_operation ──

    fn operation_err(service: &str, subcommand: &str) -> String {
        match CloudCommandBuilder::validate_aws_operation(service, subcommand) {
            Err(BridgeError::CommandDenied { reason }) => reason,
            other => panic!("{service} {subcommand}: expected CommandDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_aws_operation_refuses_the_identity_services() {
        for service in [
            "configure",
            "CONFIGURE",
            "sso",
            "sso-oidc",
            "login",
            "logout",
            "history",
        ] {
            let reason = operation_err(service, "list");
            assert!(reason.starts_with("'service'"), "{service}: {reason}");
            assert!(reason.contains("ssh_exec"), "{service}: {reason}");
        }
    }

    #[test]
    fn test_validate_aws_operation_refuses_the_operations_that_issue_a_credential() {
        for (service, subcommand) in [
            ("sts", "get-session-token"),
            ("sts", "get-federation-token"),
            ("sts", "assume-role"),
            ("sts", "assume-role-with-saml"),
            ("sts", "assume-role-with-web-identity"),
            ("sts", "assume-root"),
            ("sts", "get-web-identity-token"),
            ("ecr", "get-login-password"),
            ("ecr", "get-login"),
            ("ecr", "get-authorization-token"),
            ("ecr-public", "get-login-password"),
            ("ecr-public", "get-authorization-token"),
            ("codeartifact", "get-authorization-token"),
            ("codeartifact", "login"),
            ("codecommit", "credential-helper"),
            ("eks", "get-token"),
            ("iam", "create-access-key"),
            ("iam", "create-login-profile"),
            ("iam", "update-login-profile"),
            ("iam", "create-service-specific-credential"),
            ("iam", "reset-service-specific-credential"),
            ("iam", "create-virtual-mfa-device"),
            ("s3", "presign"),
            ("rds", "generate-db-auth-token"),
            ("dsql", "generate-db-connect-admin-auth-token"),
            ("dsql", "generate-db-connect-auth-token"),
            ("redshift", "get-cluster-credentials"),
            ("redshift", "get-cluster-credentials-with-iam"),
            ("redshift-serverless", "get-credentials"),
            ("cognito-identity", "get-credentials-for-identity"),
            ("cognito-identity", "get-open-id-token"),
            (
                "cognito-identity",
                "get-open-id-token-for-developer-identity",
            ),
            ("cognito-idp", "get-tokens-from-refresh-token"),
            ("ec2", "get-password-data"),
            ("ec2", "create-key-pair"),
            ("ec2-instance-connect", "send-ssh-public-key"),
            ("lightsail", "get-instance-access-details"),
            ("acm", "export-certificate"),
            ("sagemaker", "create-presigned-domain-url"),
            ("bedrock-agentcore", "get-workload-access-token"),
            ("lakeformation", "get-temporary-glue-table-credentials"),
            ("EKS", "Get-Token"),
            ("apigateway", "get-api-keys"),
            ("apigateway", "get-api-key"),
            ("APIGateway", "Get-Api-Keys"),
            ("apigateway", "create-api-key"),
            ("s3api", "get-object"),
            ("s3api", "get-object-torrent"),
            ("lambda", "invoke"),
            ("cloudfront", "get-function"),
            ("iotwireless", "get-position-estimate"),
            ("eks", "update-kubeconfig"),
        ] {
            let reason = operation_err(service, subcommand);
            assert!(
                reason.starts_with("'subcommand'"),
                "{service} {subcommand}: {reason}"
            );
            assert!(
                reason.contains("ssh_exec"),
                "{service} {subcommand}: {reason}"
            );
        }
    }

    #[test]
    fn test_validate_aws_operation_keeps_the_read_operations() {
        for (service, subcommand) in [
            ("s3", "ls"),
            ("s3", "cp"),
            ("s3api", "list-objects-v2"),
            ("ec2", "describe-instances"),
            ("sts", "get-caller-identity"),
            ("iam", "list-users"),
            ("iam", "list-access-keys"),
            ("iam", "get-credential-report"),
            ("iam", "update-assume-role-policy"),
            ("logs", "describe-log-groups"),
            ("lambda", "list-functions"),
            ("cloudwatch", "get-metric-statistics"),
            ("ecr", "describe-repositories"),
            ("eks", "describe-cluster"),
            ("eks", "list-clusters"),
            ("rds", "describe-db-instances"),
            ("ssm", "describe-instance-information"),
            ("s3api", "get-object-attributes"),
            ("lambda", "get-function"),
            ("apigateway", "get-rest-apis"),
            ("cloudfront", "get-distribution"),
        ] {
            CloudCommandBuilder::validate_aws_operation(service, subcommand)
                .unwrap_or_else(|e| panic!("{service} {subcommand}: {e}"));
        }
    }

    // ── build_cloud_metadata_command ──

    #[test]
    fn test_build_cloud_metadata_command() {
        let cmd = CloudCommandBuilder::build_cloud_metadata_command();
        assert!(cmd.contains("169.254.169.254"));
        assert!(cmd.contains("AWS"));
        assert!(cmd.contains("GCP"));
        assert!(cmd.contains("Azure"));
        assert!(cmd.contains("No cloud metadata available"));
    }

    // ── build_cloud_tags_command ──

    #[test]
    fn test_build_cloud_tags_default_aws() {
        let cmd = CloudCommandBuilder::build_cloud_tags_command(None);
        assert!(cmd.contains("169.254.169.254/latest/meta-data/tags"));
    }

    #[test]
    fn test_build_cloud_tags_gcp() {
        let cmd = CloudCommandBuilder::build_cloud_tags_command(Some("gcp"));
        assert!(cmd.contains("Metadata-Flavor: Google"));
        assert!(cmd.contains("tags"));
    }

    #[test]
    fn test_build_cloud_tags_azure() {
        let cmd = CloudCommandBuilder::build_cloud_tags_command(Some("azure"));
        assert!(cmd.contains("Metadata: true"));
        assert!(cmd.contains("tagsList"));
    }

    // ── build_cloud_cost_command ──

    #[test]
    fn test_build_cloud_cost_default() {
        let cmd = CloudCommandBuilder::build_cloud_cost_command(None, None);
        assert!(cmd.contains("aws ce get-cost-and-usage"));
        assert!(cmd.contains("7 days ago"));
        assert!(cmd.contains("--granularity DAILY"));
        assert!(cmd.contains("--metrics BlendedCost"));
    }

    #[test]
    fn test_build_cloud_cost_with_service() {
        let cmd = CloudCommandBuilder::build_cloud_cost_command(Some("Amazon S3"), None);
        assert!(cmd.contains("SERVICE"));
        assert!(cmd.contains("Amazon S3"));
    }

    #[test]
    fn test_build_cloud_cost_with_period() {
        let cmd = CloudCommandBuilder::build_cloud_cost_command(None, Some("30d"));
        assert!(cmd.contains("30 days ago"));
    }

    #[test]
    fn test_cloud_cost_service_is_one_quoted_json_word() {
        for svc in ["x; id #", "$(id)", "x';id;'"] {
            let cmd = CloudCommandBuilder::build_cloud_cost_command(Some(svc), None);
            let filter = cmd
                .split(" --filter ")
                .nth(1)
                .and_then(|r| r.split(" --output").next())
                .unwrap();
            assert!(filter.starts_with("'{\"Dimensions\""), "{filter}");
            let json = filter.trim_matches('\'').replace("'\\''", "'");
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(v["Dimensions"]["Values"][0], svc);
        }
    }

    #[test]
    fn test_validate_aws_service_and_subcommand_refuse_a_leading_dash() {
        let err = CloudCommandBuilder::validate_aws_service("-x").unwrap_err();
        assert!(err.to_string().contains("'service'"), "{err}");
        let err = CloudCommandBuilder::validate_subcommand("--debug").unwrap_err();
        assert!(err.to_string().contains("'subcommand'"), "{err}");
    }
}
