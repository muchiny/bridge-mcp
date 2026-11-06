#![no_main]
use bridge_mcp::domain::use_cases::cloud::CloudCommandBuilder;
use bridge_mcp_fuzz::shell_words;
use libfuzzer_sys::fuzz_target;

// What `ssh_aws_cli` owes its caller: an `args` that the validator ACCEPTED
// holds only allowed options, the values of those options, and `s3://`
// locations. No other word gets through, so no word can name a file of the
// host (a path) or make the AWS CLI load a parameter from a file or a URL.
//
// The accepted `args` is read back from the command the builder makes of it:
// the builder splits `args` itself and quotes each word, and the shell reads
// the words back, so what is asserted is the line `aws` will be started with
// and not the validator's own view of it.
//
// The oracle restates the allow-list and the arity of the options rather than
// importing them (they are private, and an oracle that shares the product's
// table cannot notice a wrong entry in it). It re-derives, word by word,
// whether a word is an option, the value of one, or a positional argument:
//
// - a word that starts with `-` is an option: its name (before the first `=`)
//   is in the list;
// - a word that follows a flag, a `--name=value` or the last value of an
//   option is a positional argument and starts with `s3://` (lower case: the
//   AWS CLI tests the prefix in lower case, so another spelling is a path);
// - no word holds `file://` or `fileb://` (any case) or starts with
//   `http://` or `https://`;
// - the value of `--region` is a region name.
//
// Refusal is always fine; the fuzzer is looking for `args` that get THROUGH.
//
// Run with: `cargo +nightly fuzz run fuzz_aws_args`

// Restated, not imported: the list in `cloud.rs` is private, and an oracle that
// read the product's own list could not tell when that list gained a name it
// should not have. A name added there on purpose has to be added here too.
const ALLOWED_OPTIONS: &[&str] = &[
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

// The allowed options that take no value (restated).
const FLAG_OPTIONS: &[&str] = &[
    "--dry-run",
    "--human-readable",
    "--no-dry-run",
    "--no-paginate",
    "--recursive",
    "--summarize",
];

// The allowed options that take every following word up to the next option
// (restated).
const LIST_OPTIONS: &[&str] = &[
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

/// What the previous word leaves to come.
#[derive(Clone, Copy, PartialEq)]
enum Next<'a> {
    /// Nothing is owed: the next non-option word is positional.
    Positional,
    /// The one value of the option.
    One(&'a str),
    /// One or more values of the option.
    Many(&'a str),
}

fn is_region_name(value: &str) -> bool {
    (2..=32).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn assert_value(option: &str, value: &str, cmd: &str) {
    if option == "--region" {
        assert!(
            is_region_name(value),
            "accepted a --region value that is not a region name: {value:?}\n  built: {cmd:?}"
        );
    }
}

fuzz_target!(|data: &str| {
    if CloudCommandBuilder::validate_aws_args(data).is_err() {
        return;
    }

    // `--output json` is appended to every command; take it off before
    // reading the line back (`2>&1` is shell syntax, not a word).
    let cmd = CloudCommandBuilder::build_aws_cli_command("s3", "ls", Some(data));
    let Some(body) = cmd.strip_suffix(" --output json 2>&1") else {
        panic!("the command does not end with the fixed tail: {cmd:?}");
    };
    let Some(words) = shell_words(body) else {
        panic!("accepted args made a command line sh cannot read as plain words: {cmd:?}");
    };
    let Some((head, words)) = words.split_at_checked(3) else {
        panic!("the command lost its program, service or operation: {cmd:?}");
    };
    assert_eq!(head, ["aws", "s3", "ls"], "built: {cmd:?}");

    let mut next = Next::Positional;
    for word in words {
        let lower = word.to_ascii_lowercase();
        assert!(
            !lower.contains("file://") && !lower.contains("fileb://"),
            "accepted a word that holds file:// or fileb://: {word:?}\n  built: {cmd:?}"
        );
        assert!(
            !lower.starts_with("http://") && !lower.starts_with("https://"),
            "accepted a word that starts with http:// or https://: {word:?}\n  built: {cmd:?}"
        );

        if word.starts_with('-') {
            let (name, value) = match word.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (word.as_str(), None),
            };
            assert!(
                ALLOWED_OPTIONS.contains(&name),
                "accepted an option that is not in the list: {word:?}\n  built: {cmd:?}"
            );
            next = if let Some(value) = value {
                assert_value(name, value, &cmd);
                Next::Positional
            } else if FLAG_OPTIONS.contains(&name) {
                Next::Positional
            } else if LIST_OPTIONS.contains(&name) {
                Next::Many(name)
            } else {
                Next::One(name)
            };
            continue;
        }

        match next {
            Next::One(name) => {
                assert_value(name, word, &cmd);
                next = Next::Positional;
            }
            Next::Many(name) => assert_value(name, word, &cmd),
            Next::Positional => assert!(
                word.starts_with("s3://"),
                "accepted a positional word that is not an s3:// location: {word:?}\n  \
                 built: {cmd:?}"
            ),
        }
    }
});
