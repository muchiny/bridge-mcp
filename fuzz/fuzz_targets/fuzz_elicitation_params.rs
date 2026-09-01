#![no_main]

use bridge_mcp::ElicitationCreateResult;
use bridge_mcp::mcp::elicitation::{confirm_destructive_request, destructive_confirmation_granted};
use libfuzzer_sys::fuzz_target;

// Two halves of the destructive gate, and the prompt half is the one that
// was broken.
//
// OUTBOUND — what the operator reads must be what runs. The prompt used to
// interpolate a client-chosen command into a fixed three-backtick fence, and
// `arguments["command"]` of `ssh_exec` may carry real newlines: a command
// containing a line of three backticks closed the block and everything after
// it rendered as prose. The operator read `rm -rf /` followed by "nothing will
// be executed; this is a dry run", and approved. Since 3.0.0 this prompt is
// the whole of `require_elicitation_on_destructive`.
//
// INBOUND — nothing but an explicit accept is consent. This half is sound and
// the assertions are here to keep it that way.

/// Read the block under `heading`, the way a markdown renderer would.
///
/// Two things the naive version got wrong, both reported by this fuzzer within
/// seconds of being written:
///
/// - `split_once("**Command:**")` matches the heading text inside a fence,
///   where a renderer sees inert prose. So this tracks fence state and only
///   recognises a heading outside one.
/// - `str::lines()` strips the `\r` of a CRLF, so the content came back
///   altered and the comparison failed on healthy code. So this slices the
///   original string by offset and returns the content byte for byte.
///
/// Returns the block's contents, plus how many headings by that name a
/// renderer would actually see.
fn block_after<'a>(message: &'a str, heading: &str) -> (Option<&'a str>, usize) {
    let mut open_fence: Option<usize> = None;
    let mut headings = 0usize;
    let mut expecting_fence = false;
    let mut content_start: Option<usize> = None;
    let mut result = None;
    let mut offset = 0usize;

    while offset <= message.len() {
        let rest = &message[offset..];
        let len = rest.find('\n').unwrap_or(rest.len());
        let line = &rest[..len];
        let next = offset + len + 1;

        // CommonMark treats CR, LF and CRLF alike as line endings, so a
        // trailing CR is not part of the line's content for structure.
        let structural = line.trim_end_matches('\r');
        let ticks = structural.chars().take_while(|c| *c == '`').count();

        if let Some(width) = open_fence {
            if ticks >= width && structural.len() == ticks {
                open_fence = None;
                if let Some(from) = content_start.take() {
                    // Stop before the `\n` that introduces the closing fence.
                    result = Some(&message[from..offset.saturating_sub(1)]);
                }
            }
        } else if expecting_fence && ticks >= 3 {
            open_fence = Some(ticks);
            expecting_fence = false;
            if result.is_none() {
                content_start = Some(next.min(message.len()));
            }
        } else {
            expecting_fence = false;
            if ticks >= 3 {
                open_fence = Some(ticks);
            } else if line == heading {
                headings += 1;
                expecting_fence = true;
            }
        }

        if len == rest.len() {
            break;
        }
        offset = next;
    }

    (result, headings)
}

fuzz_target!(|data: (&str, &str, &str, &[u8])| {
    let (tool_name, summary, command, answer_bytes) = data;

    // ── the prompt shows exactly what will run ────────────────────────
    let params = confirm_destructive_request(tool_name, summary, Some(command.to_string()));

    let (shown, command_headings) = block_after(&params.message, "**Command:**");
    assert_eq!(
        command_headings, 1,
        "a renderer would see {command_headings} Command headings, not one; \
         command {command:?} produced:\n{}",
        params.message
    );
    let shown = shown.unwrap_or_else(|| {
        panic!("the Command block did not close; command {command:?} produced:\n{}", params.message)
    });
    assert_eq!(
        shown, command,
        "the operator would see something other than the command that runs.\n  \
         command: {command:?}\n  shown  : {shown:?}\n  prompt :\n{}",
        params.message
    );

    let (args, arg_headings) = block_after(&params.message, "**Arguments:**");
    assert_eq!(
        arg_headings, 1,
        "a renderer would see {arg_headings} Arguments headings, not one: {:?}",
        params.message
    );
    let args = args.unwrap_or_else(|| {
        panic!("the Arguments block did not close; summary {summary:?} produced:\n{}", params.message)
    });
    assert_eq!(
        args, summary,
        "the arguments shown are not the arguments passed: {:?}",
        params.message
    );

    // Whatever the command contains, the prompt still ends with the question:
    // a prompt whose tail has been rewritten is a prompt for something else.
    assert!(
        params.message.ends_with("\nProceed?"),
        "the prompt does not end in its own question: {:?}",
        params.message
    );

    // ── nothing but an explicit accept is consent ─────────────────────
    let Ok(answer) = serde_json::from_slice::<serde_json::Value>(answer_bytes) else {
        return;
    };
    if destructive_confirmation_granted(&answer) {
        assert_eq!(
            answer.get("action").and_then(serde_json::Value::as_str),
            Some("accept"),
            "consent was granted without action=accept: {answer}"
        );
        assert_eq!(
            answer
                .get("content")
                .and_then(|c| c.get("confirm"))
                .and_then(serde_json::Value::as_bool),
            Some(true),
            "consent was granted without content.confirm=true: {answer}"
        );
    }

    // The typed shape must not disagree with the untyped read on what the
    // client said: a reply the server acts on is a reply it can name.
    let _ = serde_json::from_slice::<ElicitationCreateResult>(answer_bytes);
});
