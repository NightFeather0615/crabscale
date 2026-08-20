# Model implementation guide

This guide is for small-model implementers working on one issue at a time.

## Before coding

1. Read the issue, its linked wiki spec, and the crate README if one exists.
2. Run the existing test suite for the crate you will change.
3. Create a branch named `<issue-number>-<short-slug>`.
4. Do not modify unrelated crates.

## Issue shape

Every implementation issue contains:

- `Goal`: one sentence.
- `Scope`: explicit in/out of scope.
- `Contract`: file names, function signatures, or JSON examples to target.
- `Tasks`: ordered checklist, fewer than 8 items.
- `Acceptance`: commands that must pass or observable behavior.

If an issue is missing one of these sections, do not guess. Add a comment and stop.

## Implementation rules

- Tests first: add a failing test for each acceptance criterion before implementation.
- Wire behavior is implemented in `crabscale-proto` or `crabscale-transport` only.
- Policy decisions live in `crabscale-policy`.
- No `unwrap()` or `expect()` on untrusted input in protocol paths; return structured errors.
- Enforce size limits before parsing JSON or allocating from a length prefix.
- Logging may not contain private keys, auth keys, or full tokens.
- Keep functions small enough to review in isolation.

## Verification

- Run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- For protocol changes, run the relevant golden test command from the issue.
- Paste the output of the acceptance commands into the PR description.

## Definition of done

- All issue acceptance criteria are met.
- The wiki is updated in the same PR if a wire rule or config rule changed.
- No new dependency was added without a one-line justification in the PR.
