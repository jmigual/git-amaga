# ADR-0010: Local config in `git config`; actor derived from the loaded identity

**Status:** Accepted

## Context
The tool needs to know where the user's age identity is and who is acting (for the audit
log). The original design used `.git/amaga/config.toml` with an `actor_user_id`.

## Decision
- Identity path: `git config --type=path amaga.identity` (any scope, overridable with
  `git -c`), falling back to the `keygen` default path if that file exists.
- Actor: the member whose public key matches a loaded age identity, else the first member
  whose GPG secret key `gpg --list-secret-keys` reports as held. gpg is probed only when no
  age identity matches (plan.md §5.5).
- No match → `NotAMember`, listing the members and the remediation.

## Consequences
- Works in worktrees and submodules, where `.git` is a file.
- The actor cannot be configured as another member's name; it is proven by key.
- age-only users never start gpg.

## Alternatives considered
- `.git/amaga/config.toml` + `actor_user_id`: breaks when `.git` is a file, duplicates
  git's config scopes, and lets the actor name drift from the key.
