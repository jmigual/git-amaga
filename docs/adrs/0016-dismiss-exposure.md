# ADR-0016: `dismiss` clears exposure without a plaintext change

**Status:** Accepted (plan.md §7); amended by ADR-0017 (without paths, only the actor's partitions)

## Context
`exposed_to` is cleared only by a plaintext change (ADR-0006). Sometimes no credential needs
rotating: a removed member's keys are known to be destroyed, or a member swapped a device key
(ADR-0012). Today the only way out is changing the content or `seal --force`, and neither says
what happened.

## Decision
- `git-amaga dismiss [--user <name>]… [<path>…]` removes the named members (default: all) from
  `exposed_to` of the named secrets (default: all). At least one path or `--user` is required.
- A `--user` that appears in no selected secret's `exposed_to` is an error (typo guard). Names
  need not be current members: a member whose old key was swapped can be dismissed too.
- Without paths, the selection is every secret in a partition the actor is listed in
  (ADR-0017); the stale guard applies to each selected secret's partition.
- All selected secrets are decrypted before anything is written. A secret with nothing to
  dismiss is left untouched. The others are rewritten under the current epoch through
  `next_header(old, false, …)`, after which the dismissed names are removed. The epoch must
  not be stale (ADR-0015).
- One audit event `exposure.dismissed` per path and member. Never `secret.updated`; plaintext
  and base hashes are untouched.
- Named `dismiss`, not `ack` (which reads as "seen" while the flag stays) and not a `rotate`
  flag (`rotate` only re-encrypts).

## Consequences
- `status` stops flagging those secrets. The reason is a human assertion; the audit line
  records who made it.
- Re-encryption is still never reported as credential rotation.
- The noise of removing a routine key (plan.md §2 decision 5) is cleared with
  `dismiss --user <name>`; no `user key` subcommand is needed.

## Alternatives considered
- `ack`: ambiguous about whether the flag stays.
- Bare `dismiss` meaning "everything": one mistyped command would clear all tracking.
- An `--all` flag: naming the members or paths already covers it.
- Per-key dismissal: `exposed_to` is shown per member; no case needs finer control.
