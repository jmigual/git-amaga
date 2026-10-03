# ADR-0006: Exposure tracking via epoch member sets and `exposed_to`

**Status:** Accepted; amended by ADR-0015 (member sets live in epoch files), ADR-0016
(`dismiss`) and ADR-0017 (partitions)

## Context
After someone loses access, the team must know which secrets they could read and which still
need their real credential rotated. The original design used `content_generation` and
`last_exposure_*` counters, which missed merged branches and interrupted removals.

## Decision
Every epoch file records the member key set it was wrapped to (ADR-0015). Every ciphertext
write goes through one pure function, `next_header` (plan.md §6.1), given the members of the
epoch that decrypted the file and of the epoch it is written to:
- a rewrite without a plaintext change adds every key of the old epoch that the new epoch
  lacks to `exposed_to`;
- a plaintext change clears `exposed_to`;
- `dismiss` removes named members from it explicitly (ADR-0016).

`status` reports `NEEDS ROTATION: exposed to <user>` and still exits 0 (plan.md §2 decision 4).

## Consequences
- `user remove` flags every secret; `rotate` changes nothing; `user add` rewrites no secret;
  editing and sealing clears only that file; secrets added after a removal are never flagged.
- Branch-only secrets still under an epoch that included a removed user are flagged on the
  next `rotate`.
- `exposed_to` lives inside each file, so it survives `git mv`; no secret UUIDs needed.
- Removing any key (even a routine device swap) flags exposure: conservative
  (plan.md §2 decision 5); `dismiss` clears it.
- Re-encryption is never reported as credential rotation.
- Partitions (ADR-0017) use the same rule: `partition remove` flags only that partition's
  secrets, and `partition move` flags the members of the old epoch who are missing from the new one.

## Alternatives considered
- Generation counters (original design): missed merges and interrupted removals.
- Per-value tracking: needs format-aware parsing (ADR-0001).
- A recipient set per secret (ADR-0003): duplicated in every file; the epoch already has it.
