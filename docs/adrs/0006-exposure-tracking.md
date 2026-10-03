# ADR-0006: Exposure tracking via recipient sets and `exposed_to`

**Status:** Accepted

## Context
After someone loses access, the team must know which secrets they could read and which still
need their real credential rotated. The original design used `content_generation` and
`last_exposure_*` counters, which missed merged branches and interrupted removals.

## Decision
Every ciphertext write records the recipient set in the encrypted header and goes through
one pure function, `next_header` (plan.md §6.1):
- a rewrite that drops recipients without changing plaintext adds them to `exposed_to`;
- a plaintext change clears `exposed_to`.

`status` reports `NEEDS ROTATION: exposed to <user>` and still exits 0 (plan.md §2 decision 4).

## Consequences
- `user remove` flags every secret; `rotate`/`user add` change nothing; editing and sealing
  clears only that file; secrets added after a removal are never flagged.
- Branch-only secrets that still list a removed user are flagged on the next `rotate`.
- State lives inside each file, so it survives `git mv`; no secret UUIDs needed.
- Removing any key (even a routine device swap) flags exposure: conservative
  (plan.md §2 decision 5).
- Re-encryption is never reported as credential rotation.

## Alternatives considered
- Generation counters (original design): missed merges and interrupted removals.
- Per-value tracking: needs format-aware parsing (ADR-0001).
