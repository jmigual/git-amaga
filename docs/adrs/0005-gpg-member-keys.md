# ADR-0005: GPG member keys: export-minimal `.asc`, subkey-fingerprint identity, add-time expiry

**Status:** Accepted

## Context
A GPG member is stored as `.amaga/users/<name>.asc`. We must decide what an acceptable key
file is, how a key is identified in headers, and when expiry matters.

## Decision
- The `.asc` holds exactly one armored public key and must pass rPGP `verify_bindings()`,
  which rejects third-party certifications, so keys are exported with
  `--export-options export-minimal` (plan.md §5.1). It is stored byte-for-byte.
- A key is identified by its **encryption subkey** fingerprint, `pgp:<FPR>` (the newest
  non-revoked encryption-capable subkey). Encrypting to a primary key is unsupported.
- Structure, signatures and revocation are checked on every load; expiry only at
  `init`/`user add` (plan.md §1 change 18, §2 decision 9).

## Consequences
- Replacing a lost card's subkey is a key change: secrets go stale and `rotate` flags
  exposure, like a removed age key. Extending expiry keeps the fingerprint: no change.
- A key that expires after being added is still encrypted to, so one member's expiry never
  blocks the team's `seal`/`rotate`. Loading stays clock-free and deterministic.
- New subkeys or revocations take effect only when a re-exported `.asc` is committed and
  someone runs `rotate`.

## Alternatives considered
- Identify by primary fingerprint: a subkey swap would silently keep old ciphertext valid.
- Refuse expired keys on every encrypt (as `gpg -e` does): blocks the whole team and makes
  loading depend on the clock.
