# ADR-0003: One age file per secret instead of epoch keys

**Status:** Accepted (plan.md §2 decision 1 can flip it)

## Context
The original design wrapped a per-epoch symmetric key (`key.age`, HKDF, XChaCha20-Poly1305,
a custom container). That is a hand-built crypto composition with "mixed epoch" states.

## Decision
Each `*.amaga` is a standard binary age file encrypted directly to every current member key.
The decrypted payload is one JSON header line plus the plaintext body (plan.md §5.2).
Membership changes rewrite every secret, as epochs did.

## Consequences
- No custom container, KDF or AEAD; no epoch pointer; no mixed-epoch state.
- age members can recover plaintext with `age -d -i key.txt f.amaga | tail -n +2`.
- Lost: forgery resistance (moot, repository writers are not trusted), recipient visibility
  without decrypting (`status` needs an identity), ~100 bytes per recipient per file.
  Details in plan.md §4.

## Alternatives considered
- Epoch keys (original design): only worth it if "only members can produce valid ciphertext"
  were required, which does not hold against repository writers anyway.
