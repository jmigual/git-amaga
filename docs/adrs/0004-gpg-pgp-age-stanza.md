# ADR-0004: GPG members via a custom `pgp` age stanza (rPGP encrypts, `gpg` decrypts)

**Status:** Accepted

## Context
The maintainer's own keys are GPG, often on smartcards behind gpg-agent; age must remain an
option. Supporting both should not create two file formats or two exposure states.

## Decision
- A secret stays one age file. A GPG member gets an extra stanza `-> pgp <SUBKEY-FPR>` whose
  body is an OpenPGP message (PKESK v3 + SEIPD v1, AES-256) carrying the 16-byte age file key
  (plan.md §5.2.1), written through age's public `Recipient`/`Identity` traits.
- Encryption is in-process with rPGP (`pgp` crate), so encrypting never needs gpg.
- Decryption runs `gpg --decrypt` per stanza without `--batch`, so pinentry and card prompts
  work (plan.md §7.3). gpg runs only when no age identity matches.
- SEIPD v1 because GnuPG does not implement RFC 9580 SEIPD v2.
- `GpgIdentity` overrides age's `unwrap_stanzas`, which stops at the first stanza returning
  `Some`, even `Some(Err(_))`. With two held GPG keys and one card inserted, one key's gpg
  failure would mask another's success. It returns the first `Ok`, else the first `Err`, else
  `None`.
- Stanza bodies over 8 KiB are rejected before spawning gpg. A real body (PKESK v3 + SEIPD v1
  around a 16-byte file key) is a few hundred bytes; an oversized one could deadlock the
  stdin/stdout pipes (gpg blocked writing output while this process blocks writing input).

## Consequences
- age-only members never need gpg; `age -d` keeps working for them.
- GPG members cannot decrypt without this tool (age CLI cannot take a gpg-unwrapped key).
- One gpg call per secret: N secrets mean N calls, and a touch-always card needs N touches.
  Known ceiling; batching is deferred (plan.md §13).
- `rsa` is in the tree via `pgp`, only for public-key operations (RUSTSEC-2023-0071 is not
  exploitable here, plan.md §2 decision 2).

## Alternatives considered
- A separate `.gpg` file per secret: two formats, two exposure states.
- OpenPGP as the outer format: loses the `age -d` escape hatch.
- age plugins (`age-plugin-yubikey`): deferred; YubiKeys already work as GPG cards.
