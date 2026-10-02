# ADR-0013: `KEY` arguments can name a key in the local gpg keyring

**Status:** Accepted (implementation: plan.md §12 step 7b)

## Context
Requested: users should not have to type `gpg` or `age` commands themselves. Exporting a key
by hand risks the wrong format, and the `.asc` must be export-minimal (ADR-0005). age has no
keyring to look keys up in.

## Decision
- `KEY` (for `init` and `user add`) is classified: starts with `age1` → age recipient; an
  existing file ending in `.asc` → key file; anything else → a gpg key spec (plan.md §7).
- Lookup (plan.md §7.4): `gpg --list-keys --with-colons <spec>` must yield exactly one primary
  key. A bare email is wrapped as `<email>` for an exact match (gpg otherwise matches
  substrings). Then `gpg --export --armor --export-options export-minimal <FPR>` and the
  normal validation. Output and audit record the primary fingerprint and user ID.
- More than one match → error listing fingerprints and user IDs; none → "not in your local
  keyring"; gpg missing → clear error suggesting an `.asc` file.
- age: `keygen` prints the public key and the `git-amaga user add <name> age1…` line to send
  to an existing member. No age CLI anywhere.

## Consequences
- The stored `.asc` is always export-minimal, even if the keyring copy carries third-party
  certifications.
- `init`/`user add` read the local public keyring at add time only; loading still uses only
  the committed `.asc` files.
- No confirmation prompt (plan.md §2 decision 10) and no network fetch (decision 11).

## Alternatives considered
- File-only `KEY`s: users must remember the export flags.
- Fetching from a keyserver/WKD (`gpg --locate-keys`): raises network trust questions; deferred.
- Interactive confirmation of the looked-up key: blocks scripting; printing it is enough.
