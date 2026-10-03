# Fixture generation (plan 11)

Run in a throwaway `GNUPGHOME` (`mktemp -d /tmp/g.XXXX`), never `~/.gnupg`.

- `Q` = `gpg --batch --passphrase '' --quick-gen-key`
- `X` = `gpg --armor --export-options export-minimal --export`

| Fixture | Recipe |
|---------|--------|
| `valid_cv25519.asc` | `Q 'Valid <valid@example.invalid>' default default never`; `X <fpr>` |
| `valid_cv25519.secret.asc` | `gpg --batch --passphrase '' --armor --export-secret-keys <fpr>` |
| `valid_cv25519_crlf.asc` | `sed 's/$/\r/' valid_cv25519.asc` |
| `valid_rsa.asc` | `Q 'Rsa <rsa@example.invalid>' rsa2048 default never`; `gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key <fpr> rsa2048 encr never`; `X <fpr>` |
| `sign_only.asc` | `Q 'SignOnly <signonly@example.invalid>' default sign never` (no subkey); `X <fpr>` |
| `revoked.asc` | the `valid_cv25519` key; `gpg --no-tty --yes --pinentry-mode loopback --command-fd 0 --gen-revoke <fpr> > revoke.asc` (stdin `y\n0\n\ny\n`); `gpg --batch --yes --import revoke.asc`; `X <fpr>` |
| `third_party.asc` | keys Signee and Signer; `gpg --batch --yes --pinentry-mode loopback --passphrase '' --local-user <signer-fpr> --quick-sign-key <signee-fpr>`; `gpg --armor --export <signee-fpr>` (no export-minimal, which would drop the certification) |
| `two_keys.asc` | two keys in one keyring; `X <fpr1> <fpr2>` (one armor block; the separately armored case is built in-test by concatenation) |
| `garbage.asc` | `printf 'this is not an openpgp key\n'` |
| `expired.asc` | the `valid_cv25519` recipe under `--faked-system-time 20240101T000000` with expiry `1d`; plain `gpg --armor --export <fpr>` (export-minimal drops an already-expired subkey) |
| `subkey_expired.asc` | primary + encryption subkey (`never`) at `20240101T000000`, then a newer encryption subkey (`--quick-add-key <fpr> default encr 1d`) at `20240102T000000`; plain export |
| `two_subkeys.asc` | primary + encryption subkey (the expected pick), then a newer encryption subkey under a future faked time, revoked via `gpg --command-fd 0 --edit-key <fpr>` (stdin `key 2\nrevkey\ny\n0\n\ny\nsave\n`), then a newer sign-only subkey (`--quick-add-key <fpr> rsa2048 sign never`); `X <fpr>` |
| `rotated_subkey_old.asc` | `Q 'Rotate <rotate@example.invalid>' default default never`; `X <fpr>` |
| `rotated_subkey_new.asc` | the same key after `gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key <fpr> default encr never`; `X <fpr>` (same primary fingerprint, different encryption subkey) |
