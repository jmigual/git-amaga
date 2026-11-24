# ADR-0019: Plaintext file mode

**Status:** Accepted (plan.md §7, §11)

## Context
`open` wrote every plaintext as a new file with mode 0600, so it also reset a mode the user had
set. Secrets are often read by a service that runs as another user, for example a container
reading a Docker secret as uid 33, which needs 0644 or 0640. After a secret changed, `open` broke
that service until someone ran `chmod` again. A fresh clone had the same problem on its first
`open`. git-crypt had none of this: its plaintexts were written by `git checkout`, so they got
the umask's mode, which made migrated repositories fail later and silently.

## Decision
- When `open` writes a plaintext, its mode is, in this order: the `amaga-mode` git attribute of
  the plaintext path; else the permission bits of the file it replaces; else 0600.
- `amaga-mode` is three or four octal digits with owner read-write and at most read for group
  and others: 0600, 0640, 0604 or 0644. Execute bits, write for group or others, and an owner
  without read-write are refused (`ModeAttributeInvalid`), as are a set, unset or empty
  attribute. `open` reads the attribute of every selected secret, in one `git check-attr` call,
  before it writes any plaintext, so one bad value writes nothing.
- A mode with group or other bits is set on the temp file once its contents are written, before
  the rename, so the umask does not change it and `path` never has the wrong mode. Until then
  the temp file is at most owner read-write.
- The mode of a replaced file is kept after a clamp, `existing & 0o644 | 0o600`: execute bits,
  write for group or others and the special bits are dropped, and owner read-write is forced. So
  a kept mode is always one `amaga-mode` could have set.
- On other platforms the attribute is still validated, but no mode is set.

## Alternatives
- **Keep the old mode only.** Smallest change, but a fresh clone, or `close` then `open`, gives
  0600 again: nothing records the mode.
- **Record the mode in the secret's encrypted header.** Works with no extra configuration, but
  changes the header format, and `seal` would need a mode-only change state next to the
  content-based states of ADR-0009.
- **Use the umask, as git does.** Makes every secret readable by every local user by default.

## Consequences
- A repository states its non-default modes in `.gitattributes`, where review sees them.
- An attribute that is changed later takes effect at the next `open` that writes the file; an
  in-sync plaintext is not rewritten and keeps its mode.
- Any member can widen a secret's mode on every checkout through a merged `.gitattributes` line,
  so review is the safeguard. A local `.git/info/attributes` line (`<pattern> amaga-mode=0600`)
  overrides it.
- A mode wider than 0600 needs a filesystem that supports chmod; a 0600 write makes no chmod call.
- One more `git check-attr` call per `open` that selects any secret.
