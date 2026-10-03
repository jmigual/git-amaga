# ADR-0017: Partitions

**Status:** Accepted (plan.md §5.7, §7, §16); amends ADR-0006, ADR-0007, ADR-0012, ADR-0015, ADR-0016

## Context
Requested: some members should read only some secrets, for example a `production` and a
`staging` set, or `developers` and `admins`. With one epoch per repository (ADR-0015), every
member can unwrap every secret. Access must stay enforced by encryption, using standard age only.

## Decision
- A **partition** is a named member list with its own epoch chain:
  `.amaga/partitions/<p>/members` (member names, one per line) and
  `.amaga/partitions/<p>/current-epoch` (its pointer). A listed name without a user file grants
  nothing. Epoch files stay flat in `.amaga/epochs/`, because their names are already unique.
  Partition names follow the member-name rule (ADR-0012).
- `init` creates `default`. Its `members` file is explicit, like every other partition's.
  `user add` joins `default` unless `--partition` is given. There are no groups.
- Every secret carries one label stanza, `-> amaga-partition <p>`, with an empty body. It is
  written through age's `Recipient` trait next to the epoch's X25519 stanza. Anyone can read it
  without a key, and age clients ignore it. The header MAC covers it, so a member who decrypts
  the file detects a changed label. **The label is the truth.** It picks the current epoch to
  try first, the partition that `rotate` re-encrypts the secret into, and whether the actor may
  decrypt the secret at all.
- A secret's partition is chosen once, when it is created: from `add --partition`, else from
  the `amaga-partition` git attribute of the plaintext path, else `default`. After that, only
  `partition move <p> <path>…` changes it. `status` reports an error when an attribute is set and
  differs from the label. Nothing acts on the attribute after `add`.
- **Access:** a command decrypts a secret only if the actor is listed in the secret's partition
  (`NotInPartition`). Commands run without paths skip secrets in other partitions. `status` lists
  those secrets as `not a member` at level ok.
- **Stale guard per partition:** writing into partition P (`add`, `seal`, `dismiss`,
  `partition move`, `partition add`, `user add`) requires P's current epoch to be wrapped to
  exactly the keys of the users listed in P.
- **Commands:**
  - `partition create <p> <member>…` writes a new epoch.
  - `partition add <p> <member>…` re-wraps P's current epoch, as `user add` does.
  - `partition remove <p> <member>…` re-encrypts P's secrets under a new epoch.
  - `rotate [--partition <p>]…` covers, by default, every partition that lists the actor.
  - `user remove <name>` removes the name from every partition. It re-encrypts only the
    partitions the actor is in that list the name or whose current epoch was wrapped to it
    (so a rerun after an interruption or a hand edit of `members` still locks them out), and
    reports the other partitions that list the name as not rotated.
  - `user add` refuses while the name is listed in any partition, so a name left behind by a
    merge cannot give a different person that partition's access.
  - No command may leave a partition without members.
- **Exposure** keeps its rule (ADR-0006): `next_header` compares the member sets of the old and
  the new epoch. Removing someone from P flags P's secrets. Moving a secret flags the members of
  its old epoch who are missing from the new one.

## Consequences
- A command makes one gpg call per partition it touches (ADR-0015 says one per command).
- Single-partition repositories behave as before, except that the pointer moves to
  `.amaga/partitions/default/current-epoch`.
- A careless `.gitattributes` edit cannot widen who reads a secret. `rotate` follows the label,
  and `status` fails until either the attribute or the label is fixed.
- After `user remove`, a partition the actor is not in stays stale until one of its members
  runs `rotate`. Until then the removed key can still open that partition's current epoch, as
  after an interrupted run (ADR-0007).
- Partition names and their member lists are readable by anyone with repository access.
- Concurrent edits to one `members` file conflict as text. Every command refuses while
  `.amaga/partitions` is unmerged.

## Alternatives considered
- Taking the partition from the attribute on every `rotate`: one `.gitattributes` edit would
  silently move secrets into a wider partition on the next `rotate` by a member.
- Learning the partition only from the epoch that decrypts a secret: non-members cannot tell
  where a secret belongs. `rotate` also cannot tell "my partition, under an older epoch I do not
  hold" (it must abort) from "another partition" (it must skip).
- An index file mapping paths to partitions: breaks on `git mv` and in merges, and is not
  authenticated.
- Recording the partition in the epoch header: readable only by that partition's members.
- An implicit `default` containing every member: a member who should see only `staging` would
  force every other secret out of `default`.
- Refusing `user remove` unless the actor is in all of the member's partitions: deadlocks when
  no single member is in all of them.
- One `.amaga/epochs/<p>/` directory per partition: epoch names are already unique, and the
  "try older epochs" lookup (plan §5.6) needs one listing.
- Groups: not requested.
- A secret in several partitions: encrypt to each partition's current epoch, with one label
  stanza per partition; readers are the union. Deferred (plan §13). It is additive, because
  single-label files stay valid. Until then, use a partition whose members are the union.
