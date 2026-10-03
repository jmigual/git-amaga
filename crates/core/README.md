# git-amaga-core

The library behind [git-amaga](https://github.com/jmigual/git-amaga): encrypted secret files in
Git, shared with a team through age or GPG keys.

It has one `cmd_*` function per command. Each takes the directory to run in, returns typed
results and never prints. See the [API documentation](https://docs.rs/git-amaga-core) and the
[repository README](https://github.com/jmigual/git-amaga#readme) for the formats and the security
model.
