# Contributing

Thanks for helping. The most useful contributions:

- **A new check.** Something an add-on can do that `halda scan` should say plainly. Add the rule in `crates/halda-scan/src/assess.rs` with a test in `crates/halda-scan/tests/scan.rs` that builds a fake machine and checks what is found, and one that checks a harmless look-alike is not flagged.
- **A new agent.** Where an agent keeps its config, in `crates/halda-scan/src/discover.rs`, with a test.
- **A new exposure route.** A way a hijacked agent gets a secret out, in `crates/halda-scan/src/exposure.rs`. It must use the fake secret and the local listener only.
- **A false alarm.** Tell us what was flagged and why it is fine. Precision matters as much as coverage.

Before opening a pull request:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Write messages and output in plain English. Say what something can do, not what category it falls in.

By contributing you agree your work is licensed under Apache-2.0.
