Amber is a Rust utility that makes it easy to create a cryptographically-secure timestamp of a corpus.

It is based on the [reference implementation](https://github.com/tenchd/secure_timestamp) associated with the [June 2026 secure timestamp](https://www.davidtench.com/timestamp) of the Project Gutenberg corpus.

## Quick Start: Verifying an Existing Secure Timestamp.

1. Clone this repo and `cd` into the directory.
2. `cp example_config.toml config.toml`
3. Edit the last two lines in config.toml to read:
`provided_tree_path = "testing/reference_timestamp/pgmerkle.txt"`
`provided_explain_path = "testing/reference_timestamp/canonical_pg_explain.txt"`
4. `cargo run --release -- -v`

