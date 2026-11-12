# Contributing

## Checks

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
python3 scripts/check_studied_names.py
```

On Windows, `python` is the usual interpreter name. `cargo test` includes the studied-name checker tests.

## Studied-name check

Tracked files (source, comments, tests, docs, and commit-tracked config) must not name upstream projects this repository studies. Describe the capability instead (for example, "a feature-flag service" or "an evolutionary algorithm-design framework").

The denylist itself is not stored in the repository. `scripts/check_studied_names.py` reads names from the first source that exists and is non-empty:

1. `CARNOT_STUDIED_NAME_DENYLIST` — newline- or comma-separated names.
2. `CARNOT_STUDIED_NAME_DENYLIST_FILE` — path to a newline-separated names file (`#` comments allowed).
3. `.carnot/studied-name-denylist.txt` at the repository root.

`.carnot/` is gitignored. Local lineage notes belong only in `.carnot/local-lineage.jsonl`. Do not add a committed file that maps previous names to the wording in the tree.

If none of those sources is set, the checker exits 0 and prints that it skipped. A source that is set but missing, unreadable, or empty after comments are stripped exits 2 and does not skip. Whitespace-only `CARNOT_STUDIED_NAME_DENYLIST` counts as unset and falls through to the file sources. Continuous integration passes `CARNOT_STUDIED_NAME_DENYLIST` from a repository secret of the same name. An unset or empty secret skips the check; it does not fail the job.

The checker prints paths and line numbers only. It does not print matched text.
