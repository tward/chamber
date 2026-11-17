# Chamber CLI
Command-line interface for the Chamber secrets' manager. Provides a comprehensive set of commands for managing secrets, vaults, and performing administrative operations from the terminal.

## Synchronization Commands

The `chamber sync` commands keep the default vault in step across machines through a sync directory. See
[Offline Synchronization](../../README.md#offline-synchronization) in the main README for the full description.

- `chamber sync`: unlock once, merge the snapshot files in the sync directory, then publish this machine's snapshot.
- `chamber sync merge`: merge the snapshot files other machines published.
- `chamber sync publish`: publish this machine's snapshot to the sync directory.
- `chamber sync enroll <output-path>`: write a `.chenroll` enrollment package and show its transfer secret once.
- `chamber sync join <package-path>`: join an existing vault from an enrollment package on a machine whose default
  vault is not initialized.

`chamber sync`, `chamber sync merge`, and `chamber sync publish` take `--dir <path>`; without it the sync directory is
`$CHAMBER_SYNC_DIR`, then `chamber/sync` under the platform data directory.

This crate is part of the [Chamber](https://github.com/mikeleppane/chamber) secrets manager ecosystem.
