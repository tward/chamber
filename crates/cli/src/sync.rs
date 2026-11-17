//! The `chamber sync` command family: publishing and merging snapshots through a sync directory,
//! and adding a machine to a vault with an enrollment package.
//!
//! The vault library does the work ([`Vault::publish_snapshot`], [`Vault::merge_snapshots`],
//! [`Vault::write_enrollment_package`], [`EnrollmentPackage`], [`Vault::join_enrollment`]); the
//! commands here only gather input, call it, and print what it reports.
//!
//! Each command has a thin outer part that opens the default vault, reads the environment, and
//! prompts, and an inner part that takes the vault, the resolved paths, and an output writer, so
//! tests can drive the inner part with a temp vault and capture what it prints. `join` asks its
//! questions through [`JoinPrompts`], which tests script.
//!
//! Nothing printed here contains an entry name, a secret value, a key, or payload contents. The
//! one secret ever shown is the transfer secret `enroll` creates, printed once.

use crate::prompt_secret;
use chamber_vault::enroll::{ENROLLMENT_EXTENSION, EnrollmentError, EnrollmentPackage, TransferSecret};
use chamber_vault::sync_dir::display_file_name;
use chamber_vault::{FileOutcome, MergeReport, PublishReport, SYNC_DIR_ENV, Vault, resolve_sync_dir};
use clap::Subcommand;
use color_eyre::Result;
use color_eyre::eyre::eyre;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, BufRead as _, Write};
use std::path::{Path, PathBuf};

/// The prompt every command that unlocks the default vault uses.
const MASTER_KEY_PROMPT: &str = "Enter master key: ";

/// The subcommands of `chamber sync`. Without one, `chamber sync` merges and then publishes.
#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum SyncCommand {
    /// Merge the snapshot files other machines published in the sync directory
    Merge {
        #[arg(
            long,
            value_name = "PATH",
            help = "Sync directory to read (default: $CHAMBER_SYNC_DIR, then chamber/sync under the data directory)"
        )]
        dir: Option<PathBuf>,
    },

    /// Publish this machine's snapshot to the sync directory
    Publish {
        #[arg(
            long,
            value_name = "PATH",
            help = "Sync directory to write (default: $CHAMBER_SYNC_DIR, then chamber/sync under the data directory)"
        )]
        dir: Option<PathBuf>,
    },

    /// Write an enrollment package that lets another machine join this vault
    Enroll {
        #[arg(
            value_name = "OUTPUT_PATH",
            help = "New file to write the package to; its name must end in .chenroll"
        )]
        output: PathBuf,
    },

    /// Join an existing vault from an enrollment package (this machine's vault must be new)
    Join {
        #[arg(
            value_name = "PACKAGE_PATH",
            help = "Enrollment package written by `chamber sync enroll` on a machine that has the vault"
        )]
        package: PathBuf,
    },
}

/// Runs `chamber sync`: `dir` is the `--dir` given to bare `chamber sync`, and `command` the
/// subcommand, if any. Bare `chamber sync` merges and then publishes.
///
/// # Errors
/// Returns an error when the default vault cannot be opened, is not initialized (for `merge`,
/// `publish`, `enroll`, and bare `sync`) or is already initialized (for `join`), when a prompt
/// fails, when the master key is wrong, when the library refuses or fails the operation, or when
/// any snapshot file was skipped during a merge.
pub fn handle_sync_command(dir: Option<&Path>, command: Option<&SyncCommand>) -> Result<()> {
    match command {
        None => {
            let (mut vault, sync_dir) = open_for_sync(dir)?;
            run_sync(&mut vault, &sync_dir, &mut io::stdout().lock())
        }
        Some(SyncCommand::Merge { dir }) => {
            let (mut vault, sync_dir) = open_for_sync(dir.as_deref())?;
            run_merge(&mut vault, &sync_dir, &mut io::stdout().lock())
        }
        Some(SyncCommand::Publish { dir }) => {
            let (vault, sync_dir) = open_for_sync(dir.as_deref())?;
            run_publish(&vault, &sync_dir, &mut io::stdout().lock())
        }
        Some(SyncCommand::Enroll { output }) => {
            let mut vault = Vault::open_or_create(None)?;
            require_initialized(&vault)?;
            check_enroll_output(output)?;
            let master = prompt_secret(MASTER_KEY_PROMPT)?;
            vault.unlock(&master)?;
            run_enroll(&vault, output, &mut io::stdout().lock())
        }
        Some(SyncCommand::Join { package }) => {
            let mut vault = Vault::open_or_create(None)?;
            // Not locked: the terminal prompts print to stdout between the lines written here.
            run_join(&mut vault, package, &mut TerminalJoinPrompts, &mut io::stdout())
        }
    }
}

// ---- Shared steps ----

/// The outer part of `merge`, `publish`, and bare `sync`: opens the default vault, checks that it
/// is initialized, resolves the sync directory from `explicit` and `CHAMBER_SYNC_DIR`, and
/// unlocks the vault with the master key the user enters.
fn open_for_sync(explicit: Option<&Path>) -> Result<(Vault, PathBuf)> {
    let mut vault = Vault::open_or_create(None)?;
    require_initialized(&vault)?;
    let env_value = std::env::var_os(SYNC_DIR_ENV);
    let sync_dir = resolve_dir(explicit, env_value.as_deref())?;
    let master = prompt_secret(MASTER_KEY_PROMPT)?;
    vault.unlock(&master)?;
    Ok((vault, sync_dir))
}

/// Resolves the sync directory: `explicit` (from `--dir`), then `env_value` (the value of
/// `CHAMBER_SYNC_DIR`, read by the caller; empty counts as unset), then the default.
fn resolve_dir(explicit: Option<&Path>, env_value: Option<&OsStr>) -> Result<PathBuf> {
    resolve_sync_dir(explicit, env_value)
}

/// Fails, naming the way forward, when `vault` has never been initialized. Run before any prompt.
fn require_initialized(vault: &Vault) -> Result<()> {
    if vault.is_initialized() {
        return Ok(());
    }
    Err(eyre!(
        "The vault at {} is not initialized. Run `chamber init` to create a new vault, or \
         `chamber sync join <package-path>` to join an existing vault from an enrollment package.",
        vault.db_path().display()
    ))
}

// ---- Merge, publish, and bare sync ----

/// The inner part of `chamber sync merge`: merges the candidate files in `sync_dir` into the
/// unlocked `vault` and writes the report to `out`.
///
/// # Errors
/// Returns the library's error when the merge as a whole fails, and an error stating how many
/// files were skipped, after the report is written, when any was.
fn run_merge<W: Write>(vault: &mut Vault, sync_dir: &Path, out: &mut W) -> Result<()> {
    let report = vault.merge_snapshots(sync_dir)?;
    write_merge_report(&report, sync_dir, out)?;
    fail_if_skipped(&report)
}

/// The inner part of `chamber sync publish`: publishes the unlocked `vault`'s snapshot into
/// `sync_dir` and writes what was written to `out`.
///
/// # Errors
/// Returns the library's error when the publication fails.
fn run_publish<W: Write>(vault: &Vault, sync_dir: &Path, out: &mut W) -> Result<()> {
    let publication = vault.publish_snapshot(sync_dir)?;
    write_publish_report(&publication, out)
}

/// The inner part of bare `chamber sync`: merges, then publishes with the same unlocked vault, so
/// the published snapshot includes what was just merged. It publishes even when files were
/// skipped, and only then reports the skipped files as an error.
///
/// # Errors
/// Returns the merge error, without publishing, when the merge as a whole fails; the
/// publication error when publishing fails; and otherwise an error stating how many files were
/// skipped, when any was.
fn run_sync<W: Write>(vault: &mut Vault, sync_dir: &Path, out: &mut W) -> Result<()> {
    let report = vault.merge_snapshots(sync_dir)?;
    write_merge_report(&report, sync_dir, out)?;
    let publication = vault.publish_snapshot(sync_dir)?;
    write_publish_report(&publication, out)?;
    fail_if_skipped(&report)
}

/// Writes one line per candidate file (merged with its counts, or skipped with the reason), or
/// a single line saying there is nothing to merge. Only file names, counts, and rejection
/// messages are printed.
///
/// Anyone who can write to the sync directory chooses the file names, so each name in a
/// "Merged" or "Skipped" line is written through [`display_file_name`]: every control character
/// is replaced by its `\u{..}` escape (`\u{1b}` for ESC), and nothing else is changed.
fn write_merge_report<W: Write>(report: &MergeReport, sync_dir: &Path, out: &mut W) -> Result<()> {
    if report.is_empty() {
        writeln!(out, "Nothing to merge: no snapshot files in {}.", sync_dir.display())?;
        return Ok(());
    }
    for file in &report.files {
        let name = display_file_name(&file.file_name);
        match &file.outcome {
            FileOutcome::Merged(counts) => writeln!(
                out,
                "Merged {name}: {} added, {} replaced, {} removed by a tombstone, {} unchanged",
                counts.added, counts.replaced, counts.removed, counts.unchanged
            )?,
            FileOutcome::Skipped(rejection) => writeln!(out, "Skipped {name}: {rejection}")?,
        }
    }
    Ok(())
}

/// Writes the published file with its entry and tombstone counts and its snapshot ID, for
/// example `Published <path>: 1 entry, 2 tombstones (snapshot <id>)`. A count of one takes the
/// singular noun; every other count, zero included, takes the plural.
fn write_publish_report<W: Write>(publication: &PublishReport, out: &mut W) -> Result<()> {
    writeln!(
        out,
        "Published {}: {} {}, {} {} (snapshot {})",
        publication.path.display(),
        publication.entries,
        if publication.entries == 1 { "entry" } else { "entries" },
        publication.tombstones,
        if publication.tombstones == 1 {
            "tombstone"
        } else {
            "tombstones"
        },
        publication.snapshot_id
    )?;
    Ok(())
}

/// An error stating how many files `report` skipped, or `Ok` when it skipped none.
fn fail_if_skipped(report: &MergeReport) -> Result<()> {
    match report.skipped().count() {
        0 => Ok(()),
        1 => Err(eyre!("1 snapshot file was skipped; the reason is shown above.")),
        n => Err(eyre!("{n} snapshot files were skipped; the reasons are shown above.")),
    }
}

// ---- Enroll ----

/// Refuses an enrollment output path that does not end in `.chenroll` or where something already
/// exists, so the user is told before entering the master key. The library checks both again.
fn check_enroll_output(path: &Path) -> Result<()> {
    if path.extension() != Some(OsStr::new(ENROLLMENT_EXTENSION)) {
        return Err(EnrollmentError::WrongExtension.into());
    }
    if fs::symlink_metadata(path).is_ok() {
        return Err(EnrollmentError::OutputExists.into());
    }
    Ok(())
}

/// The inner part of `chamber sync enroll`: writes an enrollment package from the unlocked
/// `vault` to `output` and prints its transfer secret once, with how to convey it. The package is
/// left in place.
///
/// # Errors
/// Returns the library's error when the package cannot be written.
fn run_enroll<W: Write>(vault: &Vault, output: &Path, out: &mut W) -> Result<()> {
    let secret = vault.write_enrollment_package(output)?;
    writeln!(out, "Wrote the enrollment package to {}.", output.display())?;
    writeln!(out)?;
    writeln!(out, "Transfer secret: {}", secret.display_form())?;
    drop(secret);
    writeln!(out)?;
    writeln!(
        out,
        "This secret is shown only once. Send it to the other machine separately from the package: the \
         package may travel through the sync directory, but the transfer secret must not."
    )?;
    writeln!(
        out,
        "On the other machine, run `chamber sync join <package-path>` and enter the transfer secret when asked."
    )?;
    Ok(())
}

// ---- Join ----

/// The questions `chamber sync join` asks, kept behind a trait so tests can script the answers.
trait JoinPrompts {
    /// Asks for the transfer secret without echoing it and returns what was typed.
    ///
    /// # Errors
    /// Returns an error when the terminal cannot be read.
    fn transfer_secret(&mut self) -> Result<String>;

    /// Asks whether to join the vault just described and returns the answer as typed.
    ///
    /// # Errors
    /// Returns an error when the terminal cannot be read.
    fn confirm_join(&mut self) -> Result<String>;

    /// Asks for the new local master password with `prompt`, without echoing it.
    ///
    /// # Errors
    /// Returns an error when the terminal cannot be read.
    fn new_password(&mut self, prompt: &str) -> Result<String>;
}

/// [`JoinPrompts`] on the terminal: secrets are read without echo, the confirmation from a line
/// of standard input.
struct TerminalJoinPrompts;

impl JoinPrompts for TerminalJoinPrompts {
    fn transfer_secret(&mut self) -> Result<String> {
        prompt_secret("Enter the transfer secret: ")
    }

    fn confirm_join(&mut self) -> Result<String> {
        print!("Join this vault? [y/N]: ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().lock().read_line(&mut answer)?;
        Ok(answer)
    }

    fn new_password(&mut self, prompt: &str) -> Result<String> {
        prompt_secret(prompt)
    }
}

/// Whether a confirmation answer confirms: `y` or `yes` in any letter case, ignoring surrounding
/// whitespace. Anything else, an empty answer included, declines.
fn confirms(answer: &str) -> bool {
    let answer = answer.trim();
    answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes")
}

/// The inner part of `chamber sync join`: joins `vault` to the vault in the enrollment package at
/// `package_path`, asking through `prompts` and printing to `out`.
///
/// Each step runs only if the previous one succeeded: refuse an initialized vault, check the
/// package header, ask for and check the transfer secret, show the vault UUID and entry count
/// and ask for confirmation, ask for the new master password twice, and join. Declining the
/// confirmation prints that the join was cancelled and returns `Ok`. The package is never
/// deleted, and on any refusal, failure, or cancellation the vault is left uninitialized and
/// empty.
///
/// # Errors
/// Returns an error when the vault is already initialized, the package cannot be read or is not
/// an enrollment package, the transfer secret is malformed or wrong (or the package damaged),
/// the new master password is empty or its confirmation differs, or the library join fails.
fn run_join<P: JoinPrompts, W: Write>(
    vault: &mut Vault,
    package_path: &Path,
    prompts: &mut P,
    out: &mut W,
) -> Result<()> {
    if vault.is_initialized() {
        return Err(EnrollmentError::AlreadyInitialized.into());
    }
    let package = EnrollmentPackage::read_file(package_path)?;

    let secret = TransferSecret::parse(&prompts.transfer_secret()?)?;
    let enrollment = package.open(&secret)?;
    drop(secret);

    let vault_uuid = enrollment.vault_uuid();
    let entries = enrollment.entry_count();
    writeln!(
        out,
        "The package joins vault {vault_uuid} and carries {entries} {}.",
        if entries == 1 { "entry" } else { "entries" }
    )?;
    out.flush()?;
    if !confirms(&prompts.confirm_join()?) {
        writeln!(out, "Join cancelled. Nothing was changed.")?;
        return Ok(());
    }

    let master = prompts.new_password("Create master key: ")?;
    if master.is_empty() {
        return Err(eyre!("Master key cannot be empty"));
    }
    if prompts.new_password("Confirm master key: ")? != master {
        return Err(eyre!("Master keys do not match"));
    }
    vault.join_enrollment(&enrollment, &master)?;

    writeln!(
        out,
        "Joined vault {vault_uuid} at {}. It unlocks with the master key you just set.",
        vault.db_path().display()
    )?;
    writeln!(
        out,
        "Delete the enrollment package {} now, and discard the transfer secret.",
        package_path.display()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]
    use super::*;
    use crate::test_support::{MASTER_PASSWORD, new_item};
    use crate::{Cli, Commands};
    use chamber_vault::snapshot::SnapshotRejection;
    use chamber_vault::{Db, FileReport, MergeCounts, SyncDirError, default_sync_dir, snapshot_file_name};
    use clap::Parser;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;
    use tempfile::TempDir;

    // ---- Fixtures ----

    /// A machine: a vault at `vault.db` in its own temp directory. Fields drop in declaration
    /// order, so the vault closes its database before the directory is removed.
    struct Machine {
        vault: Vault,
        dir: TempDir,
    }

    impl Machine {
        /// A machine whose vault has never been initialized.
        fn uninitialized() -> Self {
            let dir = TempDir::new().unwrap();
            let vault = Vault::open_or_create(Some(&dir.path().join("vault.db"))).unwrap();
            Self { vault, dir }
        }

        /// A machine with an initialized vault, unlocked with [`MASTER_PASSWORD`].
        fn initialized() -> Self {
            let mut machine = Self::uninitialized();
            machine.vault.initialize(MASTER_PASSWORD).unwrap();
            machine.vault.unlock(MASTER_PASSWORD).unwrap();
            machine
        }

        fn add(&mut self, name: &str, value: &str) {
            self.vault.create_item(&new_item(name, value)).unwrap();
        }

        /// `(name, value)` of every entry, sorted.
        fn names_and_values(&self) -> Vec<(String, String)> {
            let mut pairs: Vec<_> = self
                .vault
                .list_items()
                .unwrap()
                .into_iter()
                .map(|i| (i.name, i.value))
                .collect();
            pairs.sort();
            pairs
        }

        /// Whether the vault is uninitialized and its database holds no entry and no tombstone,
        /// read without the key.
        fn assert_pristine(&self) {
            assert!(!self.vault.is_initialized(), "the vault stays uninitialized");
            let db = Db::open(self.vault.db_path()).unwrap();
            assert!(db.list_items().unwrap().is_empty(), "the vault holds no entries");
            assert!(db.tombstones().unwrap().is_empty(), "the vault holds no tombstones");
        }
    }

    /// One question `run_join` asked, with everything written to the output before it.
    #[derive(Debug)]
    struct Asked {
        question: &'static str,
        output_before: String,
    }

    /// An output buffer the test and [`ScriptedPrompts`] share, so each question can record what
    /// had been printed before it.
    #[derive(Clone, Default)]
    struct SharedOut(Rc<RefCell<Vec<u8>>>);

    impl SharedOut {
        fn text(&self) -> String {
            String::from_utf8(self.0.borrow().clone()).unwrap()
        }
    }

    impl Write for SharedOut {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// [`JoinPrompts`] answering from a script. Asking a question with no scripted answer left
    /// panics, so a test fails loudly when a refused step asks anything further.
    struct ScriptedPrompts {
        answers: VecDeque<String>,
        asked: Vec<Asked>,
        out: SharedOut,
    }

    impl ScriptedPrompts {
        fn new(out: &SharedOut, answers: &[&str]) -> Self {
            Self {
                answers: answers.iter().map(|a| (*a).to_string()).collect(),
                asked: Vec::new(),
                out: out.clone(),
            }
        }

        fn answer(&mut self, question: &'static str) -> String {
            self.asked.push(Asked {
                question,
                output_before: self.out.text(),
            });
            self.answers
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected question: {question}"))
        }

        fn questions(&self) -> Vec<&'static str> {
            self.asked.iter().map(|a| a.question).collect()
        }
    }

    impl JoinPrompts for ScriptedPrompts {
        fn transfer_secret(&mut self) -> Result<String> {
            Ok(self.answer("secret"))
        }

        fn confirm_join(&mut self) -> Result<String> {
            Ok(self.answer("confirm"))
        }

        fn new_password(&mut self, prompt: &str) -> Result<String> {
            Ok(self.answer(if prompt.starts_with("Confirm") {
                "confirm password"
            } else {
                "password"
            }))
        }
    }

    const NEW_PASSWORD: &str = "Synthetic-Joined-Master-77";

    /// Runs `run_enroll` on `source` into a new package in `dir` and returns the package path,
    /// the transfer secret as printed, and the whole output.
    fn enroll(source: &Vault, dir: &Path, name: &str) -> (PathBuf, String, String) {
        let package = dir.join(format!("{name}.chenroll"));
        let mut out = Vec::new();
        run_enroll(source, &package, &mut out).unwrap();
        let output = String::from_utf8(out).unwrap();
        let secret = output
            .lines()
            .find_map(|l| l.strip_prefix("Transfer secret: "))
            .expect("the output shows the transfer secret")
            .to_string();
        (package, secret, output)
    }

    /// Runs `run_join` on `machine` with `answers`, returning the result, the prompts, and the
    /// output.
    fn join(machine: &mut Machine, package: &Path, answers: &[&str]) -> (Result<()>, ScriptedPrompts, String) {
        let mut out = SharedOut::default();
        let mut prompts = ScriptedPrompts::new(&out, answers);
        let result = run_join(&mut machine.vault, package, &mut prompts, &mut out);
        (result, prompts, out.text())
    }

    /// A second machine joined to `source` through this module's own enroll and join, unlocked
    /// with [`NEW_PASSWORD`].
    fn joined_machine(source: &Vault) -> Machine {
        let packages = TempDir::new().unwrap();
        let (package, secret, _) = enroll(source, packages.path(), "machine");
        let mut machine = Machine::uninitialized();
        let (result, _, _) = join(&mut machine, &package, &[&secret, "y", NEW_PASSWORD, NEW_PASSWORD]);
        result.unwrap();
        machine.vault.unlock(NEW_PASSWORD).unwrap();
        machine
    }

    fn capture<F: FnOnce(&mut Vec<u8>) -> Result<()>>(f: F) -> (Result<()>, String) {
        let mut out = Vec::new();
        let result = f(&mut out);
        (result, String::from_utf8(out).unwrap())
    }

    /// Copies every `.chsnap` file in `from` into `to`, replacing files of the same name.
    fn copy_snapshots(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let path = entry.unwrap().path();
            if path.extension() == Some(OsStr::new("chsnap")) {
                fs::copy(&path, to.join(path.file_name().unwrap())).unwrap();
            }
        }
    }

    fn file_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    const CORRUPT_NAME: &str = "corrupt.chsnap";
    const CORRUPT_BYTES: &[u8] = b"not a snapshot";

    fn corrupt_rejection_text() -> String {
        SnapshotRejection::TooSmall {
            len: CORRUPT_BYTES.len() as u64,
        }
        .to_string()
    }

    // ---- Parsing ----

    fn parse_sync(args: &[&str]) -> (Option<PathBuf>, Option<SyncCommand>) {
        let cli = Cli::try_parse_from(args).unwrap();
        match cli.command {
            Some(Commands::Sync { dir, command }) => (dir, command),
            other => panic!("expected the sync command, got {other:?}"),
        }
    }

    #[test]
    fn parses_every_sync_invocation() {
        assert_eq!(parse_sync(&["chamber", "sync"]), (None, None));
        assert_eq!(
            parse_sync(&["chamber", "sync", "--dir", "X"]),
            (Some(PathBuf::from("X")), None)
        );
        assert_eq!(
            parse_sync(&["chamber", "sync", "merge"]),
            (None, Some(SyncCommand::Merge { dir: None }))
        );
        assert_eq!(
            parse_sync(&["chamber", "sync", "merge", "--dir", "X"]),
            (
                None,
                Some(SyncCommand::Merge {
                    dir: Some(PathBuf::from("X"))
                })
            )
        );
        assert_eq!(
            parse_sync(&["chamber", "sync", "publish", "--dir", "X"]),
            (
                None,
                Some(SyncCommand::Publish {
                    dir: Some(PathBuf::from("X"))
                })
            )
        );
        assert_eq!(
            parse_sync(&["chamber", "sync", "publish"]),
            (None, Some(SyncCommand::Publish { dir: None }))
        );
        assert_eq!(
            parse_sync(&["chamber", "sync", "enroll", "out.chenroll"]),
            (
                None,
                Some(SyncCommand::Enroll {
                    output: PathBuf::from("out.chenroll")
                })
            )
        );
        assert_eq!(
            parse_sync(&["chamber", "sync", "join", "pkg.chenroll"]),
            (
                None,
                Some(SyncCommand::Join {
                    package: PathBuf::from("pkg.chenroll")
                })
            )
        );
    }

    #[test]
    fn rejects_enroll_and_join_without_a_path_and_with_dir() {
        for args in [
            &["chamber", "sync", "enroll"][..],
            &["chamber", "sync", "join"],
            &["chamber", "sync", "enroll", "out.chenroll", "--dir", "X"],
            &["chamber", "sync", "join", "pkg.chenroll", "--dir", "X"],
            &["chamber", "sync", "--dir", "X", "enroll", "out.chenroll"],
            &["chamber", "sync", "--dir", "X", "join", "pkg.chenroll"],
        ] {
            assert!(Cli::try_parse_from(args).is_err(), "{args:?} is rejected");
        }
    }

    #[test]
    fn every_sync_command_and_argument_has_help() {
        use clap::CommandFactory;
        let cli = Cli::command();
        let sync = cli.find_subcommand("sync").unwrap();
        assert!(sync.get_about().is_some());
        for arg in sync.get_arguments().filter(|a| !a.is_global_set()) {
            if arg.get_id() != "help" {
                assert!(arg.get_help().is_some(), "sync --{} has help", arg.get_id());
            }
        }
        for sub in sync.get_subcommands().filter(|s| s.get_name() != "help") {
            assert!(sub.get_about().is_some(), "sync {} has help", sub.get_name());
            for arg in sub.get_arguments().filter(|a| a.get_id() != "help") {
                assert!(
                    arg.get_help().is_some(),
                    "sync {} {} has help",
                    sub.get_name(),
                    arg.get_id()
                );
            }
        }
    }

    // ---- Sync directory ----

    #[test]
    fn resolution_prefers_the_option_then_the_environment_then_the_default() {
        let explicit = Path::new("zz-explicit-dir");
        let env = OsStr::new("zz-env-dir");
        assert_eq!(resolve_dir(Some(explicit), Some(env)).unwrap(), explicit);
        assert_eq!(resolve_dir(Some(explicit), None).unwrap(), explicit);
        assert_eq!(resolve_dir(None, Some(env)).unwrap(), PathBuf::from(env));
        let default = default_sync_dir().unwrap();
        assert_eq!(resolve_dir(None, None).unwrap(), default);
        assert_eq!(
            resolve_dir(None, Some(OsStr::new(""))).unwrap(),
            default,
            "an empty environment value counts as unset"
        );
    }

    #[test]
    fn a_sync_directory_holding_the_database_is_refused_and_nothing_is_written() {
        let mut machine = Machine::initialized();
        machine.add("zz-sync-refused", "qq-refused-value");
        let sync_dir = machine.dir.path().to_path_buf();
        let before = file_names(&sync_dir);

        let (merge, _) = capture(|out| run_merge(&mut machine.vault, &sync_dir, out));
        let (publish, _) = capture(|out| run_publish(&machine.vault, &sync_dir, out));
        let (sync, _) = capture(|out| run_sync(&mut machine.vault, &sync_dir, out));

        for (what, result) in [("merge", merge), ("publish", publish), ("sync", sync)] {
            let err = result.expect_err(what);
            assert!(
                matches!(
                    err.downcast_ref::<SyncDirError>(),
                    Some(SyncDirError::ContainsDatabase { .. })
                ),
                "{what}: {err}"
            );
        }
        let after = file_names(&sync_dir);
        assert_eq!(after, before, "nothing is written to the directory");
        assert!(!after.iter().any(|n| n.contains("chsnap")));
    }

    // ---- Uninitialized vault ----

    #[test]
    fn the_initialized_check_points_to_init_and_join() {
        let machine = Machine::uninitialized();
        let err = require_initialized(&machine.vault).unwrap_err().to_string();
        assert!(err.contains("chamber init"), "{err}");
        assert!(err.contains("chamber sync join"), "{err}");
        assert!(require_initialized(&Machine::initialized().vault).is_ok());
    }

    // ---- Merge, publish, and bare sync ----

    #[test]
    fn merge_reports_merged_and_skipped_files_and_fails_when_any_is_skipped() {
        let mut a = Machine::initialized();
        a.add("zz-sync-shared", "qq-shared-value");
        let mut b = joined_machine(&a.vault);
        b.add("zz-sync-from-b", "qq-from-b-value");
        let sync_dir = TempDir::new().unwrap();
        let (published, _) = capture(|out| run_publish(&b.vault, sync_dir.path(), out));
        published.unwrap();
        fs::write(sync_dir.path().join(CORRUPT_NAME), CORRUPT_BYTES).unwrap();
        let b_file = snapshot_file_name(b.vault.device_id().unwrap());

        let (result, output) = capture(|out| run_merge(&mut a.vault, sync_dir.path(), out));

        let err = result.expect_err("a skipped file makes the merge fail").to_string();
        assert!(err.contains("1 snapshot file was skipped"), "{err}");
        assert!(
            output.contains(&format!(
                "Merged {b_file}: 1 added, 0 replaced, 0 removed by a tombstone, 1 unchanged"
            )),
            "{output}"
        );
        assert!(
            output.contains(&format!("Skipped {CORRUPT_NAME}: {}", corrupt_rejection_text())),
            "{output}"
        );
        assert!(
            a.names_and_values()
                .contains(&("zz-sync-from-b".to_string(), "qq-from-b-value".to_string())),
            "the valid file's entries are merged"
        );
        assert!(!output.contains("zz-sync-"), "no entry name is printed: {output}");
        assert!(!output.contains("qq-"), "no value is printed: {output}");
    }

    #[test]
    fn merge_output_never_contains_entry_names() {
        let mut a = Machine::initialized();
        a.add("zz-distinctive-name-4471", "qq-distinctive-value");
        let b = joined_machine(&a.vault);
        let sync_dir = TempDir::new().unwrap();
        run_publish(&a.vault, sync_dir.path(), &mut Vec::new()).unwrap();
        let mut b = b;

        let (result, output) = capture(|out| run_merge(&mut b.vault, sync_dir.path(), out));

        result.unwrap();
        assert!(output.starts_with("Merged "), "{output}");
        assert!(!output.contains("zz-distinctive-name-4471"), "{output}");
        assert!(!output.contains("qq-distinctive-value"), "{output}");
    }

    #[test]
    fn merge_of_a_missing_directory_has_nothing_to_merge() {
        let mut machine = Machine::initialized();
        let missing = TempDir::new().unwrap().path().join("zz-missing");

        let (result, output) = capture(|out| run_merge(&mut machine.vault, &missing, out));

        result.unwrap();
        assert!(output.starts_with("Nothing to merge"), "{output}");
        assert!(!missing.exists(), "the merge creates nothing");
    }

    #[test]
    fn publish_reports_the_file_written_under_the_device_id() {
        let mut machine = Machine::initialized();
        machine.add("zz-publish-1", "qq-publish-1");
        machine.add("zz-publish-2", "qq-publish-2");
        let doomed = machine
            .vault
            .list_items()
            .unwrap()
            .into_iter()
            .find(|i| i.name == "zz-publish-2")
            .unwrap();
        machine.vault.delete_item(doomed.id).unwrap();
        let sync_dir = TempDir::new().unwrap();

        let (result, output) = capture(|out| run_publish(&machine.vault, sync_dir.path(), out));

        result.unwrap();
        let expected = sync_dir
            .path()
            .join(snapshot_file_name(machine.vault.device_id().unwrap()));
        assert!(expected.is_file(), "the snapshot is published under the device ID");
        assert!(
            output.starts_with(&format!(
                "Published {}: 1 entry, 1 tombstone (snapshot ",
                expected.display()
            )),
            "{output}"
        );
        assert!(!output.contains("zz-publish"), "{output}");
    }

    #[test]
    fn publish_reports_plural_nouns_for_counts_other_than_one() {
        let mut machine = Machine::initialized();
        for n in 1..=4 {
            machine.add(&format!("zz-plural-{n}"), &format!("qq-plural-{n}"));
        }
        for doomed in ["zz-plural-3", "zz-plural-4"] {
            let item = machine
                .vault
                .list_items()
                .unwrap()
                .into_iter()
                .find(|i| i.name == doomed)
                .unwrap();
            machine.vault.delete_item(item.id).unwrap();
        }
        let sync_dir = TempDir::new().unwrap();

        let (result, output) = capture(|out| run_publish(&machine.vault, sync_dir.path(), out));

        result.unwrap();
        assert!(output.contains(": 2 entries, 2 tombstones (snapshot "), "{output}");

        let empty = Machine::initialized();
        let empty_dir = TempDir::new().unwrap();
        let (result, output) = capture(|out| run_publish(&empty.vault, empty_dir.path(), out));
        result.unwrap();
        assert!(output.contains(": 0 entries, 0 tombstones (snapshot "), "{output}");
    }

    #[test]
    fn merge_report_escapes_control_characters_in_file_names() {
        let name = "evil\u{1b}[2J.chsnap";
        let escaped = "evil\\u{1b}[2J.chsnap";
        let report = MergeReport {
            files: vec![
                FileReport {
                    file_name: name.to_string(),
                    outcome: FileOutcome::Merged(MergeCounts::default()),
                },
                FileReport {
                    file_name: name.to_string(),
                    outcome: FileOutcome::Skipped(SnapshotRejection::BadMagic),
                },
            ],
        };
        let mut out = Vec::new();

        write_merge_report(&report, Path::new("zz-sync-dir"), &mut out).unwrap();

        let output = String::from_utf8(out).unwrap();
        assert!(
            !output.chars().any(|c| c.is_control() && c != '\n'),
            "only line ends are control characters: {output:?}"
        );
        assert!(output.contains("\\u{1b}"), "{output:?}");
        assert!(output.contains(&format!("Merged {escaped}: ")), "{output:?}");
        assert!(output.contains(&format!("Skipped {escaped}: ")), "{output:?}");
    }

    #[test]
    fn display_file_name_escapes_only_control_characters() {
        assert_eq!(display_file_name("plain-name.chsnap"), "plain-name.chsnap");
        assert_eq!(display_file_name("a\\b\u{e9}.chsnap"), "a\\b\u{e9}.chsnap");
        assert_eq!(display_file_name("\u{1b}[31m"), "\\u{1b}[31m");
        assert_eq!(display_file_name("line\nbreak\r\t"), "line\\u{a}break\\u{d}\\u{9}");
        assert_eq!(display_file_name("\u{7f}\u{9b}"), "\\u{7f}\\u{9b}");
    }

    #[test]
    fn bare_sync_merges_before_publishing() {
        let mut a = Machine::initialized();
        a.add("zz-sync-a", "qq-a-value");
        let mut b = joined_machine(&a.vault);
        let mut c = joined_machine(&a.vault);
        b.add("zz-sync-b", "qq-b-value");
        let (dir_a, dir_b, dir_c) = (
            TempDir::new().unwrap(),
            TempDir::new().unwrap(),
            TempDir::new().unwrap(),
        );
        run_publish(&b.vault, dir_b.path(), &mut Vec::new()).unwrap();
        copy_snapshots(dir_b.path(), dir_a.path());

        let (result, output) = capture(|out| run_sync(&mut a.vault, dir_a.path(), out));

        result.unwrap();
        assert!(output.contains("Merged "), "{output}");
        assert!(output.contains("Published "), "{output}");
        assert_eq!(a.names_and_values(), b.names_and_values(), "A holds B's entries");

        // Only A's file reaches C: B's entry arriving on C shows A published after merging.
        let a_file = snapshot_file_name(a.vault.device_id().unwrap());
        fs::copy(dir_a.path().join(&a_file), dir_c.path().join(&a_file)).unwrap();
        assert_eq!(file_names(dir_c.path()), vec![a_file]);
        run_merge(&mut c.vault, dir_c.path(), &mut Vec::new()).unwrap();
        assert_eq!(c.names_and_values(), b.names_and_values(), "C receives B's entry via A");
    }

    #[test]
    fn bare_sync_with_a_corrupt_file_still_publishes_and_fails() {
        let mut machine = Machine::initialized();
        machine.add("zz-sync-corrupt", "qq-corrupt-value");
        let sync_dir = TempDir::new().unwrap();
        fs::write(sync_dir.path().join(CORRUPT_NAME), CORRUPT_BYTES).unwrap();

        let (result, output) = capture(|out| run_sync(&mut machine.vault, sync_dir.path(), out));

        let err = result.expect_err("a skipped file makes sync fail").to_string();
        assert!(err.contains("1 snapshot file was skipped"), "{err}");
        assert!(output.contains(&format!("Skipped {CORRUPT_NAME}: ")), "{output}");
        assert!(output.contains("Published "), "{output}");
        let published = sync_dir
            .path()
            .join(snapshot_file_name(machine.vault.device_id().unwrap()));
        assert!(
            published.is_file(),
            "the snapshot is published despite the skipped file"
        );
    }

    #[test]
    fn bare_sync_publishes_nothing_when_only_the_merge_fails() {
        let mut a = Machine::initialized();
        let mut b = joined_machine(&a.vault);
        b.add("zz-sync-merge-fails", "qq-merge-fails-value");
        let sync_dir = TempDir::new().unwrap();
        run_publish(&b.vault, sync_dir.path(), &mut Vec::new()).unwrap();
        let b_file = snapshot_file_name(b.vault.device_id().unwrap());
        assert_eq!(file_names(sync_dir.path()), vec![b_file.clone()]);
        let entries_before = a.names_and_values();

        let trigger = rusqlite::Connection::open(a.vault.db_path()).unwrap();
        trigger
            .execute_batch(
                "CREATE TRIGGER refuse_insert BEFORE INSERT ON items \
                 BEGIN SELECT RAISE(ABORT, 'insert refused by test'); END;",
            )
            .unwrap();

        let (result, output) = capture(|out| run_sync(&mut a.vault, sync_dir.path(), out));

        let err = result.expect_err("the merge fails, so sync fails");
        let chain = format!("{err:#}");
        assert!(chain.contains("insert refused by test"), "{chain}");
        assert!(!output.contains("Published "), "{output}");
        let a_id = a.vault.device_id().unwrap();
        let a_file = snapshot_file_name(a_id);
        assert!(!sync_dir.path().join(&a_file).exists(), "A's snapshot is not published");
        assert!(
            !sync_dir.path().join(format!(".{a_file}.tmp")).exists(),
            "A's temporary file is not written"
        );
        assert_eq!(file_names(sync_dir.path()), vec![b_file]);
        assert_eq!(a.names_and_values(), entries_before, "B's entry is not merged");
        assert!(
            !a.names_and_values().iter().any(|(n, _)| n == "zz-sync-merge-fails"),
            "B's entry is not listed"
        );

        trigger.execute_batch("DROP TRIGGER refuse_insert;").unwrap();
        drop(trigger);
        let (published, _) = capture(|out| run_publish(&a.vault, sync_dir.path(), out));
        published.unwrap();
        assert!(
            sync_dir.path().join(&a_file).is_file(),
            "publishing did not share the merge failure"
        );
    }

    #[test]
    fn skipped_error_states_the_count() {
        let mut machine = Machine::initialized();
        let sync_dir = TempDir::new().unwrap();
        fs::write(sync_dir.path().join("one.chsnap"), CORRUPT_BYTES).unwrap();
        fs::write(sync_dir.path().join("two.chsnap"), CORRUPT_BYTES).unwrap();

        let (result, output) = capture(|out| run_merge(&mut machine.vault, sync_dir.path(), out));

        let err = result.unwrap_err().to_string();
        assert!(err.contains("2 snapshot files were skipped"), "{err}");
        assert!(output.contains("Skipped one.chsnap: "), "{output}");
        assert!(output.contains("Skipped two.chsnap: "), "{output}");
    }

    // ---- Enroll ----

    #[test]
    fn enroll_writes_the_package_and_shows_the_secret_once() {
        let mut machine = Machine::initialized();
        machine.add("zz-enroll", "qq-enroll-value");
        let out_dir = TempDir::new().unwrap();

        let (package, secret, output) = enroll(&machine.vault, out_dir.path(), "zz-out");

        assert!(package.is_file(), "the package exists afterwards");
        assert_eq!(secret.len(), 32, "26 characters and six hyphens: {secret}");
        assert_eq!(
            TransferSecret::parse(&secret).unwrap().display_form(),
            secret,
            "the display form is printed"
        );
        assert_eq!(output.matches(&secret).count(), 1, "{output}");
        assert!(output.contains("separately from the package"), "{output}");
        assert!(
            output.contains("may travel through the sync directory, but the transfer secret must not"),
            "{output}"
        );
        assert!(!output.contains("zz-enroll"), "{output}");
        assert!(!output.contains("qq-enroll"), "{output}");
    }

    #[test]
    fn enroll_refuses_a_wrong_extension_and_an_existing_file() {
        let machine = Machine::initialized();
        let out_dir = TempDir::new().unwrap();
        let wrong = out_dir.path().join("zz-package.zip");
        let existing = out_dir.path().join("zz-existing.chenroll");
        fs::write(&existing, b"keep me").unwrap();

        for path in [&wrong, &existing] {
            assert!(check_enroll_output(path).is_err(), "{}", path.display());
            let (result, output) = capture(|out| run_enroll(&machine.vault, path, out));
            assert!(result.is_err(), "{}", path.display());
            assert!(output.is_empty(), "{output}");
        }
        assert!(
            check_enroll_output(&wrong)
                .unwrap_err()
                .to_string()
                .contains(".chenroll")
        );
        assert!(!wrong.exists());
        assert_eq!(
            fs::read(&existing).unwrap(),
            b"keep me",
            "the existing file is unchanged"
        );
        assert!(check_enroll_output(&out_dir.path().join("zz-new.chenroll")).is_ok());
    }

    // ---- Join ----

    /// A source machine with two entries, and a package from it with its secret.
    fn source_and_package() -> (Machine, TempDir, PathBuf, String) {
        let mut source = Machine::initialized();
        source.add("zz-join-1", "qq-join-value-1");
        source.add("zz-join-2", "qq-join-value-2");
        let packages = TempDir::new().unwrap();
        let (package, secret, _) = enroll(&source.vault, packages.path(), "transfer");
        (source, packages, package, secret)
    }

    #[test]
    fn join_succeeds_and_keeps_the_package() {
        let (source, _packages, package, secret) = source_and_package();
        let mut machine = Machine::uninitialized();

        let (result, prompts, output) = join(&mut machine, &package, &[&secret, "y", NEW_PASSWORD, NEW_PASSWORD]);

        result.unwrap();
        assert_eq!(
            prompts.questions(),
            vec!["secret", "confirm", "password", "confirm password"]
        );
        let summary = format!(
            "The package joins vault {} and carries 2 entries.",
            source.vault.vault_uuid().unwrap()
        );
        let at_confirm = &prompts.asked[1].output_before;
        assert!(at_confirm.contains(&summary), "{at_confirm}");
        assert!(!at_confirm.contains("Delete the enrollment package"), "{at_confirm}");
        let after_confirm = &output[at_confirm.len()..];
        assert!(after_confirm.contains("Joined vault"), "{output}");
        assert!(after_confirm.contains("Delete the enrollment package"), "{output}");
        assert!(after_confirm.contains("discard the transfer secret"), "{output}");
        assert!(!output.contains("zz-join"), "{output}");

        machine.vault.unlock(NEW_PASSWORD).unwrap();
        assert_eq!(machine.names_and_values(), source.names_and_values());
        assert!(package.is_file(), "the package is not deleted");
    }

    #[test]
    fn join_accepts_a_lowercase_secret_with_spaces_and_a_yes_in_any_case() {
        let (source, _packages, package, secret) = source_and_package();
        let typed = secret.to_lowercase().replace('-', " ");
        let mut machine = Machine::uninitialized();

        let (result, _, _) = join(&mut machine, &package, &[&typed, " YeS \n", NEW_PASSWORD, NEW_PASSWORD]);

        result.unwrap();
        machine.vault.unlock(NEW_PASSWORD).unwrap();
        assert_eq!(machine.names_and_values(), source.names_and_values());
    }

    #[test]
    fn join_refuses_an_initialized_vault_before_asking_anything() {
        let (_source, _packages, package, secret) = source_and_package();
        let mut machine = Machine::initialized();
        machine.add("zz-own-entry", "qq-own-value");
        machine.vault.lock();

        let (result, prompts, _) = join(&mut machine, &package, &[&secret, "y", NEW_PASSWORD, NEW_PASSWORD]);

        let err = result.unwrap_err().to_string();
        assert_eq!(err, EnrollmentError::AlreadyInitialized.to_string());
        assert!(prompts.asked.is_empty(), "nothing is asked");
        machine.vault.unlock(MASTER_PASSWORD).unwrap();
        assert_eq!(
            machine.names_and_values(),
            vec![("zz-own-entry".to_string(), "qq-own-value".to_string())]
        );
    }

    #[test]
    fn join_refuses_a_snapshot_before_asking_for_the_secret() {
        let source = Machine::initialized();
        let sync_dir = TempDir::new().unwrap();
        run_publish(&source.vault, sync_dir.path(), &mut Vec::new()).unwrap();
        let snapshot = sync_dir
            .path()
            .join(snapshot_file_name(source.vault.device_id().unwrap()));
        let mut machine = Machine::uninitialized();

        let (result, prompts, _) = join(&mut machine, &snapshot, &[]);

        assert_eq!(result.unwrap_err().to_string(), EnrollmentError::IsSnapshot.to_string());
        assert!(prompts.asked.is_empty());
        machine.assert_pristine();
    }

    #[test]
    fn join_refuses_a_wrong_or_malformed_secret_before_confirming() {
        let (_source, _packages, package, _secret) = source_and_package();
        let wrong = TransferSecret::generate().unwrap().display_form();
        for (typed, expected) in [
            (wrong.as_str(), EnrollmentError::WrongSecretOrDamaged),
            ("not-a-transfer-secret", EnrollmentError::InvalidTransferSecret),
        ] {
            let mut machine = Machine::uninitialized();

            let (result, prompts, _) = join(&mut machine, &package, &[typed]);

            assert_eq!(result.unwrap_err().to_string(), expected.to_string());
            assert_eq!(prompts.questions(), vec!["secret"], "no confirmation is asked");
            machine.assert_pristine();
        }
    }

    #[test]
    fn join_cancels_on_an_empty_or_negative_answer() {
        let (_source, _packages, package, secret) = source_and_package();
        for answer in ["", "\n", "n", "no", "maybe"] {
            let mut machine = Machine::uninitialized();

            let (result, prompts, output) = join(&mut machine, &package, &[&secret, answer]);

            result.unwrap();
            assert_eq!(prompts.questions(), vec!["secret", "confirm"], "answer {answer:?}");
            assert!(output.contains("Join cancelled"), "{output}");
            machine.assert_pristine();
        }
    }

    #[test]
    fn join_refuses_an_empty_or_mismatched_password() {
        let (_source, _packages, package, secret) = source_and_package();

        let mut machine = Machine::uninitialized();
        let (result, prompts, _) = join(&mut machine, &package, &[&secret, "y", ""]);
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
        assert_eq!(prompts.questions(), vec!["secret", "confirm", "password"]);
        machine.assert_pristine();

        let mut machine = Machine::uninitialized();
        let (result, _, output) = join(
            &mut machine,
            &package,
            &[&secret, "y", NEW_PASSWORD, "Different-Pass-1"],
        );
        assert!(result.unwrap_err().to_string().contains("do not match"));
        assert!(!output.contains("Joined"), "{output}");
        machine.assert_pristine();
        assert!(package.is_file());
    }

    // ---- End to end ----

    #[test]
    fn two_machines_converge_through_bare_sync() {
        let mut a = Machine::initialized();
        a.add("zz-e2e-a1", "qq-a1");
        a.add("zz-e2e-shared", "qq-shared");
        let mut b = joined_machine(&a.vault);

        a.add("zz-e2e-a2", "qq-a2");
        b.add("zz-e2e-b1", "qq-b1");
        let shared_on_b = b
            .vault
            .list_items()
            .unwrap()
            .into_iter()
            .find(|i| i.name == "zz-e2e-shared")
            .unwrap();
        b.vault.delete_item(shared_on_b.id).unwrap();

        let (dir_a, dir_b) = (TempDir::new().unwrap(), TempDir::new().unwrap());
        run_sync(&mut b.vault, dir_b.path(), &mut Vec::new()).unwrap();
        copy_snapshots(dir_b.path(), dir_a.path());
        run_sync(&mut a.vault, dir_a.path(), &mut Vec::new()).unwrap();
        copy_snapshots(dir_a.path(), dir_b.path());
        run_sync(&mut b.vault, dir_b.path(), &mut Vec::new()).unwrap();

        assert_eq!(
            a.vault.export_sync_state().unwrap(),
            b.vault.export_sync_state().unwrap()
        );
        let expected: Vec<(String, String)> = [("zz-e2e-a1", "qq-a1"), ("zz-e2e-a2", "qq-a2"), ("zz-e2e-b1", "qq-b1")]
            .iter()
            .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
            .collect();
        assert_eq!(a.names_and_values(), expected);
        assert_eq!(b.names_and_values(), expected);
    }
}
