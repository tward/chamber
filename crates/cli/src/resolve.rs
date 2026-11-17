//! Choosing one entry when the CLI is given an entry name.
//!
//! Names are not unique: a merge can leave several entries with the same name, because the
//! entry UUID is the identity and merging never renames. `get` and `update` take a name, so
//! when several entries match they must ask which one is meant instead of picking one.
//!
//! [`resolve_item`] does the choosing against any reader and writer, and [`lookup_item`] looks a
//! name up in an unlocked vault and resolves it. The production entry point,
//! [`lookup_item_on_terminal`], treats the session as interactive when standard input is a
//! terminal, writes the list and prompt to standard error, and reads the choice from standard
//! input, so standard output carries only what the command prints itself.
//!
//! Nothing here writes a secret value: a match is shown by its UUID suffix, kind, and updated
//! time only.

use std::cmp::Reverse;
use std::io::{BufRead, IsTerminal, Write};

use chamber_vault::{Item, Vault, short_uuid};
use color_eyre::Result;
use color_eyre::eyre::eyre;
use time::format_description::well_known::Rfc3339;

/// Orders `matches` stably for display: newest updated time first, then by UUID.
fn sort_matches(matches: &mut [Item]) {
    matches.sort_by_key(|item| (Reverse(item.updated_at), item.uuid));
}

/// One match, as shown in the numbered list and in the non-interactive error: its UUID suffix,
/// kind, and updated time. Never the value.
fn describe(item: &Item) -> String {
    let updated = item
        .updated_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string());
    format!(
        "{}  [{}]  updated {updated}",
        short_uuid(item.uuid),
        item.kind.display_name()
    )
}

/// Chooses one entry among `matches`, the entries named `name`.
///
/// - One match: returns it and writes nothing.
/// - Several matches and `interactive`: writes a numbered list (one line per match with its UUID
///   suffix, kind, and updated time) and a prompt to `output`, then reads one line from `input`.
///   A number from 1 to the number of matches returns that match.
/// - Several matches and not `interactive`: reads nothing and fails with an error that lists
///   the matches.
///
/// Matches are listed newest updated time first, then by UUID.
///
/// # Errors
/// Returns an error when `matches` is empty (`Item not found`); when the session is not
/// interactive and there are several matches; when the input is empty, not a number, or a
/// number out of range (the choice is aborted and nothing is changed); and when reading
/// `input` or writing `output` fails.
pub fn resolve_item<R: BufRead, W: Write>(
    name: &str,
    mut matches: Vec<Item>,
    interactive: bool,
    input: &mut R,
    output: &mut W,
) -> Result<Item> {
    if matches.len() <= 1 {
        return matches.pop().ok_or_else(|| eyre!("Item not found"));
    }
    sort_matches(&mut matches);
    let count = matches.len();

    if !interactive {
        let listing: Vec<String> = matches.iter().map(|m| format!("  {}", describe(m))).collect();
        return Err(eyre!(
            "Several items are named '{name}'; run in an interactive terminal to choose one:\n{}",
            listing.join("\n")
        ));
    }

    writeln!(output, "Several items are named '{name}':")?;
    for (index, item) in matches.iter().enumerate() {
        writeln!(output, "  {}) {}", index + 1, describe(item))?;
    }
    write!(output, "Choose an item [1-{count}] (press Enter to cancel): ")?;
    output.flush()?;

    let mut line = String::new();
    input.read_line(&mut line)?;
    let answer = line.trim();
    if answer.is_empty() {
        return Err(eyre!("Cancelled: no item chosen for '{name}'"));
    }
    let choice: usize = answer
        .parse()
        .map_err(|_| eyre!("Invalid choice '{answer}': expected a number from 1 to {count}"))?;
    if !(1..=count).contains(&choice) {
        return Err(eyre!("Invalid choice {choice}: expected a number from 1 to {count}"));
    }
    Ok(matches.swap_remove(choice - 1))
}

/// Looks `name` up in the unlocked `vault` and chooses one entry with [`resolve_item`].
///
/// Returns `Ok(None)` when no entry has this name, without reading or writing anything.
///
/// # Errors
/// Returns an error when the vault cannot list its items (for example when it is locked), and
/// any error from [`resolve_item`], such as an aborted choice.
pub fn lookup_item<R: BufRead, W: Write>(
    vault: &Vault,
    name: &str,
    interactive: bool,
    input: &mut R,
    output: &mut W,
) -> Result<Option<Item>> {
    let matches = vault.items_by_name(name)?;
    if matches.is_empty() {
        return Ok(None);
    }
    resolve_item(name, matches, interactive, input, output).map(Some)
}

/// [`lookup_item`] on the process's terminal: interactive when standard input is a terminal,
/// with the list and prompt on standard error and the choice read from standard input.
///
/// # Errors
/// Any error from [`lookup_item`].
pub fn lookup_item_on_terminal(vault: &Vault, name: &str) -> Result<Option<Item>> {
    let stdin = std::io::stdin();
    let interactive = stdin.is_terminal();
    lookup_item(vault, name, interactive, &mut stdin.lock(), &mut std::io::stderr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        assert_recorded_edit_of, duplicate_via_merge, listed, listed_by_uuid, new_item, synthetic_item, unlocked_vault,
    };
    use crate::update_item_value;
    use chamber_vault::{ItemKind, Uuid};
    use std::io::Cursor;
    use time::macros::datetime;

    const OLD: time::OffsetDateTime = datetime!(2026-03-01 10:00:00 UTC);
    const NEW: time::OffsetDateTime = datetime!(2026-03-02 10:00:00 UTC);

    fn uuid(s: &str) -> Uuid {
        Uuid::parse_str(s).unwrap()
    }

    /// Three same-named items whose display order differs from their order here: `a` is the
    /// oldest, while `b` and `c` share the newest time and are ordered by UUID.
    fn three_matches() -> Vec<Item> {
        vec![
            synthetic_item(
                "github",
                ItemKind::Password,
                uuid("0a0a0a0a-0000-4000-8000-000000000001"),
                OLD,
            ),
            synthetic_item(
                "github",
                ItemKind::ApiKey,
                uuid("cccccccc-0000-4000-8000-000000000003"),
                NEW,
            ),
            synthetic_item(
                "github",
                ItemKind::Note,
                uuid("bbbbbbbb-0000-4000-8000-000000000002"),
                NEW,
            ),
        ]
    }

    fn written(out: Vec<u8>) -> String {
        String::from_utf8(out).unwrap()
    }

    fn assert_no_secret(text: &str, items: &[Item]) {
        for item in items {
            assert!(!text.contains(&item.value), "a secret value was written: {text}");
        }
    }

    #[test]
    fn one_match_is_returned_without_output_or_input() {
        let only = synthetic_item(
            "github",
            ItemKind::Password,
            uuid("1a2b3c4d-0000-4000-8000-000000000001"),
            OLD,
        );
        for interactive in [true, false] {
            let mut input = Cursor::new(b"2\n".to_vec());
            let mut output = Vec::new();
            let chosen = resolve_item("github", vec![only.clone()], interactive, &mut input, &mut output).unwrap();
            assert_eq!(chosen.uuid, only.uuid);
            assert!(output.is_empty(), "nothing is written");
            assert_eq!(input.position(), 0, "nothing is read");
        }
    }

    #[test]
    fn no_match_is_item_not_found() {
        let mut output = Vec::new();
        let err = resolve_item("github", vec![], true, &mut Cursor::new(Vec::new()), &mut output).unwrap_err();
        assert_eq!(err.to_string(), "Item not found");
        assert!(output.is_empty());
    }

    #[test]
    fn interactive_lists_numbered_matches_and_returns_the_chosen_one() {
        let items = three_matches();
        // Display order: newest first, then by UUID.
        let expected_order = [
            ("bbbbbbbb", "Note", "2026-03-02T10:00:00Z"),
            ("cccccccc", "API Key", "2026-03-02T10:00:00Z"),
            ("0a0a0a0a", "Password", "2026-03-01T10:00:00Z"),
        ];
        for (choice, (suffix, _, _)) in expected_order.iter().enumerate() {
            let mut input = Cursor::new(format!("{}\n", choice + 1).into_bytes());
            let mut output = Vec::new();
            let chosen = resolve_item("github", items.clone(), true, &mut input, &mut output).unwrap();
            assert_eq!(&short_uuid(chosen.uuid), suffix, "choice {}", choice + 1);

            let text = written(output);
            let numbered: Vec<&str> = text
                .lines()
                .filter(|l| l.trim_start().starts_with(char::is_numeric))
                .collect();
            assert_eq!(numbered.len(), 3, "one numbered line per match: {text}");
            for (index, (line, (suffix, kind, updated))) in numbered.iter().zip(expected_order).enumerate() {
                assert!(line.trim_start().starts_with(&format!("{})", index + 1)), "{line}");
                assert!(line.contains(suffix), "{line}");
                assert!(line.contains(&format!("[{kind}]")), "{line}");
                assert!(line.contains(updated), "{line}");
            }
            assert!(
                text.contains("Choose an item [1-3]"),
                "a prompt asks for a number: {text}"
            );
            assert_no_secret(&text, &items);
        }
    }

    #[test]
    fn interactive_choice_tolerates_surrounding_whitespace() {
        let mut input = Cursor::new(b"  3 \r\n".to_vec());
        let chosen = resolve_item("github", three_matches(), true, &mut input, &mut Vec::new()).unwrap();
        assert_eq!(short_uuid(chosen.uuid), "0a0a0a0a");
    }

    #[test]
    fn empty_invalid_and_out_of_range_input_abort() {
        for (answer, expected) in [
            ("", "Cancelled"),
            ("\n", "Cancelled"),
            ("   \n", "Cancelled"),
            ("two\n", "Invalid choice"),
            ("-1\n", "Invalid choice"),
            ("1.5\n", "Invalid choice"),
            ("0\n", "Invalid choice"),
            ("4\n", "Invalid choice"),
            ("99999999999999999999999\n", "Invalid choice"),
        ] {
            let mut input = Cursor::new(answer.as_bytes().to_vec());
            let mut output = Vec::new();
            let err = resolve_item("github", three_matches(), true, &mut input, &mut output).unwrap_err();
            assert!(err.to_string().contains(expected), "{answer:?}: {err}");
        }
    }

    #[test]
    fn non_interactive_fails_with_every_match_and_reads_nothing() {
        let items = three_matches();
        let mut input = Cursor::new(b"1\n".to_vec());
        let mut output = Vec::new();
        let err = resolve_item("github", items.clone(), false, &mut input, &mut output)
            .unwrap_err()
            .to_string();
        assert_eq!(input.position(), 0, "nothing is read");
        assert!(output.is_empty(), "nothing is written to the output");
        assert!(err.contains("'github'"), "{err}");
        for item in &items {
            assert!(err.contains(&short_uuid(item.uuid)), "{err}");
            assert!(err.contains(item.kind.display_name()), "{err}");
        }
        assert!(
            err.contains("2026-03-02T10:00:00Z") && err.contains("2026-03-01T10:00:00Z"),
            "{err}"
        );
        assert_no_secret(&err, &items);
    }

    // ---- The lookup step against a temp vault ----

    #[test]
    fn lookup_of_an_unknown_name_returns_none_silently() {
        let mut tv = unlocked_vault();
        tv.vault.create_item(&new_item("zz-cli-shared", "qq-original")).unwrap();
        let mut input = Cursor::new(b"1\n".to_vec());
        let mut output = Vec::new();
        let found = lookup_item(&tv.vault, "zz-cli-missing", true, &mut input, &mut output).unwrap();
        assert!(found.is_none());
        assert!(output.is_empty());
        assert_eq!(input.position(), 0);

        // A unique name resolves without a prompt.
        let found = lookup_item(&tv.vault, "zz-cli-shared", true, &mut input, &mut output)
            .unwrap()
            .expect("one match");
        assert_eq!(found.value, "qq-original");
        assert!(output.is_empty());
    }

    #[test]
    fn choosing_the_second_match_updates_only_that_entry() {
        let mut tv = unlocked_vault();
        tv.vault.create_item(&new_item("zz-cli-shared", "qq-original")).unwrap();
        let original = listed(&tv.vault, "zz-cli-shared");
        // The copy is newer, so it is listed first and the original second.
        let copy = duplicate_via_merge(
            &mut tv.vault,
            "zz-cli-shared",
            uuid("c0c0c0c0-0000-4000-8000-000000000000"),
            time::Duration::hours(1),
        );

        let mut input = Cursor::new(b"2\n".to_vec());
        let mut output = Vec::new();
        let chosen = lookup_item(&tv.vault, "zz-cli-shared", true, &mut input, &mut output)
            .unwrap()
            .expect("a match is chosen");
        assert_eq!(chosen.uuid, original.uuid, "the second listed match is the original");
        let text = written(output);
        assert!(text.contains("1) c0c0c0c0"), "{text}");
        assert!(text.contains(&format!("2) {}", short_uuid(original.uuid))), "{text}");
        assert_no_secret(&text, &[original.clone(), copy.clone()]);

        update_item_value(&mut tv.vault, &chosen, "qq-New-value-9!", "zz-synthetic-vault", false).unwrap();

        let after = assert_recorded_edit_of(&tv.vault, &original);
        assert_eq!(after.value, "qq-New-value-9!");
        let other = listed_by_uuid(&tv.vault, copy.uuid);
        assert_eq!(other.uuid, copy.uuid);
        assert_eq!(other.revision, copy.revision, "the other entry keeps its revision");
        assert_eq!(other.value, "qq-original", "the other entry keeps its value");
        assert_eq!(tv.vault.list_items().unwrap().len(), 2);
    }

    #[test]
    fn aborted_choice_changes_nothing() {
        for answer in ["", "\n", "nope\n", "0\n", "3\n"] {
            let mut tv = unlocked_vault();
            tv.vault.create_item(&new_item("zz-cli-shared", "qq-original")).unwrap();
            duplicate_via_merge(
                &mut tv.vault,
                "zz-cli-shared",
                uuid("c0c0c0c0-0000-4000-8000-000000000000"),
                time::Duration::hours(1),
            );
            let before = tv.vault.export_sync_state().unwrap();
            let hwm_before = tv.vault.high_water_mark().unwrap();

            let mut input = Cursor::new(answer.as_bytes().to_vec());
            let result = lookup_item(&tv.vault, "zz-cli-shared", true, &mut input, &mut Vec::new());

            assert!(result.is_err(), "{answer:?} aborts");
            assert_eq!(
                tv.vault.export_sync_state().unwrap(),
                before,
                "both entries are unchanged"
            );
            assert_eq!(tv.vault.high_water_mark().unwrap(), hwm_before);
            assert_eq!(tv.vault.items_by_name("zz-cli-shared").unwrap().len(), 2);
        }
    }

    #[test]
    fn non_interactive_lookup_with_two_matches_fails_and_changes_nothing() {
        let mut tv = unlocked_vault();
        tv.vault.create_item(&new_item("zz-cli-shared", "qq-original")).unwrap();
        let original = listed(&tv.vault, "zz-cli-shared");
        duplicate_via_merge(
            &mut tv.vault,
            "zz-cli-shared",
            uuid("c0c0c0c0-0000-4000-8000-000000000000"),
            time::Duration::hours(1),
        );
        let mut input = Cursor::new(b"1\n".to_vec());
        let err = lookup_item(&tv.vault, "zz-cli-shared", false, &mut input, &mut Vec::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("c0c0c0c0"), "{err}");
        assert!(err.contains(&short_uuid(original.uuid)), "{err}");
        assert_eq!(input.position(), 0);
    }
}
