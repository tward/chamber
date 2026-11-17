//! Display helpers for item names, shared by the CLI and the TUI.
//!
//! Names are not unique: a merge can leave several entries with the same name, because the
//! entry UUID is the identity and merging never renames. Listings tell such entries apart by
//! appending a short UUID suffix, `name (1a2b3c4d)`. An entry whose name no other entry has is
//! displayed by its bare name.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;

use uuid::Uuid;

use crate::Item;

/// The number of hexadecimal characters in a [`short_uuid`] suffix.
pub const SHORT_UUID_LEN: usize = 8;

/// Returns the short suffix of `uuid`: the first [`SHORT_UUID_LEN`] hexadecimal characters of
/// its lowercase hyphenated form (which come before the first hyphen).
#[must_use]
pub fn short_uuid(uuid: Uuid) -> String {
    let mut buf = Uuid::encode_buffer();
    let hyphenated = uuid.hyphenated().encode_lower(&mut buf);
    hyphenated[..SHORT_UUID_LEN].to_owned()
}

/// Returns the names that more than one item in `items` has.
///
/// Pass every entry of the vault, not a filtered view, so that an entry keeps its suffix even
/// when a filter hides its namesake.
#[must_use]
pub fn shared_names(items: &[Item]) -> HashSet<String> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for item in items {
        *counts.entry(item.name.as_str()).or_default() += 1;
    }
    counts
        .into_iter()
        .filter(|&(_, n)| n > 1)
        .map(|(name, _)| name.to_owned())
        .collect()
}

/// Returns how `item` is shown in a listing, given the set of shared names from
/// [`shared_names`]: `name (1a2b3c4d)` when its name is shared, and the bare name otherwise.
#[must_use]
pub fn display_name<S: BuildHasher>(item: &Item, shared: &HashSet<String, S>) -> String {
    if shared.contains(&item.name) {
        format!("{} ({})", item.name, short_uuid(item.uuid))
    } else {
        item.name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ItemKind, Revision};
    use time::macros::datetime;

    fn item(name: &str, uuid: Uuid) -> Item {
        let t = datetime!(2026-02-03 04:05:06 UTC);
        Item {
            id: 1,
            name: name.to_owned(),
            kind: ItemKind::Password,
            value: "secret".to_owned(),
            created_at: t,
            updated_at: t,
            uuid,
            revision: Revision::default(),
        }
    }

    #[test]
    fn short_uuid_is_first_eight_lowercase_hex_characters() {
        let uuid = Uuid::parse_str("1A2B3C4D-5E6F-4A8B-9C0D-1E2F3A4B5C6D").unwrap();
        assert_eq!(short_uuid(uuid), "1a2b3c4d");
        assert_eq!(short_uuid(uuid).len(), SHORT_UUID_LEN);
        assert_eq!(short_uuid(Uuid::from_bytes([0xAB; 16])), "abababab");
        assert_eq!(short_uuid(Uuid::nil()), "00000000");
    }

    #[test]
    fn shared_names_holds_only_names_used_more_than_once() {
        let items = [
            item("a", Uuid::from_bytes([1; 16])),
            item("b", Uuid::from_bytes([2; 16])),
            item("a", Uuid::from_bytes([3; 16])),
            item("A", Uuid::from_bytes([4; 16])),
        ];
        let shared = shared_names(&items);
        assert_eq!(shared, HashSet::from(["a".to_owned()]));
        assert!(shared_names(&[]).is_empty());
    }

    #[test]
    fn display_name_adds_suffix_only_for_shared_names() {
        let first = item(
            "github",
            Uuid::parse_str("1a2b3c4d-0000-4000-8000-000000000001").unwrap(),
        );
        let second = item(
            "github",
            Uuid::parse_str("9f8e7d6c-0000-4000-8000-000000000002").unwrap(),
        );
        let lone = item(
            "gitlab",
            Uuid::parse_str("55555555-0000-4000-8000-000000000003").unwrap(),
        );
        let items = [first.clone(), second.clone(), lone.clone()];
        let shared = shared_names(&items);
        assert_eq!(display_name(&first, &shared), "github (1a2b3c4d)");
        assert_eq!(display_name(&second, &shared), "github (9f8e7d6c)");
        assert_eq!(display_name(&lone, &shared), "gitlab");
        assert_eq!(display_name(&first, &HashSet::new()), "github");
    }
}
