#![allow(clippy::unwrap_used)]
//! Tests that every REST API write records synchronization state: a create mints an entry UUID and a revision, an
//! edit assigns a greater revision under the same UUID, and a delete leaves a tombstone. Each test makes the HTTP
//! call, then inspects the server's own vault through `TestContext::vault`.
mod common;

use crate::common::TestContext;
use chamber_api::models::{ApiResponse, ItemResponse, UpdateItemRequest};
use chamber_import_export::{ExportFormat, export_items};
use chamber_vault::{Item, ItemKind, Revision, Uuid, Vault};
use time::OffsetDateTime;

/// The listed item named `name`.
fn listed(vault: &Vault, name: &str) -> Item {
    vault
        .list_items()
        .unwrap()
        .into_iter()
        .find(|i| i.name == name)
        .expect("the item is listed")
}

/// Asserts the item named `name` has a non-nil UUID shared with no other item and a revision from this vault's
/// device. Returns the item.
fn assert_created_entry(vault: &Vault, name: &str) -> Item {
    let items = vault.list_items().unwrap();
    let item = items
        .iter()
        .find(|i| i.name == name)
        .expect("the created item is listed")
        .clone();
    assert!(!item.uuid.is_nil(), "the UUID of '{name}' is not nil");
    assert_eq!(
        items.iter().filter(|i| i.uuid == item.uuid).count(),
        1,
        "the UUID of '{name}' differs from every other item's"
    );
    assert_eq!(
        item.revision.device_id,
        vault.device_id().unwrap(),
        "the revision of '{name}' names this device"
    );
    item
}

/// Asserts the item named `name` was recorded as a create whose revision is the high-water mark.
fn assert_recorded_create(vault: &Vault, name: &str) -> Item {
    let item = assert_created_entry(vault, name);
    assert_eq!(
        (item.revision.wall_ms, item.revision.counter),
        vault.high_water_mark().unwrap(),
        "the revision of '{name}' is the high-water mark"
    );
    item
}

/// Builds a context with a logged-in, unlocked session.
async fn unlocked_context() -> color_eyre::Result<TestContext> {
    let mut ctx = TestContext::new()?;
    ctx.login().await?;
    ctx.unlock_session().await?;
    Ok(ctx)
}

#[tokio::test]
async fn create_item_records_a_create() -> color_eyre::Result<()> {
    let mut ctx = unlocked_context().await?;
    ctx.create_test_item("zz-api-existing", "note", "qq-api-existing-value")
        .await?;
    let hwm_before = ctx.vault.lock().await.high_water_mark()?;

    let id = ctx
        .create_test_item("zz-api-created", "password", "qq-api-created-value")
        .await?;

    let vault = ctx.vault.lock().await;
    let created = assert_recorded_create(&vault, "zz-api-created");
    drop(vault);
    assert_eq!(created.id, id, "the response names the created row");
    assert_eq!(created.value, "qq-api-created-value");
    assert!(
        (created.revision.wall_ms, created.revision.counter) > hwm_before,
        "the create moves the high-water mark forward"
    );
    Ok(())
}

#[tokio::test]
async fn update_item_value_records_an_edit() -> color_eyre::Result<()> {
    let mut ctx = unlocked_context().await?;
    let id = ctx
        .create_test_item("zz-api-updated", "password", "qq-api-old-value")
        .await?;
    let before = listed(&*ctx.vault.lock().await, "zz-api-updated");

    let response = ctx
        .server
        .put(&format!("/api/v1/items/{id}"))
        .authorization_bearer(ctx.auth_token.as_ref().unwrap())
        .json(&UpdateItemRequest {
            name: None,
            kind: None,
            value: Some("qq-api-new-value".to_string()),
        })
        .await;
    response.assert_status_ok();
    let body: ApiResponse<ItemResponse> = response.json();
    assert_eq!(body.data.id, id);

    let vault = ctx.vault.lock().await;
    let after = listed(&vault, "zz-api-updated");
    let device_id = vault.device_id()?;
    let hwm = vault.high_water_mark()?;
    drop(vault);
    assert_eq!(after.value, "qq-api-new-value", "the entry holds the new value");
    assert_eq!(after.uuid, before.uuid, "an edit keeps the entry UUID");
    assert!(after.revision > before.revision, "an edit assigns a greater revision");
    assert_eq!(
        after.revision.device_id, device_id,
        "the edit revision names this device"
    );
    assert_eq!(
        (after.revision.wall_ms, after.revision.counter),
        hwm,
        "the edit revision is the high-water mark"
    );
    Ok(())
}

#[tokio::test]
async fn delete_item_records_a_delete() -> color_eyre::Result<()> {
    let mut ctx = unlocked_context().await?;
    let id = ctx
        .create_test_item("zz-api-deleted", "note", "qq-api-deleted-value")
        .await?;
    ctx.create_test_item("zz-api-kept", "note", "qq-api-kept-value").await?;
    let (deleted, kept) = {
        let vault = ctx.vault.lock().await;
        (listed(&vault, "zz-api-deleted"), listed(&vault, "zz-api-kept"))
    };

    let response = ctx
        .server
        .delete(&format!("/api/v1/items/{id}"))
        .authorization_bearer(ctx.auth_token.as_ref().unwrap())
        .await;
    response.assert_status_ok();

    let vault = ctx.vault.lock().await;
    let items = vault.list_items()?;
    let tombstones = vault.tombstones()?;
    drop(vault);
    assert!(
        items.iter().all(|i| i.uuid != deleted.uuid && i.id != deleted.id),
        "the deleted item is no longer listed"
    );
    assert_eq!(
        tombstones,
        [deleted.uuid],
        "the deleted item's UUID is the only tombstone"
    );
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].uuid, kept.uuid, "the other item stays");
    Ok(())
}

/// A synthetic item to write into an import file. Its UUID and revision are placeholders the export ignores.
fn export_entry(name: &str, value: &str) -> Item {
    let now = OffsetDateTime::now_utc();
    Item {
        id: 0,
        name: name.to_string(),
        kind: ItemKind::Note,
        value: value.to_string(),
        created_at: now,
        updated_at: now,
        uuid: Uuid::nil(),
        revision: Revision::default(),
    }
}

#[tokio::test]
async fn import_records_each_imported_item_as_a_create() -> color_eyre::Result<()> {
    let mut ctx = unlocked_context().await?;
    ctx.create_test_item("zz-api-present", "note", "qq-api-present-value")
        .await?;
    let (existing, hwm_before) = {
        let vault = ctx.vault.lock().await;
        (listed(&vault, "zz-api-present"), vault.high_water_mark()?)
    };

    let file = ctx.temp_dir.path().join("import.json");
    let entries = [
        export_entry("zz-api-import-1", "qq-api-import-value-1"),
        export_entry("zz-api-present", "qq-api-replacement-value"),
        export_entry("zz-api-import-2", "qq-api-import-value-2"),
    ];
    export_items(&entries, &ExportFormat::Json, &file)?;

    let response = ctx
        .server
        .post("/api/v1/import")
        .authorization_bearer(ctx.auth_token.as_ref().unwrap())
        .json(&serde_json::json!({ "format": "json", "path": file.to_string_lossy() }))
        .await;
    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["data"]["imported"], 2);
    assert_eq!(body["data"]["skipped"], 1);

    let vault = ctx.vault.lock().await;
    let imported: Vec<Item> = ["zz-api-import-1", "zz-api-import-2"]
        .iter()
        .map(|n| assert_created_entry(&vault, n))
        .collect();
    let hwm = vault.high_water_mark()?;
    let kept = listed(&vault, "zz-api-present");
    drop(vault);

    for item in &imported {
        assert!(
            (item.revision.wall_ms, item.revision.counter) > hwm_before,
            "the revision of '{}' is after the high-water mark read before the import",
            item.name
        );
        assert_ne!(item.uuid, existing.uuid, "imported entries get UUIDs of their own");
    }
    let greatest = imported.iter().map(|i| i.revision).max().unwrap();
    assert_eq!(
        (greatest.wall_ms, greatest.counter),
        hwm,
        "the latest import revision is the high-water mark"
    );
    assert_eq!(kept.uuid, existing.uuid, "the skipped entry keeps its UUID");
    assert_eq!(kept.revision, existing.revision, "the skipped entry keeps its revision");
    Ok(())
}
