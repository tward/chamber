use crate::common::TestContext;
use crate::common::fixtures::sample_login_request;
use chamber_api::models::{ApiResponse, ItemResponse, ItemWithValueResponse, LoginRequest, LoginResponse};
use http::StatusCode;
use serde_json::json;
mod common;

// ============================================================================
// Login Tests
// ============================================================================

#[tokio::test]
async fn test_login_success() -> color_eyre::Result<()> {
    // Create a completely isolated test context
    let ctx = TestContext::new()?;

    let login_request = sample_login_request();
    let response = ctx.server.post("/api/v1/auth/login").json(&login_request).await;

    response.assert_status_ok();

    let body: ApiResponse<LoginResponse> = response.json();
    assert!(!body.data.token.is_empty(), "Token should not be empty");
    assert!(!body.data.scopes.is_empty(), "Scopes should not be empty");
    assert!(body.data.expires_at > chrono::Utc::now(), "Token should not be expired");

    // Verify token contains expected scopes
    let expected_scopes = ["read:items", "write:items", "manage:vaults"];
    for scope in expected_scopes {
        assert!(
            body.data.scopes.contains(&scope.to_string()),
            "Token should contain scope: {scope}"
        );
    }
    Ok(())
    // TempDir automatically cleans up when ctx goes out of scope
}

#[tokio::test]
async fn test_login_invalid_password() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let login_request = LoginRequest {
        master_password: "wrong_password".to_string(),
    };

    let response = ctx.server.post("/api/v1/auth/login").json(&login_request).await;
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_login_empty_password() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let login_request = LoginRequest {
        master_password: String::new(),
    };

    let response = ctx.server.post("/api/v1/auth/login").json(&login_request).await;
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_login_malformed_request() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    // Missing master_password field
    let malformed_request = json!({
        "password": "some_password"  // wrong field name
    });

    let response = ctx.server.post("/api/v1/auth/login").json(&malformed_request).await;
    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);

    Ok(())
}

// ============================================================================
// Token Validation Tests
// ============================================================================

#[tokio::test]
async fn test_protected_endpoint_with_valid_token() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;

    response.assert_status_ok();

    Ok(())
}

#[tokio::test]
async fn test_protected_endpoint_without_token() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let response = ctx.server.get("/api/v1/items").await;
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_protected_endpoint_with_invalid_token() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let response = ctx
        .server
        .get("/api/v1/items")
        .authorization_bearer("invalid_token")
        .await;

    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_protected_endpoint_with_malformed_bearer() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let response = ctx
        .server
        .get("/api/v1/items")
        .add_header("Authorization", "Bearer") // Missing token
        .await;

    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_protected_endpoint_with_wrong_auth_scheme() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let response = ctx
        .server
        .get("/api/v1/items")
        .add_header("Authorization", "Basic dGVzdDp0ZXN0") // Basic auth instead of Bearer
        .await;

    response.assert_status_unauthorized();

    Ok(())
}

// ============================================================================
// Session Management Tests
// ============================================================================

#[tokio::test]
async fn test_session_lock_success() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let response = ctx
        .server
        .post("/api/v1/session/lock")
        .authorization_bearer(&token)
        .await;

    response.assert_status_ok();

    // Verify the session is actually locked by trying to access items
    let items_response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;

    // Should still be authorized (token valid) but vault should be locked
    items_response.assert_status(StatusCode::BAD_REQUEST); // Bad request due to locked vault

    Ok(())
}

#[tokio::test]
async fn test_session_lock_without_auth() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let response = ctx.server.post("/api/v1/session/lock").await;
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_session_unlock_success() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    // First lock the session
    let _lock_response = ctx
        .server
        .post("/api/v1/session/lock")
        .authorization_bearer(&token)
        .await;

    // Then unlock it
    let unlock_request = json!({
        "master_password": ctx.master_password
    });

    let response = ctx
        .server
        .post("/api/v1/session/unlock")
        .authorization_bearer(&token)
        .json(&unlock_request)
        .await;

    response.assert_status_ok();

    // Verify we can now access items
    let items_response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;

    items_response.assert_status_ok();

    Ok(())
}

#[tokio::test]
async fn test_session_unlock_invalid_password() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let unlock_request = json!({
        "master_password": "wrong_password"
    });

    let response = ctx
        .server
        .post("/api/v1/session/unlock")
        .authorization_bearer(&token)
        .json(&unlock_request)
        .await;

    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_session_unlock_without_auth() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let unlock_request = json!({
        "master_password": ctx.master_password
    });

    let response = ctx.server.post("/api/v1/session/unlock").json(&unlock_request).await;
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_logout_success() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let response = ctx
        .server
        .post("/api/v1/auth/logout")
        .authorization_bearer(&token)
        .await;

    response.assert_status_ok();

    // Verify the vault is locked after logout
    let items_response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;

    // Token should still be valid but vault should be locked
    items_response.assert_status(StatusCode::BAD_REQUEST);

    Ok(())
}

#[tokio::test]
async fn test_logout_without_auth() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let response = ctx.server.post("/api/v1/auth/logout").await;
    response.assert_status_unauthorized();

    Ok(())
}

/// Asserts that the item endpoints return the given item unchanged: same id, name, kind, and value.
async fn assert_item_intact(ctx: &TestContext, token: &str, id: u64, name: &str, kind: &str, value: &str) {
    let response = ctx
        .server
        .get(&format!("/api/v1/items/{id}"))
        .authorization_bearer(token)
        .await;
    response.assert_status_ok();
    let body: ApiResponse<ItemResponse> = response.json();
    assert_eq!(body.data.id, id);
    assert_eq!(body.data.name, name);
    assert_eq!(body.data.kind, kind);

    let response = ctx
        .server
        .get(&format!("/api/v1/items/{id}/value"))
        .authorization_bearer(token)
        .await;
    response.assert_status_ok();
    let body: ApiResponse<ItemWithValueResponse> = response.json();
    assert_eq!(body.data.id, id);
    assert_eq!(body.data.name, name);
    assert_eq!(body.data.kind, kind);
    assert!(body.data.value == value, "item value changed across the lock");
}

#[tokio::test]
async fn test_session_lock_drops_vault_key_and_unlock_restores_it() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let (name, kind, value) = ("lock_cycle_item", "password", "synthetic_value_lock_cycle");
    let id = ctx.create_test_item(name, kind, value).await?;
    let unlocked = ctx.vault.lock().await.is_unlocked();
    assert!(unlocked, "vault should hold its key after login");

    // Lock: the key must be gone, not just hidden behind the flag
    let response = ctx
        .server
        .post("/api/v1/session/lock")
        .authorization_bearer(&token)
        .await;
    response.assert_status_ok();
    let body: ApiResponse<String> = response.json();
    assert_eq!(body.data, "Session locked successfully");
    let unlocked = ctx.vault.lock().await.is_unlocked();
    assert!(!unlocked, "vault key should be dropped after session lock");

    let items_response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;
    items_response.assert_status(StatusCode::BAD_REQUEST);
    let value_response = ctx
        .server
        .get(&format!("/api/v1/items/{id}/value"))
        .authorization_bearer(&token)
        .await;
    value_response.assert_status(StatusCode::BAD_REQUEST);

    // A wrong password must not restore the key
    let response = ctx
        .server
        .post("/api/v1/session/unlock")
        .authorization_bearer(&token)
        .json(&json!({ "master_password": "wrong_password" }))
        .await;
    response.assert_status_unauthorized();
    let unlocked = ctx.vault.lock().await.is_unlocked();
    assert!(!unlocked, "vault should stay locked after a wrong unlock password");
    let items_response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;
    items_response.assert_status(StatusCode::BAD_REQUEST);

    // The correct password restores the key and the original data
    let response = ctx
        .server
        .post("/api/v1/session/unlock")
        .authorization_bearer(&token)
        .json(&json!({ "master_password": ctx.master_password }))
        .await;
    response.assert_status_ok();
    let unlocked = ctx.vault.lock().await.is_unlocked();
    assert!(unlocked, "vault should hold its key again after a correct unlock");

    assert_item_intact(&ctx, &token, id, name, kind, value).await;

    Ok(())
}

#[tokio::test]
async fn test_logout_drops_vault_key_and_login_restores_it() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let (name, kind, value) = ("logout_cycle_item", "note", "synthetic_value_logout_cycle");
    let id = ctx.create_test_item(name, kind, value).await?;

    let response = ctx
        .server
        .post("/api/v1/auth/logout")
        .authorization_bearer(&token)
        .await;
    response.assert_status_ok();
    let body: ApiResponse<String> = response.json();
    assert_eq!(body.data, "Logged out successfully");
    let unlocked = ctx.vault.lock().await.is_unlocked();
    assert!(!unlocked, "vault key should be dropped after logout");

    let items_response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;
    items_response.assert_status(StatusCode::BAD_REQUEST);

    // Logging in again restores the key, and the new token sees the original item
    let new_token = ctx.login().await?;
    let unlocked = ctx.vault.lock().await.is_unlocked();
    assert!(unlocked, "vault should hold its key again after login");

    assert_item_intact(&ctx, &new_token, id, name, kind, value).await;

    Ok(())
}

#[tokio::test]
async fn test_repeated_lock_and_logout_on_locked_vault_succeed() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    for _ in 0..2 {
        let response = ctx
            .server
            .post("/api/v1/session/lock")
            .authorization_bearer(&token)
            .await;
        response.assert_status_ok();
        let body: ApiResponse<String> = response.json();
        assert_eq!(body.data, "Session locked successfully");
        let unlocked = ctx.vault.lock().await.is_unlocked();
        assert!(!unlocked, "vault should stay locked after each session lock");
    }

    // Logout on an already locked vault is also a successful no-op
    let response = ctx
        .server
        .post("/api/v1/auth/logout")
        .authorization_bearer(&token)
        .await;
    response.assert_status_ok();
    let body: ApiResponse<String> = response.json();
    assert_eq!(body.data, "Logged out successfully");
    let unlocked = ctx.vault.lock().await.is_unlocked();
    assert!(!unlocked, "vault should stay locked after logout on a locked vault");

    Ok(())
}

// ============================================================================
// Scope-based Authorization Tests
// ============================================================================

#[tokio::test]
async fn test_scope_read_items() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    // Should be able to list items (requires read:items scope)
    let response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;

    response.assert_status_ok();

    Ok(())
}

#[tokio::test]
async fn test_scope_write_items() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let create_request = json!({
        "name": "test_item",
        "kind": "note",
        "value": "test_value"
    });

    // Should be able to create items (requires write:items scope)
    let response = ctx
        .server
        .post("/api/v1/items")
        .authorization_bearer(&token)
        .json(&create_request)
        .await;

    response.assert_status_ok();

    Ok(())
}

#[tokio::test]
async fn test_scope_manage_vaults() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    // Should be able to list vaults (requires manage:vaults scope)
    let response = ctx.server.get("/api/v1/vaults").authorization_bearer(&token).await;

    response.assert_status_ok();

    Ok(())
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

/*#[tokio::test]
async fn test_multiple_concurrent_logins() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;
    let login_request = sample_login_request();

    // Perform multiple concurrent login requests
    let responses = futures:: ::join_all((0..5).map(|_| {
        ctx.server.post("/api/v1/auth/login").json(&login_request)
    })).await;

    // All should succeed
    for response in responses {
        response.assert_status_ok();
    }

    Ok(())
}*/

#[tokio::test]
async fn test_token_after_server_restart() -> color_eyre::Result<()> {
    // Note: This test would be more complex to implement properly as it would
    // require actually restarting the test server. For now, we can simulate
    // the scenario by creating a new TestContext with the same vault data.

    let mut ctx1 = TestContext::new()?;
    let token = ctx1.login().await?;

    // Create a new context (simulating server restart)
    // In a real scenario, tokens should be invalidated after restart
    // since the signing secret would be regenerated
    let ctx2 = TestContext::new()?;

    let response = ctx2.server.get("/api/v1/items").authorization_bearer(&token).await;

    // Token should be invalid with new server instance
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_case_insensitive_bearer_header() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    // Test with lowercase 'bearer'
    let response = ctx
        .server
        .get("/api/v1/items")
        .add_header("Authorization", &format!("bearer {token}"))
        .await;

    // Should still work (HTTP headers are case-insensitive)
    response.assert_status_ok();

    Ok(())
}
