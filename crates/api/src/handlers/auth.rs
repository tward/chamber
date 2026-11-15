use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;

use crate::auth::AuthenticatedUser;
use crate::error::{ApiError, ApiResult};
use crate::models::{ApiResponse, LoginRequest, LoginResponse};
use crate::server::AppState;

/// # Errors
///
/// This function returns an error if:
/// - The provided master password is incorrect (Unauthorized)
/// - The vault cannot be unlocked due to internal errors
/// - Token generation fails due to internal errors
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<ApiResponse<LoginResponse>>> {
    // Try to unlock the vault with the provided password

    state
        .vault
        .lock()
        .await
        .unlock(&request.master_password)
        .map_err(|_| ApiError::Unauthorized)?;

    // Set vault as unlocked
    state.auth.set_vault_unlocked(true);

    // Generate token with default scopes
    let scopes = vec![
        "read:items".to_string(),
        "write:items".to_string(),
        "reveal:values".to_string(),
        "generate:passwords".to_string(),
        "vault:health".to_string(),
        "vault:read".to_string(),
        "vault:list".to_string(),
        "vault:create".to_string(),
        "vault:update".to_string(),
        "vault:delete".to_string(),
        "vault:switch".to_string(),
        "manage:vaults".to_string(),
    ];

    let token = state.auth.generate_token(scopes.clone())?;
    let expires_at: DateTime<Utc> = Utc::now() + Duration::hours(24);

    let response = LoginResponse {
        token,
        expires_at,
        scopes,
    };

    Ok(Json(ApiResponse::new(response)))
}

/// Ends the unlocked session: drops the vault key from memory, closes every vault the
/// vault manager holds open, and clears the session's unlocked flag.
///
/// Calling this on an already locked vault succeeds, because each step is a no-op there.
///
/// # Errors
///
/// This function returns an error if:
/// - The authentication token is missing, invalid, or expired (Unauthorized)
pub async fn logout(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(_claims): AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<String>>> {
    // Drop the vault key, close open vaults, and clear the unlocked flag
    end_unlocked_session(&state).await;

    Ok(Json(ApiResponse::new("Logged out successfully".to_string())))
}

/// Locks the session: drops the vault key from memory, closes every vault the vault
/// manager holds open, and clears the session's unlocked flag. The token stays valid,
/// so `session_unlock` can restore access with the master password.
///
/// Calling this on an already locked vault succeeds, because each step is a no-op there.
///
/// # Errors
///
/// This function returns an error if:
/// - The authentication token is missing, invalid, or expired (Unauthorized)
pub async fn session_lock(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(_claims): AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<String>>> {
    // Drop the vault key, close open vaults, and clear the unlocked flag
    end_unlocked_session(&state).await;

    Ok(Json(ApiResponse::new("Session locked successfully".to_string())))
}

/// # Errors
///
/// This function returns an error if:
/// - The provided master password is incorrect (Unauthorized)
/// - The vault cannot be unlocked due to internal errors
pub async fn session_unlock(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(_claims): AuthenticatedUser, // Add this parameter to require auth
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<ApiResponse<String>>> {
    // Try to unlock the vault with the provided password

    state
        .vault
        .lock()
        .await
        .unlock(&request.master_password)
        .map_err(|_| ApiError::Unauthorized)?;

    // Set vault as unlocked
    state.auth.set_vault_unlocked(true);

    Ok(Json(ApiResponse::new("Session unlocked successfully".to_string())))
}

/// Shared by `logout` and `session_lock`: drops the in-memory vault key, closes every
/// vault the manager holds open, then clears the unlocked flag.
///
/// Each step is its own statement so each mutex guard is released before the next one
/// is taken. None of the steps can fail, and all are no-ops on an already locked vault.
async fn end_unlocked_session(state: &AppState) {
    // The first `lock()` takes the tokio mutex; the second is `Vault::lock`, which drops the key.
    state.vault.lock().await.lock();
    state.vault_manager.lock().await.close_all_vaults();
    state.auth.set_vault_unlocked(false);
}
