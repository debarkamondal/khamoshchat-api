use redis::AsyncCommands;
use crate::{state::AppState, error::AppError};

pub async fn set_temp_json(state: &AppState, key: &str, json_val: &str, ttl_secs: u64) -> Result<(), AppError> {
    let mut conn = state.redis.clone();
    conn.set_ex::<_, _, ()>(key, json_val, ttl_secs)
        .await
        .map_err(|e| {
            tracing::error!("Redis set error: {}", e);
            AppError::Internal(format!("Redis error: {e}"))
        })?;
    Ok(())
}

/// Atomically sets a key only if it does not already exist (SET NX EX).
/// Returns `true` if the key was newly created (safe to proceed).
/// Returns `false` if the key already existed (replay detected — reject request).
pub async fn set_temp_json_nx(state: &AppState, key: &str, json_val: &str, ttl_secs: u64) -> Result<bool, AppError> {
    let mut conn = state.redis.clone();
    // SET key value NX EX ttl — atomically set only if not exists
    let result: Option<String> = redis::cmd("SET")
        .arg(key)
        .arg(json_val)
        .arg("NX")
        .arg("EX")
        .arg(ttl_secs)
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Redis SET NX error: {}", e);
            AppError::Internal(format!("Redis error: {e}"))
        })?;
    // Redis returns "OK" if set, nil (None) if key already existed
    Ok(result.is_some())
}

pub async fn get_temp_json(state: &AppState, key: &str) -> Result<Option<String>, AppError> {
    let mut conn = state.redis.clone();
    let stored: Option<String> = conn.get(key).await.map_err(|e| {
        tracing::error!("Redis get error: {}", e);
        AppError::Internal(format!("Redis error: {e}"))
    })?;
    Ok(stored)
}

pub async fn delete_temp_key(state: &AppState, key: &str) -> Result<(), AppError> {
    let mut conn = state.redis.clone();
    let _: () = conn.del(key).await.map_err(|e| {
        tracing::error!("Redis delete error: {}", e);
        AppError::Internal(format!("Redis delete error: {e}"))
    })?;
    Ok(())
}
