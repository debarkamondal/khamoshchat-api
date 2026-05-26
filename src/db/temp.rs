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
