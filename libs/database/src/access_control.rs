use app_error::AppError;
use futures_util::stream::BoxStream;
use sqlx::{Executor, PgPool, Postgres};
use uuid::Uuid;

/// A single user object-level grant, used by the access-control adapter to load
/// per-collab policies into the enforcer at startup.
///
/// Only user grants with an access level are loaded here (Phase 1). Group grants
/// and role-based grants are handled by later phases.
#[derive(sqlx::FromRow)]
pub struct AFObjectGrantPermRow {
  pub uid: i64,
  pub object_id: Uuid,
  pub access_level: i32,
}

/// Streams all user access-level grants from `af_object_grant`.
///
/// Uses a runtime-checked query (not the `query!` macro) so the crate compiles
/// without a database connection or prepared `.sqlx` metadata for this query.
pub fn select_object_grant_perm_stream(
  pg_pool: &PgPool,
) -> BoxStream<'_, sqlx::Result<AFObjectGrantPermRow>> {
  sqlx::query_as::<_, AFObjectGrantPermRow>(
    "SELECT uid, object_id, access_level FROM af_object_grant \
     WHERE uid IS NOT NULL AND access_level IS NOT NULL",
  )
  .fetch(pg_pool)
}

/// A user object grant joined with the grantee's identity, for listing the
/// access on a given object.
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct AFObjectGrantRow {
  pub object_id: Uuid,
  pub uid: i64,
  pub email: String,
  pub name: String,
  pub access_level: i32,
}

/// Inserts or updates a user access-level grant on an object ("set" semantics).
pub async fn upsert_object_grant<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  workspace_id: &Uuid,
  object_type: &str,
  object_id: &Uuid,
  uid: i64,
  access_level: i32,
  granted_by: i64,
) -> Result<(), AppError> {
  sqlx::query(
    "INSERT INTO af_object_grant (workspace_id, object_type, object_id, uid, access_level, granted_by) \
     VALUES ($1, $2, $3, $4, $5, $6) \
     ON CONFLICT (object_id, uid) WHERE uid IS NOT NULL \
     DO UPDATE SET access_level = EXCLUDED.access_level, granted_by = EXCLUDED.granted_by",
  )
  .bind(workspace_id)
  .bind(object_type)
  .bind(object_id)
  .bind(uid)
  .bind(access_level)
  .bind(granted_by)
  .execute(executor)
  .await?;
  Ok(())
}

/// Removes a user's grant on an object. Returns the number of rows removed.
pub async fn delete_object_grant<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  object_id: &Uuid,
  uid: i64,
) -> Result<u64, AppError> {
  let result = sqlx::query("DELETE FROM af_object_grant WHERE object_id = $1 AND uid = $2")
    .bind(object_id)
    .bind(uid)
    .execute(executor)
    .await?;
  Ok(result.rows_affected())
}

/// Lists all user grants on an object, joined with grantee identity.
pub async fn select_object_grants<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  object_id: &Uuid,
) -> Result<Vec<AFObjectGrantRow>, AppError> {
  let rows = sqlx::query_as::<_, AFObjectGrantRow>(
    "SELECT g.object_id, g.uid, u.email, u.name, g.access_level \
     FROM af_object_grant g JOIN af_user u ON u.uid = g.uid \
     WHERE g.object_id = $1 AND g.uid IS NOT NULL AND g.access_level IS NOT NULL \
     ORDER BY u.email",
  )
  .bind(object_id)
  .fetch_all(executor)
  .await?;
  Ok(rows)
}
