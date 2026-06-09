use futures_util::stream::BoxStream;
use sqlx::PgPool;
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
