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

/// Inserts or updates a group access-level grant on an object ("set" semantics).
pub async fn upsert_group_object_grant<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  workspace_id: &Uuid,
  object_type: &str,
  object_id: &Uuid,
  group_id: &Uuid,
  access_level: i32,
  granted_by: i64,
) -> Result<(), AppError> {
  sqlx::query(
    "INSERT INTO af_object_grant (workspace_id, object_type, object_id, group_id, access_level, granted_by) \
     VALUES ($1, $2, $3, $4, $5, $6) \
     ON CONFLICT (object_id, group_id) WHERE group_id IS NOT NULL \
     DO UPDATE SET access_level = EXCLUDED.access_level, granted_by = EXCLUDED.granted_by",
  )
  .bind(workspace_id)
  .bind(object_type)
  .bind(object_id)
  .bind(group_id)
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

// =====================================================================
// Groups (Phase 2)
// =====================================================================

#[derive(sqlx::FromRow, serde::Serialize)]
pub struct AFGroupRow {
  pub id: Uuid,
  pub workspace_id: Uuid,
  pub name: String,
  pub description: Option<String>,
  pub member_count: i64,
}

#[derive(sqlx::FromRow, serde::Serialize)]
pub struct AFGroupMemberRow {
  pub uid: i64,
  pub email: String,
  pub name: String,
}

/// A user -> group membership, for loading the casbin `g2` grouping at startup.
#[derive(sqlx::FromRow)]
pub struct AFGroupMembershipRow {
  pub uid: i64,
  pub group_id: Uuid,
}

/// A group object-level grant, for loading group policies at startup.
#[derive(sqlx::FromRow)]
pub struct AFGroupGrantPermRow {
  pub group_id: Uuid,
  pub object_id: Uuid,
  pub access_level: i32,
}

pub async fn insert_group<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  workspace_id: &Uuid,
  name: &str,
  description: Option<&str>,
  created_by: i64,
) -> Result<Uuid, AppError> {
  let id: Uuid = sqlx::query_scalar(
    "INSERT INTO af_group (workspace_id, name, description, created_by) \
     VALUES ($1, $2, $3, $4) RETURNING id",
  )
  .bind(workspace_id)
  .bind(name)
  .bind(description)
  .bind(created_by)
  .fetch_one(executor)
  .await?;
  Ok(id)
}

pub async fn select_groups<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  workspace_id: &Uuid,
) -> Result<Vec<AFGroupRow>, AppError> {
  let rows = sqlx::query_as::<_, AFGroupRow>(
    "SELECT g.id, g.workspace_id, g.name, g.description, COUNT(gm.uid) AS member_count \
     FROM af_group g LEFT JOIN af_group_member gm ON gm.group_id = g.id \
     WHERE g.workspace_id = $1 \
     GROUP BY g.id ORDER BY g.name",
  )
  .bind(workspace_id)
  .fetch_all(executor)
  .await?;
  Ok(rows)
}

/// Returns the workspace a group belongs to, or None if it does not exist.
pub async fn select_group_workspace<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  group_id: &Uuid,
) -> Result<Option<Uuid>, AppError> {
  let ws: Option<Uuid> =
    sqlx::query_scalar("SELECT workspace_id FROM af_group WHERE id = $1")
      .bind(group_id)
      .fetch_optional(executor)
      .await?;
  Ok(ws)
}

pub async fn delete_group<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  group_id: &Uuid,
) -> Result<(), AppError> {
  sqlx::query("DELETE FROM af_group WHERE id = $1")
    .bind(group_id)
    .execute(executor)
    .await?;
  Ok(())
}

pub async fn insert_group_member<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  group_id: &Uuid,
  uid: i64,
) -> Result<(), AppError> {
  sqlx::query(
    "INSERT INTO af_group_member (group_id, uid) VALUES ($1, $2) ON CONFLICT DO NOTHING",
  )
  .bind(group_id)
  .bind(uid)
  .execute(executor)
  .await?;
  Ok(())
}

pub async fn delete_group_member<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  group_id: &Uuid,
  uid: i64,
) -> Result<(), AppError> {
  sqlx::query("DELETE FROM af_group_member WHERE group_id = $1 AND uid = $2")
    .bind(group_id)
    .bind(uid)
    .execute(executor)
    .await?;
  Ok(())
}

pub async fn select_group_members<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  group_id: &Uuid,
) -> Result<Vec<AFGroupMemberRow>, AppError> {
  let rows = sqlx::query_as::<_, AFGroupMemberRow>(
    "SELECT u.uid, u.email, u.name FROM af_group_member gm \
     JOIN af_user u ON u.uid = gm.uid WHERE gm.group_id = $1 ORDER BY u.email",
  )
  .bind(group_id)
  .fetch_all(executor)
  .await?;
  Ok(rows)
}

/// Streams all group memberships for loading the casbin `g2` grouping at startup.
pub fn select_group_membership_stream(
  pg_pool: &PgPool,
) -> BoxStream<'_, sqlx::Result<AFGroupMembershipRow>> {
  sqlx::query_as::<_, AFGroupMembershipRow>("SELECT uid, group_id FROM af_group_member")
    .fetch(pg_pool)
}

/// Streams all group object-level grants for loading group policies at startup.
pub fn select_group_grant_perm_stream(
  pg_pool: &PgPool,
) -> BoxStream<'_, sqlx::Result<AFGroupGrantPermRow>> {
  sqlx::query_as::<_, AFGroupGrantPermRow>(
    "SELECT group_id, object_id, access_level FROM af_object_grant \
     WHERE group_id IS NOT NULL AND access_level IS NOT NULL",
  )
  .fetch(pg_pool)
}

// =====================================================================
// Custom roles + capabilities (Phase 3)
// =====================================================================

#[derive(sqlx::FromRow, serde::Serialize)]
pub struct AFCapabilityRow {
  pub capability: String,
  pub name: String,
  pub description: Option<String>,
}

#[derive(sqlx::FromRow)]
pub struct AFCustomRoleRow {
  pub id: i32,
  pub name: String,
  pub description: Option<String>,
}

/// The catalog of named capabilities (af_permissions rows with a capability).
pub async fn select_capabilities<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
) -> Result<Vec<AFCapabilityRow>, AppError> {
  let rows = sqlx::query_as::<_, AFCapabilityRow>(
    "SELECT capability, name, description FROM af_permissions \
     WHERE capability IS NOT NULL ORDER BY capability",
  )
  .fetch_all(executor)
  .await?;
  Ok(rows)
}

pub async fn insert_custom_role<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  workspace_id: &Uuid,
  name: &str,
  description: Option<&str>,
) -> Result<i32, AppError> {
  let id: i32 = sqlx::query_scalar(
    "INSERT INTO af_roles (name, workspace_id, is_custom, description) \
     VALUES ($1, $2, true, $3) RETURNING id",
  )
  .bind(name)
  .bind(workspace_id)
  .bind(description)
  .fetch_one(executor)
  .await?;
  Ok(id)
}

pub async fn select_custom_roles<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  workspace_id: &Uuid,
) -> Result<Vec<AFCustomRoleRow>, AppError> {
  let rows = sqlx::query_as::<_, AFCustomRoleRow>(
    "SELECT id, name, description FROM af_roles \
     WHERE workspace_id = $1 AND is_custom ORDER BY name",
  )
  .bind(workspace_id)
  .fetch_all(executor)
  .await?;
  Ok(rows)
}

/// The workspace a custom role belongs to, or None if it is not a custom role.
pub async fn select_custom_role_workspace<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  role_id: i32,
) -> Result<Option<Uuid>, AppError> {
  let ws: Option<Uuid> = sqlx::query_scalar(
    "SELECT workspace_id FROM af_roles WHERE id = $1 AND is_custom",
  )
  .bind(role_id)
  .fetch_optional(executor)
  .await?;
  Ok(ws)
}

/// Replaces a role's capability set (af_role_permissions rows mapped from
/// capability strings to permission ids).
///
/// Delete and insert run as separate statements in a transaction: a single
/// data-modifying CTE would evaluate both against the same snapshot, so the
/// insert would conflict with the not-yet-deleted rows.
pub async fn set_role_capabilities(
  pg_pool: &PgPool,
  role_id: i32,
  capabilities: &[String],
) -> Result<(), AppError> {
  let mut txn = pg_pool.begin().await?;
  sqlx::query("DELETE FROM af_role_permissions WHERE role_id = $1")
    .bind(role_id)
    .execute(&mut *txn)
    .await?;
  sqlx::query(
    "INSERT INTO af_role_permissions (role_id, permission_id) \
     SELECT $1, id FROM af_permissions WHERE capability = ANY($2)",
  )
  .bind(role_id)
  .bind(capabilities)
  .execute(&mut *txn)
  .await?;
  txn.commit().await?;
  Ok(())
}

pub async fn select_role_capabilities<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  role_id: i32,
) -> Result<Vec<String>, AppError> {
  let caps: Vec<String> = sqlx::query_scalar(
    "SELECT p.capability FROM af_role_permissions rp \
     JOIN af_permissions p ON p.id = rp.permission_id \
     WHERE rp.role_id = $1 AND p.capability IS NOT NULL",
  )
  .bind(role_id)
  .fetch_all(executor)
  .await?;
  Ok(caps)
}

pub async fn update_custom_role_meta<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  role_id: i32,
  name: &str,
  description: Option<&str>,
) -> Result<(), AppError> {
  sqlx::query(
    "UPDATE af_roles SET name = $2, description = $3 WHERE id = $1 AND is_custom",
  )
  .bind(role_id)
  .bind(name)
  .bind(description)
  .execute(executor)
  .await?;
  Ok(())
}

pub async fn delete_custom_role(pg_pool: &PgPool, role_id: i32) -> Result<(), AppError> {
  // Clear af_role_permissions first (its FK to af_roles is not deferrable), then
  // delete the role. af_user_custom_role cascades on the role delete.
  let mut txn = pg_pool.begin().await?;
  sqlx::query("DELETE FROM af_role_permissions WHERE role_id = $1")
    .bind(role_id)
    .execute(&mut *txn)
    .await?;
  sqlx::query("DELETE FROM af_roles WHERE id = $1 AND is_custom")
    .bind(role_id)
    .execute(&mut *txn)
    .await?;
  txn.commit().await?;
  Ok(())
}

pub async fn assign_custom_role<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  workspace_id: &Uuid,
  uid: i64,
  role_id: i32,
) -> Result<(), AppError> {
  sqlx::query(
    "INSERT INTO af_user_custom_role (workspace_id, uid, role_id) \
     VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
  )
  .bind(workspace_id)
  .bind(uid)
  .bind(role_id)
  .execute(executor)
  .await?;
  Ok(())
}

pub async fn unassign_custom_role<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  workspace_id: &Uuid,
  uid: i64,
  role_id: i32,
) -> Result<(), AppError> {
  sqlx::query(
    "DELETE FROM af_user_custom_role WHERE workspace_id = $1 AND uid = $2 AND role_id = $3",
  )
  .bind(workspace_id)
  .bind(uid)
  .bind(role_id)
  .execute(executor)
  .await?;
  Ok(())
}

/// Capabilities a user gains from custom roles assigned to them in a workspace.
pub async fn select_user_custom_capabilities<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  workspace_id: &Uuid,
  uid: i64,
) -> Result<Vec<String>, AppError> {
  let caps: Vec<String> = sqlx::query_scalar(
    "SELECT DISTINCT p.capability FROM af_user_custom_role ucr \
     JOIN af_role_permissions rp ON rp.role_id = ucr.role_id \
     JOIN af_permissions p ON p.id = rp.permission_id \
     WHERE ucr.workspace_id = $1 AND ucr.uid = $2 AND p.capability IS NOT NULL",
  )
  .bind(workspace_id)
  .bind(uid)
  .fetch_all(executor)
  .await?;
  Ok(caps)
}

/// The user's base workspace role id (1=Owner, 2=Member, 3=Guest), if a member.
pub async fn select_workspace_member_role_id<'a, E: Executor<'a, Database = Postgres>>(
  executor: E,
  workspace_id: &Uuid,
  uid: i64,
) -> Result<Option<i32>, AppError> {
  let role_id: Option<i32> = sqlx::query_scalar(
    "SELECT role_id FROM af_workspace_member WHERE workspace_id = $1 AND uid = $2",
  )
  .bind(workspace_id)
  .bind(uid)
  .fetch_optional(executor)
  .await?;
  Ok(role_id)
}
