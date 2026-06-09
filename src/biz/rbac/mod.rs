use std::sync::Arc;

use access_control::collab::CollabAccessControl;
use access_control::workspace::WorkspaceAccessControl;
use app_error::AppError;
use database::access_control::{delete_object_grant, select_object_grants, upsert_object_grant};
use database::user::select_uid_from_email;
use database_entity::dto::{AFAccessLevel, AFRole};
use shared_entity::dto::rbac_dto::{GrantObjectAccessParams, ObjectGrant, ObjectGrants};
use sqlx::PgPool;
use uuid::Uuid;

fn access_level_from_i32(value: i32) -> AFAccessLevel {
  match value {
    10 => AFAccessLevel::ReadOnly,
    20 => AFAccessLevel::ReadAndComment,
    30 => AFAccessLevel::ReadAndWrite,
    50 => AFAccessLevel::FullAccess,
    _ => AFAccessLevel::ReadOnly,
  }
}

/// Grants (or updates) a user's access level on an object.
///
/// Writes the durable `af_object_grant` row and updates the live enforcer so the
/// grant takes effect immediately and survives a restart (the adapter reloads
/// from the table). Only workspace Owners may manage object-level grants in
/// Phase 1; finer-grained "page managers" come with capabilities in Phase 3.
pub async fn grant_object_access(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  collab_access_control: &Arc<dyn CollabAccessControl>,
  granter_uid: i64,
  workspace_id: &Uuid,
  params: GrantObjectAccessParams,
) -> Result<(), AppError> {
  workspace_access_control
    .enforce_role_strong(&granter_uid, workspace_id, AFRole::Owner)
    .await?;

  let grantee_uid = select_uid_from_email(pg_pool, &params.email).await?;
  let level = params.access_level;

  upsert_object_grant(
    pg_pool,
    workspace_id,
    params.object_type.as_str(),
    &params.object_id,
    grantee_uid,
    level as i32,
    granter_uid,
  )
  .await?;

  collab_access_control
    .update_access_level_policy(&grantee_uid, &params.object_id, level)
    .await?;
  Ok(())
}

/// Revokes a user's grant on an object (durable row + live enforcer).
pub async fn revoke_object_access(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  collab_access_control: &Arc<dyn CollabAccessControl>,
  granter_uid: i64,
  workspace_id: &Uuid,
  object_id: &Uuid,
  grantee_uid: i64,
) -> Result<(), AppError> {
  workspace_access_control
    .enforce_role_strong(&granter_uid, workspace_id, AFRole::Owner)
    .await?;

  delete_object_grant(pg_pool, object_id, grantee_uid).await?;
  collab_access_control
    .remove_access_level(&grantee_uid, object_id)
    .await?;
  Ok(())
}

/// Lists the user grants on an object. Any workspace member may view them.
pub async fn list_object_grants(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  requester_uid: i64,
  workspace_id: &Uuid,
  object_id: &Uuid,
) -> Result<ObjectGrants, AppError> {
  workspace_access_control
    .enforce_role_weak(&requester_uid, workspace_id, AFRole::Member)
    .await?;

  let rows = select_object_grants(pg_pool, object_id).await?;
  let grants = rows
    .into_iter()
    .map(|r| ObjectGrant {
      object_id: r.object_id,
      uid: r.uid,
      email: r.email,
      name: r.name,
      access_level: access_level_from_i32(r.access_level),
    })
    .collect();
  Ok(ObjectGrants { grants })
}
