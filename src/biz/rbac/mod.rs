use std::sync::Arc;

use access_control::collab::CollabAccessControl;
use access_control::group::GroupAccessControl;
use access_control::workspace::WorkspaceAccessControl;
use app_error::AppError;
use database::access_control::{
  delete_group, delete_group_member, delete_object_grant, insert_group, insert_group_member,
  select_group_members, select_group_workspace, select_groups, select_object_grants,
  upsert_group_object_grant, upsert_object_grant,
};
use database::user::select_uid_from_email;
use database_entity::dto::{AFAccessLevel, AFRole};
use shared_entity::dto::rbac_dto::{
  GrantGroupAccessParams, GrantObjectAccessParams, Group, GroupMember, GroupMembers, Groups,
  ObjectGrant, ObjectGrants,
};
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

// =====================================================================
// Groups (Phase 2)
// =====================================================================

/// Ensures a group exists and belongs to the given workspace, returning an error
/// otherwise. Prevents acting on a group across workspace boundaries.
async fn ensure_group_in_workspace(
  pg_pool: &PgPool,
  group_id: &Uuid,
  workspace_id: &Uuid,
) -> Result<(), AppError> {
  match select_group_workspace(pg_pool, group_id).await? {
    Some(ws) if &ws == workspace_id => Ok(()),
    _ => Err(AppError::RecordNotFound(format!(
      "group {} not found in workspace {}",
      group_id, workspace_id
    ))),
  }
}

pub async fn create_group(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  granter_uid: i64,
  workspace_id: &Uuid,
  name: &str,
  description: Option<&str>,
) -> Result<Uuid, AppError> {
  workspace_access_control
    .enforce_role_strong(&granter_uid, workspace_id, AFRole::Owner)
    .await?;
  insert_group(pg_pool, workspace_id, name, description, granter_uid).await
}

pub async fn list_groups(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  requester_uid: i64,
  workspace_id: &Uuid,
) -> Result<Groups, AppError> {
  workspace_access_control
    .enforce_role_weak(&requester_uid, workspace_id, AFRole::Member)
    .await?;
  let rows = select_groups(pg_pool, workspace_id).await?;
  let groups = rows
    .into_iter()
    .map(|r| Group {
      id: r.id,
      name: r.name,
      description: r.description,
      member_count: r.member_count,
    })
    .collect();
  Ok(Groups { groups })
}

pub async fn delete_group_op(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  group_access_control: &Arc<dyn GroupAccessControl>,
  granter_uid: i64,
  workspace_id: &Uuid,
  group_id: &Uuid,
) -> Result<(), AppError> {
  workspace_access_control
    .enforce_role_strong(&granter_uid, workspace_id, AFRole::Owner)
    .await?;
  ensure_group_in_workspace(pg_pool, group_id, workspace_id).await?;

  // Remove the live g2 memberships first so a deleted group grants nothing, then
  // delete the rows (FK cascade removes memberships and grants from the DB).
  let members = select_group_members(pg_pool, group_id).await?;
  delete_group(pg_pool, group_id).await?;
  for m in members {
    group_access_control.remove_member(m.uid, group_id).await?;
  }
  Ok(())
}

pub async fn add_group_member(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  group_access_control: &Arc<dyn GroupAccessControl>,
  granter_uid: i64,
  workspace_id: &Uuid,
  group_id: &Uuid,
  email: &str,
) -> Result<(), AppError> {
  workspace_access_control
    .enforce_role_strong(&granter_uid, workspace_id, AFRole::Owner)
    .await?;
  ensure_group_in_workspace(pg_pool, group_id, workspace_id).await?;

  let uid = select_uid_from_email(pg_pool, email).await?;
  insert_group_member(pg_pool, group_id, uid).await?;
  group_access_control.add_member(uid, group_id).await?;
  Ok(())
}

pub async fn remove_group_member(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  group_access_control: &Arc<dyn GroupAccessControl>,
  granter_uid: i64,
  workspace_id: &Uuid,
  group_id: &Uuid,
  member_uid: i64,
) -> Result<(), AppError> {
  workspace_access_control
    .enforce_role_strong(&granter_uid, workspace_id, AFRole::Owner)
    .await?;
  ensure_group_in_workspace(pg_pool, group_id, workspace_id).await?;

  delete_group_member(pg_pool, group_id, member_uid).await?;
  group_access_control.remove_member(member_uid, group_id).await?;
  Ok(())
}

pub async fn list_group_members(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  requester_uid: i64,
  workspace_id: &Uuid,
  group_id: &Uuid,
) -> Result<GroupMembers, AppError> {
  workspace_access_control
    .enforce_role_weak(&requester_uid, workspace_id, AFRole::Member)
    .await?;
  ensure_group_in_workspace(pg_pool, group_id, workspace_id).await?;

  let rows = select_group_members(pg_pool, group_id).await?;
  let members = rows
    .into_iter()
    .map(|r| GroupMember {
      uid: r.uid,
      email: r.email,
      name: r.name,
    })
    .collect();
  Ok(GroupMembers { members })
}

/// Grants a group an access level on an object (durable row + live enforcer).
pub async fn grant_group_object_access(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  group_access_control: &Arc<dyn GroupAccessControl>,
  granter_uid: i64,
  workspace_id: &Uuid,
  group_id: &Uuid,
  params: GrantGroupAccessParams,
) -> Result<(), AppError> {
  workspace_access_control
    .enforce_role_strong(&granter_uid, workspace_id, AFRole::Owner)
    .await?;
  ensure_group_in_workspace(pg_pool, group_id, workspace_id).await?;

  let level = params.access_level;
  upsert_group_object_grant(
    pg_pool,
    workspace_id,
    params.object_type.as_str(),
    &params.object_id,
    group_id,
    level as i32,
    granter_uid,
  )
  .await?;
  group_access_control
    .grant_group_access(group_id, &params.object_id, level)
    .await?;
  Ok(())
}
