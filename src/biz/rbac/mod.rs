use std::sync::Arc;

use access_control::collab::CollabAccessControl;
use access_control::group::GroupAccessControl;
use access_control::workspace::WorkspaceAccessControl;
use app_error::AppError;
use std::collections::HashSet;

use database::access_control::{
  assign_custom_role, delete_custom_role, delete_group, delete_group_member,
  delete_group_object_grant, delete_object_grant, insert_custom_role, insert_group,
  insert_group_member, select_capabilities, select_custom_role_workspace,
  select_group_object_grant_ids,
  select_custom_roles, select_group_members, select_group_workspace, select_groups,
  select_object_grants, select_role_capabilities, select_role_members,
  select_user_custom_capabilities, select_workspace_member_role_id, set_role_capabilities,
  unassign_custom_role, update_custom_role_meta, upsert_group_object_grant, upsert_object_grant,
};
use database::user::select_uid_from_email;
use database_entity::dto::{AFAccessLevel, AFRole};
use shared_entity::dto::rbac_dto::{
  Capabilities, Capability, CreateRoleParams, CustomRole, CustomRoles, GrantGroupAccessParams,
  GrantObjectAccessParams, Group, GroupMember, GroupMembers, Groups, MyCapabilities, ObjectGrant,
  ObjectGrants, UpdateRoleParams,
};
use sqlx::PgPool;
use uuid::Uuid;

/// The full capability catalog (must mirror the seeded af_permissions.capability
/// rows). Owners implicitly have all of these.
const ALL_CAPABILITIES: &[&str] = &[
  "page.view",
  "page.comment",
  "page.edit",
  "page.delete",
  "object.manage",
  "member.manage",
  "group.manage",
  "role.manage",
];

/// Capabilities a built-in workspace role confers by default.
fn base_role_capabilities(role_id: Option<i32>) -> Vec<&'static str> {
  match role_id {
    Some(1) => ALL_CAPABILITIES.to_vec(),                  // Owner
    Some(2) => vec!["page.view", "page.comment", "page.edit"], // Member
    Some(3) => vec!["page.view"],                          // Guest
    _ => vec![],
  }
}

/// Rejects capability strings not in the catalog, so a role can't be created that
/// silently grants nothing (the DB `WHERE capability = ANY` would drop unknowns).
fn validate_capabilities(requested: &[String]) -> Result<(), AppError> {
  for cap in requested {
    if !ALL_CAPABILITIES.contains(&cap.as_str()) {
      return Err(AppError::InvalidRequest(format!("unknown capability: {cap}")));
    }
  }
  Ok(())
}

/// Rejects an empty or over-long display name.
fn validate_name(name: &str) -> Result<(), AppError> {
  let n = name.trim();
  if n.is_empty() || n.chars().count() > 100 {
    return Err(AppError::InvalidRequest(
      "name must be 1-100 characters".to_string(),
    ));
  }
  Ok(())
}

/// Only page-level object grants are enforced today (the Casbin adapter maps
/// every grant to a Collab policy); reject workspace/space types rather than
/// accept a grant the system silently ignores.
fn ensure_page_grant(object_type: &str) -> Result<(), AppError> {
  if object_type != "page" {
    return Err(AppError::InvalidRequest(
      "only page-level grants are supported".to_string(),
    ));
  }
  Ok(())
}

/// All capabilities a user effectively holds in a workspace: their built-in role
/// capabilities plus any conferred by assigned custom roles.
async fn effective_capabilities(
  pg_pool: &PgPool,
  uid: i64,
  workspace_id: &Uuid,
) -> Result<HashSet<String>, AppError> {
  let role_id = select_workspace_member_role_id(pg_pool, workspace_id, uid).await?;
  let mut caps: HashSet<String> = base_role_capabilities(role_id)
    .into_iter()
    .map(String::from)
    .collect();
  caps.extend(select_user_custom_capabilities(pg_pool, workspace_id, uid).await?);
  Ok(caps)
}

/// Prevents privilege escalation via custom roles: a non-owner may only place
/// capabilities into a role that they themselves hold, and may never grant
/// `role.manage` (which would let a delegate mint owner-equivalent powers).
/// Workspace Owners may grant any capability.
async fn ensure_can_grant_capabilities(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  uid: i64,
  workspace_id: &Uuid,
  requested: &[String],
) -> Result<(), AppError> {
  if workspace_access_control
    .enforce_role_weak(&uid, workspace_id, AFRole::Owner)
    .await
    .is_ok()
  {
    return Ok(());
  }
  let held = effective_capabilities(pg_pool, uid, workspace_id).await?;
  for cap in requested {
    if cap.as_str() == "role.manage" || !held.contains(cap) {
      return Err(AppError::NotEnoughPermissions);
    }
  }
  Ok(())
}

/// Returns Ok if the user may exercise the given management capability: workspace
/// Owners always may; otherwise the user must hold the capability through an
/// assigned custom role. This is the capability-based delegation gate, replacing
/// the previous owner-only checks while preserving owner behavior.
async fn ensure_can_manage(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  uid: i64,
  workspace_id: &Uuid,
  capability: &str,
) -> Result<(), AppError> {
  // Owner fast-path (also keeps behavior consistent with the enforcer).
  if workspace_access_control
    .enforce_role_weak(&uid, workspace_id, AFRole::Owner)
    .await
    .is_ok()
  {
    return Ok(());
  }
  let custom = select_user_custom_capabilities(pg_pool, workspace_id, uid).await?;
  if custom.iter().any(|c| c == capability) {
    return Ok(());
  }
  Err(AppError::NotEnoughPermissions)
}

/// Strict guard: a permission (object grant, group membership, role assignment)
/// may only ever be given to a user who is already a member of the workspace.
/// This prevents permission leaks to anyone outside the workspace.
async fn ensure_user_in_workspace(
  pg_pool: &PgPool,
  workspace_id: &Uuid,
  uid: i64,
) -> Result<(), AppError> {
  if select_workspace_member_role_id(pg_pool, workspace_id, uid)
    .await?
    .is_some()
  {
    Ok(())
  } else {
    Err(AppError::InvalidRequest(
      "the target user is not a member of this workspace".to_string(),
    ))
  }
}

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
  ensure_can_manage(
    pg_pool,
    workspace_access_control,
    granter_uid,
    workspace_id,
    "object.manage",
  )
  .await?;

  ensure_page_grant(params.object_type.as_str())?;
  let grantee_uid = select_uid_from_email(pg_pool, &params.email).await?;
  ensure_user_in_workspace(pg_pool, workspace_id, grantee_uid).await?;
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

  // B2: the durable row is committed; if the live enforcer update fails, surface
  // the error (the grant becomes effective once a restart reloads it from the DB).
  collab_access_control
    .update_access_level_policy(&grantee_uid, &params.object_id, level)
    .await
    .inspect_err(|e| {
      tracing::error!(
        "grant: enforcer update failed after durable write (uid={grantee_uid}, obj={}): {e}",
        params.object_id
      )
    })?;
  tracing::info!(
    target: "rbac_audit",
    actor = granter_uid, workspace = %workspace_id, grantee = grantee_uid,
    object = %params.object_id, level = level as i32, "grant_object_access"
  );
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
  ensure_can_manage(
    pg_pool,
    workspace_access_control,
    granter_uid,
    workspace_id,
    "object.manage",
  )
  .await?;

  // B2: remove live access FIRST (fail-closed — never leave access live after the
  // durable grant is gone), then delete the durable row. M1: scope the delete to
  // this workspace so an object id from another workspace can't be revoked here.
  collab_access_control
    .remove_access_level(&grantee_uid, object_id)
    .await
    .inspect_err(|e| {
      tracing::error!(
        "revoke: enforcer remove_access_level failed (uid={grantee_uid}, obj={object_id}): {e}"
      )
    })?;
  delete_object_grant(pg_pool, workspace_id, object_id, grantee_uid).await?;
  tracing::info!(
    target: "rbac_audit",
    actor = granter_uid, workspace = %workspace_id, grantee = grantee_uid,
    object = %object_id, "revoke_object_access"
  );
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
  ensure_can_manage(
    pg_pool,
    workspace_access_control,
    granter_uid,
    workspace_id,
    "group.manage",
  )
  .await?;
  validate_name(name)?;
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
  ensure_can_manage(
    pg_pool,
    workspace_access_control,
    granter_uid,
    workspace_id,
    "group.manage",
  )
  .await?;
  ensure_group_in_workspace(pg_pool, group_id, workspace_id).await?;

  // Remove the live g2 memberships first so a deleted group grants nothing, then
  // delete the rows (FK cascade removes memberships and grants from the DB).
  let members = select_group_members(pg_pool, group_id).await?;
  let grant_oids = select_group_object_grant_ids(pg_pool, group_id).await?;
  delete_group(pg_pool, group_id).await?;
  for m in members {
    group_access_control.remove_member(m.uid, group_id).await?;
  }
  // The DB grants are FK-cascaded by delete_group, but the live enforcer's
  // group-subject policies must be cleared too, else they linger until restart.
  for oid in grant_oids {
    group_access_control.revoke_group_access(group_id, &oid).await?;
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
  ensure_can_manage(
    pg_pool,
    workspace_access_control,
    granter_uid,
    workspace_id,
    "group.manage",
  )
  .await?;
  ensure_group_in_workspace(pg_pool, group_id, workspace_id).await?;

  let uid = select_uid_from_email(pg_pool, email).await?;
  ensure_user_in_workspace(pg_pool, workspace_id, uid).await?;
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
  ensure_can_manage(
    pg_pool,
    workspace_access_control,
    granter_uid,
    workspace_id,
    "group.manage",
  )
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
  ensure_can_manage(
    pg_pool,
    workspace_access_control,
    granter_uid,
    workspace_id,
    "object.manage",
  )
  .await?;
  ensure_group_in_workspace(pg_pool, group_id, workspace_id).await?;
  ensure_page_grant(params.object_type.as_str())?;

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

/// Revokes a group's grant on an object (durable row + live enforcer).
pub async fn revoke_group_object_access(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  group_access_control: &Arc<dyn GroupAccessControl>,
  granter_uid: i64,
  workspace_id: &Uuid,
  group_id: &Uuid,
  object_id: &Uuid,
) -> Result<(), AppError> {
  ensure_can_manage(
    pg_pool,
    workspace_access_control,
    granter_uid,
    workspace_id,
    "object.manage",
  )
  .await?;
  ensure_group_in_workspace(pg_pool, group_id, workspace_id).await?;

  // Fail-closed: remove live access first, then delete the durable row.
  group_access_control
    .revoke_group_access(group_id, object_id)
    .await
    .inspect_err(|e| {
      tracing::error!("revoke group grant: enforcer failed (group={group_id}, obj={object_id}): {e}")
    })?;
  delete_group_object_grant(pg_pool, workspace_id, object_id, group_id).await?;
  Ok(())
}

// =====================================================================
// Custom roles + capabilities (Phase 3)
// =====================================================================

async fn ensure_custom_role_in_workspace(
  pg_pool: &PgPool,
  role_id: i32,
  workspace_id: &Uuid,
) -> Result<(), AppError> {
  match select_custom_role_workspace(pg_pool, role_id).await? {
    Some(ws) if &ws == workspace_id => Ok(()),
    _ => Err(AppError::RecordNotFound(format!(
      "custom role {} not found in workspace {}",
      role_id, workspace_id
    ))),
  }
}

/// The capability catalog (available to any member building a role).
pub async fn list_capabilities(pg_pool: &PgPool) -> Result<Capabilities, AppError> {
  let rows = select_capabilities(pg_pool).await?;
  Ok(Capabilities {
    capabilities: rows
      .into_iter()
      .map(|r| Capability {
        capability: r.capability,
        name: r.name,
        description: r.description,
      })
      .collect(),
  })
}

pub async fn create_role(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  granter_uid: i64,
  workspace_id: &Uuid,
  params: CreateRoleParams,
) -> Result<i32, AppError> {
  ensure_can_manage(pg_pool, workspace_access_control, granter_uid, workspace_id, "role.manage").await?;
  ensure_can_grant_capabilities(
    pg_pool,
    workspace_access_control,
    granter_uid,
    workspace_id,
    &params.capabilities,
  )
  .await?;
  validate_name(&params.name)?;
  validate_capabilities(&params.capabilities)?;
  let role_id =
    insert_custom_role(pg_pool, workspace_id, &params.name, params.description.as_deref()).await?;
  set_role_capabilities(pg_pool, role_id, &params.capabilities).await?;
  Ok(role_id)
}

pub async fn list_roles(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  requester_uid: i64,
  workspace_id: &Uuid,
) -> Result<CustomRoles, AppError> {
  workspace_access_control
    .enforce_role_weak(&requester_uid, workspace_id, AFRole::Member)
    .await?;
  let rows = select_custom_roles(pg_pool, workspace_id).await?;
  let mut roles = Vec::with_capacity(rows.len());
  for r in rows {
    let capabilities = select_role_capabilities(pg_pool, r.id).await?;
    roles.push(CustomRole {
      id: r.id,
      name: r.name,
      description: r.description,
      capabilities,
    });
  }
  Ok(CustomRoles { roles })
}

pub async fn update_role(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  granter_uid: i64,
  workspace_id: &Uuid,
  role_id: i32,
  params: UpdateRoleParams,
) -> Result<(), AppError> {
  ensure_can_manage(pg_pool, workspace_access_control, granter_uid, workspace_id, "role.manage").await?;
  ensure_can_grant_capabilities(
    pg_pool,
    workspace_access_control,
    granter_uid,
    workspace_id,
    &params.capabilities,
  )
  .await?;
  validate_name(&params.name)?;
  validate_capabilities(&params.capabilities)?;
  ensure_custom_role_in_workspace(pg_pool, role_id, workspace_id).await?;
  update_custom_role_meta(pg_pool, role_id, &params.name, params.description.as_deref()).await?;
  set_role_capabilities(pg_pool, role_id, &params.capabilities).await?;
  Ok(())
}

pub async fn delete_role(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  granter_uid: i64,
  workspace_id: &Uuid,
  role_id: i32,
) -> Result<(), AppError> {
  ensure_can_manage(pg_pool, workspace_access_control, granter_uid, workspace_id, "role.manage").await?;
  ensure_custom_role_in_workspace(pg_pool, role_id, workspace_id).await?;
  delete_custom_role(pg_pool, role_id).await?;
  Ok(())
}

/// Lists the workspace members assigned a given custom role.
pub async fn list_role_members(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  requester_uid: i64,
  workspace_id: &Uuid,
  role_id: i32,
) -> Result<GroupMembers, AppError> {
  workspace_access_control
    .enforce_role_weak(&requester_uid, workspace_id, AFRole::Member)
    .await?;
  ensure_custom_role_in_workspace(pg_pool, role_id, workspace_id).await?;
  let rows = select_role_members(pg_pool, workspace_id, role_id).await?;
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

pub async fn assign_role(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  granter_uid: i64,
  workspace_id: &Uuid,
  email: &str,
  role_id: i32,
) -> Result<(), AppError> {
  ensure_can_manage(pg_pool, workspace_access_control, granter_uid, workspace_id, "role.manage").await?;
  ensure_custom_role_in_workspace(pg_pool, role_id, workspace_id).await?;
  let uid = select_uid_from_email(pg_pool, email).await?;
  ensure_user_in_workspace(pg_pool, workspace_id, uid).await?;
  assign_custom_role(pg_pool, workspace_id, uid, role_id).await?;
  tracing::info!(
    target: "rbac_audit",
    actor = granter_uid, workspace = %workspace_id, member = uid, role = role_id, "assign_role"
  );
  Ok(())
}

pub async fn unassign_role(
  pg_pool: &PgPool,
  workspace_access_control: &Arc<dyn WorkspaceAccessControl>,
  granter_uid: i64,
  workspace_id: &Uuid,
  member_uid: i64,
  role_id: i32,
) -> Result<(), AppError> {
  ensure_can_manage(pg_pool, workspace_access_control, granter_uid, workspace_id, "role.manage").await?;
  ensure_custom_role_in_workspace(pg_pool, role_id, workspace_id).await?;
  unassign_custom_role(pg_pool, workspace_id, member_uid, role_id).await?;
  tracing::info!(
    target: "rbac_audit",
    actor = granter_uid, workspace = %workspace_id, member = member_uid, role = role_id, "unassign_role"
  );
  Ok(())
}

/// The current user's effective capabilities in a workspace (base role + custom
/// roles). Feeds the web `useCan` hook.
pub async fn my_capabilities(
  pg_pool: &PgPool,
  uid: i64,
  workspace_id: &Uuid,
) -> Result<MyCapabilities, AppError> {
  let mut capabilities: Vec<String> = effective_capabilities(pg_pool, uid, workspace_id)
    .await?
    .into_iter()
    .collect();
  capabilities.sort();
  Ok(MyCapabilities { capabilities })
}
