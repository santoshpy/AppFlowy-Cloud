use actix_web::web::{self, Data, Json, Path};
use actix_web::{Result, Scope};
use shared_entity::dto::rbac_dto::{
  AddGroupMemberParams, AssignRoleParams, Capabilities, CreateGroupParams, CreateRoleParams,
  CustomRoles, GrantGroupAccessParams, GrantObjectAccessParams, GroupMembers, Groups,
  MyCapabilities, ObjectGrants, UpdateRoleParams,
};
use shared_entity::response::{AppResponse, JsonAppResponse};
use uuid::Uuid;

use crate::biz::authentication::jwt::UserUuid;
use crate::biz::rbac;
use crate::state::AppState;

/// Object-level RBAC endpoints (Django-style grants), Phase 1: per-object user
/// access-level grants.
///
/// A distinct `/api/object-grant` prefix is used (rather than nesting under
/// `/api/workspace`) so it does not overlap the existing workspace scope's
/// prefix — overlapping Actix scope prefixes can shadow one another.
///
/// - `PUT    /api/object-grant/workspace/{workspace_id}`                        grant/update
/// - `GET    /api/object-grant/workspace/{workspace_id}/{object_id}`           list grants
/// - `DELETE /api/object-grant/workspace/{workspace_id}/{object_id}/user/{uid}` revoke
pub fn rbac_scope() -> Scope {
  web::scope("/api/object-grant/workspace/{workspace_id}")
    .service(web::resource("").route(web::put().to(grant_object_access_handler)))
    .service(web::resource("{object_id}").route(web::get().to(list_object_grants_handler)))
    .service(
      web::resource("{object_id}/user/{uid}")
        .route(web::delete().to(revoke_object_grant_handler)),
    )
}

async fn grant_object_access_handler(
  user_uuid: UserUuid,
  workspace_id: Path<Uuid>,
  payload: Json<GrantObjectAccessParams>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<()>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let workspace_id = workspace_id.into_inner();
  rbac::grant_object_access(
    &state.pg_pool,
    &state.workspace_access_control,
    &state.collab_access_control,
    uid,
    &workspace_id,
    payload.into_inner(),
  )
  .await?;
  Ok(AppResponse::Ok().into())
}

async fn list_object_grants_handler(
  user_uuid: UserUuid,
  path: Path<(Uuid, Uuid)>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<ObjectGrants>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let (workspace_id, object_id) = path.into_inner();
  let grants = rbac::list_object_grants(
    &state.pg_pool,
    &state.workspace_access_control,
    uid,
    &workspace_id,
    &object_id,
  )
  .await?;
  Ok(AppResponse::Ok().with_data(grants).into())
}

async fn revoke_object_grant_handler(
  user_uuid: UserUuid,
  path: Path<(Uuid, Uuid, i64)>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<()>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let (workspace_id, object_id, grantee_uid) = path.into_inner();
  rbac::revoke_object_access(
    &state.pg_pool,
    &state.workspace_access_control,
    &state.collab_access_control,
    uid,
    &workspace_id,
    &object_id,
    grantee_uid,
  )
  .await?;
  Ok(AppResponse::Ok().into())
}

/// Group management endpoints (Phase 2):
///
/// - `POST   /api/group/workspace/{workspace_id}`                          create
/// - `GET    /api/group/workspace/{workspace_id}`                          list
/// - `DELETE /api/group/workspace/{workspace_id}/{group_id}`               delete
/// - `GET    /api/group/workspace/{workspace_id}/{group_id}/member`        list members
/// - `POST   /api/group/workspace/{workspace_id}/{group_id}/member`        add member
/// - `DELETE /api/group/workspace/{workspace_id}/{group_id}/member/{uid}`  remove member
/// - `PUT    /api/group/workspace/{workspace_id}/{group_id}/grant`         grant group access
pub fn group_scope() -> Scope {
  web::scope("/api/group/workspace/{workspace_id}")
    .service(
      web::resource("")
        .route(web::post().to(create_group_handler))
        .route(web::get().to(list_groups_handler)),
    )
    .service(web::resource("{group_id}").route(web::delete().to(delete_group_handler)))
    .service(
      web::resource("{group_id}/member")
        .route(web::get().to(list_group_members_handler))
        .route(web::post().to(add_group_member_handler)),
    )
    .service(
      web::resource("{group_id}/member/{uid}")
        .route(web::delete().to(remove_group_member_handler)),
    )
    .service(web::resource("{group_id}/grant").route(web::put().to(grant_group_access_handler)))
}

async fn create_group_handler(
  user_uuid: UserUuid,
  workspace_id: Path<Uuid>,
  payload: Json<CreateGroupParams>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<Uuid>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let workspace_id = workspace_id.into_inner();
  let params = payload.into_inner();
  let id = rbac::create_group(
    &state.pg_pool,
    &state.workspace_access_control,
    uid,
    &workspace_id,
    &params.name,
    params.description.as_deref(),
  )
  .await?;
  Ok(AppResponse::Ok().with_data(id).into())
}

async fn list_groups_handler(
  user_uuid: UserUuid,
  workspace_id: Path<Uuid>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<Groups>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let workspace_id = workspace_id.into_inner();
  let groups = rbac::list_groups(&state.pg_pool, &state.workspace_access_control, uid, &workspace_id)
    .await?;
  Ok(AppResponse::Ok().with_data(groups).into())
}

async fn delete_group_handler(
  user_uuid: UserUuid,
  path: Path<(Uuid, Uuid)>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<()>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let (workspace_id, group_id) = path.into_inner();
  rbac::delete_group_op(
    &state.pg_pool,
    &state.workspace_access_control,
    &state.group_access_control,
    uid,
    &workspace_id,
    &group_id,
  )
  .await?;
  Ok(AppResponse::Ok().into())
}

async fn list_group_members_handler(
  user_uuid: UserUuid,
  path: Path<(Uuid, Uuid)>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<GroupMembers>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let (workspace_id, group_id) = path.into_inner();
  let members = rbac::list_group_members(
    &state.pg_pool,
    &state.workspace_access_control,
    uid,
    &workspace_id,
    &group_id,
  )
  .await?;
  Ok(AppResponse::Ok().with_data(members).into())
}

async fn add_group_member_handler(
  user_uuid: UserUuid,
  path: Path<(Uuid, Uuid)>,
  payload: Json<AddGroupMemberParams>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<()>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let (workspace_id, group_id) = path.into_inner();
  rbac::add_group_member(
    &state.pg_pool,
    &state.workspace_access_control,
    &state.group_access_control,
    uid,
    &workspace_id,
    &group_id,
    &payload.into_inner().email,
  )
  .await?;
  Ok(AppResponse::Ok().into())
}

async fn remove_group_member_handler(
  user_uuid: UserUuid,
  path: Path<(Uuid, Uuid, i64)>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<()>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let (workspace_id, group_id, member_uid) = path.into_inner();
  rbac::remove_group_member(
    &state.pg_pool,
    &state.workspace_access_control,
    &state.group_access_control,
    uid,
    &workspace_id,
    &group_id,
    member_uid,
  )
  .await?;
  Ok(AppResponse::Ok().into())
}

async fn grant_group_access_handler(
  user_uuid: UserUuid,
  path: Path<(Uuid, Uuid)>,
  payload: Json<GrantGroupAccessParams>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<()>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let (workspace_id, group_id) = path.into_inner();
  rbac::grant_group_object_access(
    &state.pg_pool,
    &state.workspace_access_control,
    &state.group_access_control,
    uid,
    &workspace_id,
    &group_id,
    payload.into_inner(),
  )
  .await?;
  Ok(AppResponse::Ok().into())
}

/// Custom roles + capabilities (Phase 3):
///
/// - `GET    /api/role/workspace/{workspace_id}/capabilities`     capability catalog
/// - `GET    /api/role/workspace/{workspace_id}/my-capabilities`  caller's effective caps
/// - `POST   /api/role/workspace/{workspace_id}/assign`           assign a role to a user
/// - `POST   /api/role/workspace/{workspace_id}`                  create role
/// - `GET    /api/role/workspace/{workspace_id}`                  list roles
/// - `PUT    /api/role/workspace/{workspace_id}/{role_id}`        update role
/// - `DELETE /api/role/workspace/{workspace_id}/{role_id}`        delete role
/// - `DELETE /api/role/workspace/{workspace_id}/{role_id}/user/{uid}` unassign a role
///
/// Literal resources are registered before the `{role_id}` resource so paths
/// like `capabilities` are not captured as a role id.
pub fn role_scope() -> Scope {
  web::scope("/api/role/workspace/{workspace_id}")
    .service(web::resource("capabilities").route(web::get().to(list_capabilities_handler)))
    .service(web::resource("my-capabilities").route(web::get().to(my_capabilities_handler)))
    .service(web::resource("assign").route(web::post().to(assign_role_handler)))
    .service(
      web::resource("")
        .route(web::post().to(create_role_handler))
        .route(web::get().to(list_roles_handler)),
    )
    .service(
      web::resource("{role_id}")
        .route(web::put().to(update_role_handler))
        .route(web::delete().to(delete_role_handler)),
    )
    .service(
      web::resource("{role_id}/user/{uid}").route(web::delete().to(unassign_role_handler)),
    )
}

async fn list_capabilities_handler(
  _user_uuid: UserUuid,
  _path: Path<Uuid>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<Capabilities>> {
  let caps = rbac::list_capabilities(&state.pg_pool).await?;
  Ok(AppResponse::Ok().with_data(caps).into())
}

async fn my_capabilities_handler(
  user_uuid: UserUuid,
  path: Path<Uuid>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<MyCapabilities>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let workspace_id = path.into_inner();
  let caps = rbac::my_capabilities(&state.pg_pool, uid, &workspace_id).await?;
  Ok(AppResponse::Ok().with_data(caps).into())
}

async fn create_role_handler(
  user_uuid: UserUuid,
  path: Path<Uuid>,
  payload: Json<CreateRoleParams>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<i32>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let workspace_id = path.into_inner();
  let id = rbac::create_role(
    &state.pg_pool,
    &state.workspace_access_control,
    uid,
    &workspace_id,
    payload.into_inner(),
  )
  .await?;
  Ok(AppResponse::Ok().with_data(id).into())
}

async fn list_roles_handler(
  user_uuid: UserUuid,
  path: Path<Uuid>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<CustomRoles>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let workspace_id = path.into_inner();
  let roles = rbac::list_roles(&state.pg_pool, &state.workspace_access_control, uid, &workspace_id)
    .await?;
  Ok(AppResponse::Ok().with_data(roles).into())
}

async fn update_role_handler(
  user_uuid: UserUuid,
  path: Path<(Uuid, i32)>,
  payload: Json<UpdateRoleParams>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<()>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let (workspace_id, role_id) = path.into_inner();
  rbac::update_role(
    &state.pg_pool,
    &state.workspace_access_control,
    uid,
    &workspace_id,
    role_id,
    payload.into_inner(),
  )
  .await?;
  Ok(AppResponse::Ok().into())
}

async fn delete_role_handler(
  user_uuid: UserUuid,
  path: Path<(Uuid, i32)>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<()>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let (workspace_id, role_id) = path.into_inner();
  rbac::delete_role(&state.pg_pool, &state.workspace_access_control, uid, &workspace_id, role_id)
    .await?;
  Ok(AppResponse::Ok().into())
}

async fn assign_role_handler(
  user_uuid: UserUuid,
  path: Path<Uuid>,
  payload: Json<AssignRoleParams>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<()>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let workspace_id = path.into_inner();
  let params = payload.into_inner();
  rbac::assign_role(
    &state.pg_pool,
    &state.workspace_access_control,
    uid,
    &workspace_id,
    &params.email,
    params.role_id,
  )
  .await?;
  Ok(AppResponse::Ok().into())
}

async fn unassign_role_handler(
  user_uuid: UserUuid,
  path: Path<(Uuid, i32, i64)>,
  state: Data<AppState>,
) -> Result<JsonAppResponse<()>> {
  let uid = state.user_cache.get_user_uid(&user_uuid).await?;
  let (workspace_id, role_id, member_uid) = path.into_inner();
  rbac::unassign_role(
    &state.pg_pool,
    &state.workspace_access_control,
    uid,
    &workspace_id,
    member_uid,
    role_id,
  )
  .await?;
  Ok(AppResponse::Ok().into())
}
