use actix_web::web::{self, Data, Json, Path};
use actix_web::{Result, Scope};
use shared_entity::dto::rbac_dto::{GrantObjectAccessParams, ObjectGrants};
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
