use app_error::AppError;
use async_trait::async_trait;
use database_entity::dto::AFAccessLevel;
use uuid::Uuid;

/// Manages group membership and group object-level grants in the enforcer.
///
/// Membership maps a user to a group via the casbin `g2` grouping, so that
/// object grants made to the group (subject `g:<group_id>`) also apply to the
/// user. The durable rows live in `af_group_member` / `af_object_grant`; this
/// trait keeps the live enforcer in sync.
#[async_trait]
pub trait GroupAccessControl: Send + Sync + 'static {
  async fn add_member(&self, uid: i64, group_id: &Uuid) -> Result<(), AppError>;
  async fn remove_member(&self, uid: i64, group_id: &Uuid) -> Result<(), AppError>;
  async fn grant_group_access(
    &self,
    group_id: &Uuid,
    oid: &Uuid,
    level: AFAccessLevel,
  ) -> Result<(), AppError>;
  async fn revoke_group_access(&self, group_id: &Uuid, oid: &Uuid) -> Result<(), AppError>;
}
