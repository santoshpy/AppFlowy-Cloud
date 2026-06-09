use crate::entity::{ObjectType, SubjectType};
use crate::group::GroupAccessControl;
use app_error::AppError;
use async_trait::async_trait;
use database_entity::dto::AFAccessLevel;
use uuid::Uuid;

use super::access::AccessControl;
use super::adapter::group_subject;

#[derive(Clone)]
pub struct GroupAccessControlImpl {
  access_control: AccessControl,
}

impl GroupAccessControlImpl {
  pub fn new(access_control: AccessControl) -> Self {
    Self { access_control }
  }
}

#[async_trait]
impl GroupAccessControl for GroupAccessControlImpl {
  async fn add_member(&self, uid: i64, group_id: &Uuid) -> Result<(), AppError> {
    self
      .access_control
      .add_group_membership(uid, &SubjectType::Group(group_subject(group_id)))
      .await
  }

  async fn remove_member(&self, uid: i64, group_id: &Uuid) -> Result<(), AppError> {
    self
      .access_control
      .remove_group_membership(uid, &SubjectType::Group(group_subject(group_id)))
      .await
  }

  async fn grant_group_access(
    &self,
    group_id: &Uuid,
    oid: &Uuid,
    level: AFAccessLevel,
  ) -> Result<(), AppError> {
    let subject = SubjectType::Group(group_subject(group_id));
    let object = ObjectType::Collab(oid.to_string());
    // "set" semantics: replace any existing grant for this group on the object.
    self
      .access_control
      .remove_policy(subject.clone(), object.clone())
      .await?;
    self.access_control.update_policy(subject, object, level).await
  }

  async fn revoke_group_access(&self, group_id: &Uuid, oid: &Uuid) -> Result<(), AppError> {
    self
      .access_control
      .remove_policy(
        SubjectType::Group(group_subject(group_id)),
        ObjectType::Collab(oid.to_string()),
      )
      .await
  }
}
