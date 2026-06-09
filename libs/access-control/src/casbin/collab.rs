use crate::{
  act::Action,
  collab::{CollabAccessControl, RealtimeAccessControl},
  entity::{ObjectType, SubjectType},
};
use app_error::AppError;
use async_trait::async_trait;
use database_entity::dto::AFAccessLevel;
use tracing::instrument;
use uuid::Uuid;

use super::access::AccessControl;

#[derive(Clone)]
pub struct CollabAccessControlImpl {
  access_control: AccessControl,
}

impl CollabAccessControlImpl {
  pub fn new(access_control: AccessControl) -> Self {
    Self { access_control }
  }
}

#[async_trait]
impl CollabAccessControl for CollabAccessControlImpl {
  async fn enforce_action(
    &self,
    workspace_id: &Uuid,
    uid: &i64,
    oid: &Uuid,
    action: Action,
  ) -> Result<(), AppError> {
    // Anyone who can write to a workspace, can also delete a collab.
    let workspace_action = match action {
      Action::Read => Action::Read,
      Action::Write => Action::Write,
      Action::Delete => Action::Write,
    };

    // 1. Object-level grant (additive): if the user has a direct access-level
    //    grant on this specific collab that permits the action, allow it. This
    //    lets a user act on a page even when their workspace role wouldn't, and
    //    is the basis for per-page sharing.
    if self
      .access_control
      .enforce_immediately(
        uid,
        ObjectType::Collab(oid.to_string()),
        workspace_action.clone(),
      )
      .await?
    {
      return Ok(());
    }

    // 2. Fall back to the workspace role (unchanged behavior). A collab with no
    //    object-level grants is therefore governed entirely by workspace role,
    //    exactly as before.
    match self
      .access_control
      .enforce_immediately(
        uid,
        ObjectType::Workspace(workspace_id.to_string()),
        workspace_action,
      )
      .await
    {
      Ok(true) => Ok(()),
      Ok(false) => Err(AppError::NotEnoughPermissions),
      Err(e) => Err(e),
    }
  }

  async fn enforce_access_level(
    &self,
    workspace_id: &Uuid,
    uid: &i64,
    oid: &Uuid,
    access_level: AFAccessLevel,
  ) -> Result<(), AppError> {
    // 1. Object-level grant (additive): a direct grant on the collab whose level
    //    is >= the required level allows access.
    if self
      .access_control
      .enforce_immediately(uid, ObjectType::Collab(oid.to_string()), access_level)
      .await?
    {
      return Ok(());
    }

    // 2. Fall back to the workspace role (unchanged behavior). Anyone who can
    //    write to a workspace has full access to its collabs.
    let workspace_action = match access_level {
      AFAccessLevel::ReadOnly => Action::Read,
      AFAccessLevel::ReadAndComment => Action::Read,
      AFAccessLevel::ReadAndWrite => Action::Write,
      AFAccessLevel::FullAccess => Action::Write,
    };

    match self
      .access_control
      .enforce_immediately(
        uid,
        ObjectType::Workspace(workspace_id.to_string()),
        workspace_action,
      )
      .await
    {
      Ok(true) => Ok(()),
      Ok(false) => Err(AppError::NotEnoughPermissions),
      Err(e) => Err(e),
    }
  }

  #[instrument(level = "info", skip_all)]
  async fn update_access_level_policy(
    &self,
    uid: &i64,
    oid: &Uuid,
    level: AFAccessLevel,
  ) -> Result<(), AppError> {
    let object = ObjectType::Collab(oid.to_string());
    // Replace any existing grant for this user on the object so that updating an
    // access level has "set" semantics (the durable af_object_grant row is a
    // single upserted row per (object, user)).
    self
      .access_control
      .remove_policy(SubjectType::User(*uid), object.clone())
      .await?;
    self
      .access_control
      .update_policy(SubjectType::User(*uid), object, level)
      .await
  }

  #[instrument(level = "info", skip_all)]
  async fn remove_access_level(&self, uid: &i64, oid: &Uuid) -> Result<(), AppError> {
    self
      .access_control
      .remove_policy(SubjectType::User(*uid), ObjectType::Collab(oid.to_string()))
      .await
  }
}

#[derive(Clone)]
pub struct RealtimeCollabAccessControlImpl {
  access_control: AccessControl,
}

impl RealtimeCollabAccessControlImpl {
  pub fn new(access_control: AccessControl) -> Self {
    Self { access_control }
  }

  async fn can_perform_action(
    &self,
    workspace_id: &Uuid,
    uid: &i64,
    oid: &Uuid,
    required_action: Action,
  ) -> Result<bool, AppError> {
    // Anyone who can write to a workspace, can also delete a collab.
    let workspace_action = match required_action {
      Action::Read => Action::Read,
      Action::Write => Action::Write,
      Action::Delete => Action::Write,
    };

    // 1. Object-level grant (additive) on this specific collab.
    if self
      .access_control
      .enforce_immediately(
        uid,
        ObjectType::Collab(oid.to_string()),
        workspace_action.clone(),
      )
      .await?
    {
      return Ok(true);
    }

    // 2. Fall back to the workspace role (unchanged behavior).
    self
      .access_control
      .enforce_immediately(
        uid,
        ObjectType::Workspace(workspace_id.to_string()),
        workspace_action,
      )
      .await
  }
}

#[async_trait]
impl RealtimeAccessControl for RealtimeCollabAccessControlImpl {
  async fn can_write_collab(
    &self,
    workspace_id: &Uuid,
    uid: &i64,
    oid: &Uuid,
  ) -> Result<bool, AppError> {
    self
      .can_perform_action(workspace_id, uid, oid, Action::Write)
      .await
  }

  async fn can_read_collab(
    &self,
    workspace_id: &Uuid,
    uid: &i64,
    oid: &Uuid,
  ) -> Result<bool, AppError> {
    self
      .can_perform_action(workspace_id, uid, oid, Action::Read)
      .await
  }
}

#[cfg(test)]
mod tests {
  use database_entity::dto::AFRole;
  use uuid::Uuid;

  use crate::casbin::util::tests::test_enforcer_v2;
  use crate::{
    act::Action,
    casbin::access::AccessControl,
    collab::CollabAccessControl,
    entity::{ObjectType, SubjectType},
  };

  #[tokio::test]
  pub async fn test_collab_access_control() {
    let enforcer = test_enforcer_v2().await;
    let uid = 1;
    let workspace_id = Uuid::new_v4();
    let oid = Uuid::new_v4();
    enforcer
      .update_policy(
        SubjectType::User(uid),
        ObjectType::Workspace(workspace_id.to_string()),
        AFRole::Member,
      )
      .await
      .unwrap();
    let access_control = AccessControl::with_enforcer(enforcer);
    let collab_access_control = super::CollabAccessControlImpl::new(access_control);
    for action in [Action::Read, Action::Write, Action::Delete] {
      collab_access_control
        .enforce_action(&workspace_id, &uid, &oid, action.clone())
        .await
        .unwrap_or_else(|_| panic!("Failed to enforce action: {:?}", action));
    }
  }

  /// A user who is NOT a workspace member gains access to a specific collab
  /// purely through an object-level grant, and loses it on revoke. Exercises the
  /// additive grant + set-on-update + revoke paths of CollabAccessControlImpl.
  #[tokio::test]
  pub async fn test_object_level_grant_for_non_member() {
    use database_entity::dto::AFAccessLevel;

    let enforcer = test_enforcer_v2().await;
    let uid = 42; // not a member of the workspace below
    let workspace_id = Uuid::new_v4();
    let oid = Uuid::new_v4();
    let access_control = AccessControl::with_enforcer(enforcer);
    let collab_access_control = super::CollabAccessControlImpl::new(access_control);

    // No workspace role and no grant -> denied for any action.
    assert!(collab_access_control
      .enforce_action(&workspace_id, &uid, &oid, Action::Read)
      .await
      .is_err());

    // Grant ReadOnly on this collab -> can read, cannot write.
    collab_access_control
      .update_access_level_policy(&uid, &oid, AFAccessLevel::ReadOnly)
      .await
      .unwrap();
    collab_access_control
      .enforce_action(&workspace_id, &uid, &oid, Action::Read)
      .await
      .expect("ReadOnly grant should allow read");
    assert!(collab_access_control
      .enforce_action(&workspace_id, &uid, &oid, Action::Write)
      .await
      .is_err());

    // Upgrading to ReadAndWrite has "set" semantics -> write now allowed.
    collab_access_control
      .update_access_level_policy(&uid, &oid, AFAccessLevel::ReadAndWrite)
      .await
      .unwrap();
    collab_access_control
      .enforce_action(&workspace_id, &uid, &oid, Action::Write)
      .await
      .expect("ReadAndWrite grant should allow write");

    // A grant on this collab must not leak to a different collab.
    let other_oid = Uuid::new_v4();
    assert!(collab_access_control
      .enforce_action(&workspace_id, &uid, &other_oid, Action::Read)
      .await
      .is_err());

    // Revoke -> access removed entirely.
    collab_access_control
      .remove_access_level(&uid, &oid)
      .await
      .unwrap();
    assert!(collab_access_control
      .enforce_action(&workspace_id, &uid, &oid, Action::Read)
      .await
      .is_err());
  }
}
