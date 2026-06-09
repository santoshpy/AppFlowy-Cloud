use database_entity::dto::AFAccessLevel;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The kind of object a grant targets. A space/page object_id is a folder
/// view / collab uuid; a workspace object_id is the workspace uuid.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GrantObjectType {
  Workspace,
  Space,
  Page,
}

impl GrantObjectType {
  pub fn as_str(&self) -> &'static str {
    match self {
      GrantObjectType::Workspace => "workspace",
      GrantObjectType::Space => "space",
      GrantObjectType::Page => "page",
    }
  }
}

/// Request body to grant (or update) a user's access level on an object.
#[derive(Serialize, Deserialize, Debug)]
pub struct GrantObjectAccessParams {
  pub object_type: GrantObjectType,
  pub object_id: Uuid,
  /// The grantee, identified by email (consistent with the invite/member APIs).
  pub email: String,
  pub access_level: AFAccessLevel,
}

/// A single user grant on an object, with grantee identity, for listings.
#[derive(Serialize, Deserialize, Debug)]
pub struct ObjectGrant {
  pub object_id: Uuid,
  pub uid: i64,
  pub email: String,
  pub name: String,
  pub access_level: AFAccessLevel,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ObjectGrants {
  pub grants: Vec<ObjectGrant>,
}

// ===== Groups (Phase 2) =====

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateGroupParams {
  pub name: String,
  pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Group {
  pub id: Uuid,
  pub name: String,
  pub description: Option<String>,
  pub member_count: i64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Groups {
  pub groups: Vec<Group>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GroupMember {
  pub uid: i64,
  pub email: String,
  pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct GroupMembers {
  pub members: Vec<GroupMember>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AddGroupMemberParams {
  pub email: String,
}

/// Grant a group an access level on an object (members inherit it).
#[derive(Serialize, Deserialize, Debug)]
pub struct GrantGroupAccessParams {
  pub object_type: GrantObjectType,
  pub object_id: Uuid,
  pub access_level: AFAccessLevel,
}
