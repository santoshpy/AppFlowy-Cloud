use client_api_test::{TestClient, LOCALHOST_URL};
use database_entity::dto::AFRole;
use serde_json::{json, Value};
use uuid::Uuid;

// The custom RBAC endpoints have no typed client-api methods yet, so these tests
// call them over raw HTTP with the user's bearer token. AppFlowy wraps responses
// as { code, message, data }; success is code == 0.

async fn api_call(
  client: &TestClient,
  method: reqwest::Method,
  path: &str,
  body: Option<Value>,
) -> Value {
  let token = client.api_client.access_token().unwrap();
  let url = format!("{}{}", LOCALHOST_URL.as_ref(), path);
  let mut req = reqwest::Client::new().request(method, url).bearer_auth(token);
  if let Some(b) = body {
    req = req.json(&b);
  }
  req
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap_or_else(|_| json!({ "code": -999 }))
}

fn code(resp: &Value) -> i64 {
  resp.get("code").and_then(|c| c.as_i64()).unwrap_or(-999)
}

/// Invariant: a permission can never be granted to a non-member of the workspace.
#[tokio::test]
async fn grant_object_access_to_non_member_is_rejected() {
  let owner = TestClient::new_user().await;
  let workspace_id = owner.workspace_id().await;
  let non_member = TestClient::new_user().await;

  let resp = api_call(
    &owner,
    reqwest::Method::PUT,
    &format!("/api/object-grant/workspace/{workspace_id}"),
    Some(json!({
      "object_type": "page",
      "object_id": Uuid::new_v4(),
      "email": non_member.user.email,
      "access_level": 10,
    })),
  )
  .await;
  assert_ne!(code(&resp), 0, "granting access to a non-member must be rejected");
}

/// A workspace member is allowed to receive an object grant.
#[tokio::test]
async fn grant_object_access_to_member_succeeds() {
  let owner = TestClient::new_user().await;
  let workspace_id = owner.workspace_id().await;
  let member = TestClient::new_user().await;
  owner
    .invite_and_accepted_workspace_member(&workspace_id, &member, AFRole::Member)
    .await
    .unwrap();

  let resp = api_call(
    &owner,
    reqwest::Method::PUT,
    &format!("/api/object-grant/workspace/{workspace_id}"),
    Some(json!({
      "object_type": "page",
      "object_id": Uuid::new_v4(),
      "email": member.user.email,
      "access_level": 30,
    })),
  )
  .await;
  assert_eq!(code(&resp), 0, "granting to a member should succeed: {resp}");
}

/// A plain member without any management capability cannot manage roles.
#[tokio::test]
async fn non_owner_without_capability_cannot_create_role() {
  let owner = TestClient::new_user().await;
  let workspace_id = owner.workspace_id().await;
  let member = TestClient::new_user().await;
  owner
    .invite_and_accepted_workspace_member(&workspace_id, &member, AFRole::Member)
    .await
    .unwrap();

  let resp = api_call(
    &member,
    reqwest::Method::POST,
    &format!("/api/role/workspace/{workspace_id}"),
    Some(json!({ "name": "X", "description": null, "capabilities": ["page.edit"] })),
  )
  .await;
  assert_ne!(code(&resp), 0, "a member without role.manage must not create roles");
}

/// B1 regression: a delegate holding only `role.manage` must NOT be able to mint a
/// role bundling capabilities it does not itself hold (privilege escalation).
#[tokio::test]
async fn role_manage_delegate_cannot_escalate_capabilities() {
  let owner = TestClient::new_user().await;
  let workspace_id = owner.workspace_id().await;
  let delegate = TestClient::new_user().await;
  owner
    .invite_and_accepted_workspace_member(&workspace_id, &delegate, AFRole::Member)
    .await
    .unwrap();

  // Owner creates a role granting only `role.manage` and assigns it to the delegate.
  let created = api_call(
    &owner,
    reqwest::Method::POST,
    &format!("/api/role/workspace/{workspace_id}"),
    Some(json!({ "name": "Role Admin", "description": null, "capabilities": ["role.manage"] })),
  )
  .await;
  let role_id = created.get("data").and_then(|d| d.as_i64()).expect("role id");

  let assigned = api_call(
    &owner,
    reqwest::Method::POST,
    &format!("/api/role/workspace/{workspace_id}/assign"),
    Some(json!({ "email": delegate.user.email, "role_id": role_id })),
  )
  .await;
  assert_eq!(code(&assigned), 0, "owner assigns role-admin to the delegate: {assigned}");

  // The delegate (role.manage only) tries to create a role with `member.manage`.
  let escalate = api_call(
    &delegate,
    reqwest::Method::POST,
    &format!("/api/role/workspace/{workspace_id}"),
    Some(json!({ "name": "Escalate", "description": null, "capabilities": ["member.manage"] })),
  )
  .await;
  assert_ne!(
    code(&escalate),
    0,
    "B1: a role.manage delegate must not grant a capability it lacks: {escalate}"
  );
}
