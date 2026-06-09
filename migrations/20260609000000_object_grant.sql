-- Object-level access grants (Django-style RBAC, Phase 1).
--
-- A unified grant table: a subject (a user now; a group from Phase 2) is granted
-- access to an object (a workspace, a space, or a page) either by a role or by an
-- access level. Phase 1 only reads USER + access_level grants on pages/collabs;
-- the group_id / role_id columns are provisioned here so later phases are additive
-- (no further schema churn to the grant table).
--
-- Enforcement is additive: a grant can only ADD access on top of the workspace
-- role. A collab with no grants is governed entirely by workspace role, exactly
-- as before (see libs/access-control/src/casbin/collab.rs).

CREATE TABLE IF NOT EXISTS af_object_grant (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES af_workspace(workspace_id) ON DELETE CASCADE,
  -- 'workspace' | 'space' | 'page'. space/page object_id is a folder view / collab uuid.
  object_type TEXT NOT NULL CHECK (object_type IN ('workspace', 'space', 'page')),
  object_id UUID NOT NULL,
  -- subject: exactly one of uid / group_id is non-null.
  uid BIGINT REFERENCES af_user(uid) ON DELETE CASCADE,
  group_id UUID, -- FK to af_group(id) is added in the Phase 2 (groups) migration.
  -- grant: exactly one of role_id / access_level is non-null.
  role_id INT REFERENCES af_roles(id),
  access_level INT, -- one of af_permissions.access_level (10/20/30/50)
  granted_by BIGINT REFERENCES af_user(uid),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT af_object_grant_one_subject CHECK ((uid IS NOT NULL) <> (group_id IS NOT NULL)),
  CONSTRAINT af_object_grant_one_grant CHECK ((role_id IS NOT NULL) <> (access_level IS NOT NULL))
);

-- At most one grant per (object, subject); supports upsert / "set access level".
CREATE UNIQUE INDEX IF NOT EXISTS uq_af_object_grant_user
  ON af_object_grant (object_id, uid) WHERE uid IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_af_object_grant_group
  ON af_object_grant (object_id, group_id) WHERE group_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_af_object_grant_object ON af_object_grant (object_id);
CREATE INDEX IF NOT EXISTS idx_af_object_grant_uid ON af_object_grant (uid) WHERE uid IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_af_object_grant_workspace ON af_object_grant (workspace_id);

-- Best-effort backfill from the legacy per-collab member table. In current
-- installs af_collab_member is empty (writes were disabled), so this is usually
-- a no-op; included for correctness on older databases.
-- Cast oids to text for the join/regex (af_collab.oid and af_collab_member.oid
-- may be text or uuid depending on schema version) and to uuid for the target
-- column. This keeps the backfill valid regardless of the underlying oid type.
INSERT INTO af_object_grant (workspace_id, object_type, object_id, uid, access_level, granted_by)
SELECT c.workspace_id, 'page', m.oid::text::uuid, m.uid, p.access_level, m.uid
FROM af_collab_member m
JOIN af_permissions p ON p.id = m.permission_id
JOIN (SELECT DISTINCT oid::text AS oid, workspace_id FROM af_collab) c ON c.oid = m.oid::text
WHERE m.oid::text ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
ON CONFLICT DO NOTHING;
