-- Groups (Django-style RBAC, Phase 2).
--
-- A group is a named collection of workspace members. A group can be granted
-- access to an object via af_object_grant.group_id (the column was provisioned
-- in the Phase 1 migration); members inherit the group's grants through the
-- casbin `g2` user->group grouping.

CREATE TABLE IF NOT EXISTS af_group (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES af_workspace(workspace_id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  created_by BIGINT REFERENCES af_user(uid),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, name)
);

CREATE TABLE IF NOT EXISTS af_group_member (
  group_id UUID NOT NULL REFERENCES af_group(id) ON DELETE CASCADE,
  uid BIGINT NOT NULL REFERENCES af_user(uid) ON DELETE CASCADE,
  added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, uid)
);

CREATE INDEX IF NOT EXISTS idx_af_group_workspace ON af_group (workspace_id);
CREATE INDEX IF NOT EXISTS idx_af_group_member_uid ON af_group_member (uid);

-- Now that af_group exists, attach the deferred FK from the Phase 1 grant table.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'af_object_grant_group_id_fkey'
  ) THEN
    ALTER TABLE af_object_grant
      ADD CONSTRAINT af_object_grant_group_id_fkey
      FOREIGN KEY (group_id) REFERENCES af_group (id) ON DELETE CASCADE;
  END IF;
END $$;
