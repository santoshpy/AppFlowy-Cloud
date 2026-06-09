-- Custom roles + capability catalog (Django-style RBAC, Phase 3).
--
-- Capabilities are named permissions (e.g. group.manage) checked in the
-- application layer. Custom roles bundle capabilities and are assigned to users
-- per workspace, granting those users the capabilities in addition to whatever
-- their base workspace role (Owner/Member/Guest) provides.

-- 1. Capability catalog: add a capability column to af_permissions and seed the
--    known capabilities. The existing access-level rows keep capability = NULL.
ALTER TABLE af_permissions ADD COLUMN IF NOT EXISTS capability TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS uq_af_permissions_capability
  ON af_permissions (capability) WHERE capability IS NOT NULL;

INSERT INTO af_permissions (name, description, access_level, capability) VALUES
  ('View pages',     'View pages and their content',        10, 'page.view'),
  ('Comment',        'Comment on pages',                    20, 'page.comment'),
  ('Edit pages',     'Create and edit pages',               30, 'page.edit'),
  ('Delete pages',   'Delete pages',                        50, 'page.delete'),
  ('Manage object access', 'Share pages and grant/revoke object access', 50, 'object.manage'),
  ('Manage members', 'Invite and remove workspace members', 50, 'member.manage'),
  ('Manage groups',  'Create, edit, and delete groups',     50, 'group.manage'),
  ('Manage roles',   'Create, edit, and delete custom roles', 50, 'role.manage')
ON CONFLICT (name) DO NOTHING;

-- 2. Custom roles: extend af_roles. Built-in roles (ids 1/2/3) keep
--    workspace_id = NULL and is_custom = false.
ALTER TABLE af_roles ADD COLUMN IF NOT EXISTS workspace_id UUID
  REFERENCES af_workspace (workspace_id) ON DELETE CASCADE;
ALTER TABLE af_roles ADD COLUMN IF NOT EXISTS is_custom BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE af_roles ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE af_roles ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Replace the global name uniqueness with builtin/custom-scoped uniqueness so a
-- custom role name only has to be unique within its workspace.
ALTER TABLE af_roles DROP CONSTRAINT IF EXISTS af_roles_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_af_roles_builtin_name
  ON af_roles (name) WHERE workspace_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_af_roles_custom_name
  ON af_roles (workspace_id, name) WHERE workspace_id IS NOT NULL;

-- 3. Per-user custom role assignment (additive; does not touch
--    af_workspace_member, so base-role enforcement is unchanged).
CREATE TABLE IF NOT EXISTS af_user_custom_role (
  workspace_id UUID NOT NULL REFERENCES af_workspace (workspace_id) ON DELETE CASCADE,
  uid BIGINT NOT NULL REFERENCES af_user (uid) ON DELETE CASCADE,
  role_id INT NOT NULL REFERENCES af_roles (id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, uid, role_id)
);
CREATE INDEX IF NOT EXISTS idx_af_user_custom_role_user
  ON af_user_custom_role (workspace_id, uid);
