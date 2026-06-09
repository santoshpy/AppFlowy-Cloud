# Team self-host fork

This fork adds a Django-style RBAC system and config-driven branding on top of
the open-source AppFlowy-Cloud (AGPLv3). It is built and run as custom Docker
images from this repo plus the sibling `../AppFlowy-Web` checkout.

## What this fork adds

- **Object-level access grants** — grant a user/group an access level
  (view/comment/edit/full) on a specific page/space (`/api/object-grant/...`).
- **Groups** — named collections of workspace members; a group can be granted
  access and members inherit it via the Casbin `g2` grouping (`/api/group/...`).
- **Custom roles + capabilities** — define roles that bundle capabilities
  (`page.view`, `group.manage`, `role.manage`, …) and assign them to members to
  **delegate** admin powers to non-owners (`/api/role/...`).
- **`useCan` capability gating** + Groups/Roles panels in the web Settings.
- **Config-driven branding** — `APPFLOWY_BRAND_*` env vars (web), defaulting to
  AppFlowy.

## Strict permission rule (security invariant)

Permissions may only ever be given to **existing members of the workspace**.
Object grants, group membership, and role assignment all validate that the
target user is a workspace member (`ensure_user_in_workspace` in
`src/biz/rbac/mod.rs`) and reject anyone outside it — so there is no permission
leak to non-members. Management actions are gated by capability
(`ensure_can_manage`: workspace Owner **or** the specific capability via an
assigned custom role). Listing endpoints require workspace membership.

## Build & run the custom images

```bash
# from this repo, with ../AppFlowy-Web checked out alongside it
./script/generate_env.sh                # or: cp deploy.env .env   (FQDN=localhost)
docker compose -f docker-compose.yml -f docker-compose.custom.yml up -d --build
```

`http://localhost` then serves the modified web (same-origin with the API).
Migrations run automatically at `appflowy_cloud` startup.

Rebuild a single service after changes:

```bash
docker compose -f docker-compose.yml -f docker-compose.custom.yml up -d --build appflowy_cloud
docker compose -f docker-compose.yml -f docker-compose.custom.yml up -d --build appflowy_web
```

Revert to the official published images: `docker compose up -d --force-recreate`
(drop the `-f docker-compose.custom.yml` overlay).

## Rebranding

Set these on the `appflowy_web` service (or `.env`); all default to AppFlowy:
`APPFLOWY_BRAND_NAME`, `APPFLOWY_BRAND_DESCRIPTION`, `APPFLOWY_BRAND_URL`,
`APPFLOWY_BRAND_TWITTER`. Replace `public/appflowy.{ico,svg}` / `og-image.png`
and the brand color in `src/styles/variables/{light,dark}.variables.css`
(`pnpm css:variables`) in the web repo for full rebranding.

## License

AGPLv3. Modified source must be offered to users (AGPL §13). Keep `team-main`
publicly accessible and linked from the running app.
