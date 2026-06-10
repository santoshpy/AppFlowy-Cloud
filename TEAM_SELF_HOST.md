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

## Web ↔ cloud API compatibility (why the compat routes exist)

AppFlowy ships its `:latest` Docker images from a coordinated web+cloud pairing,
but the two repos' `main` branches are **not** always API-compatible: cloud
`main` has restructured some endpoints ahead of web `main`. Building **both**
forks from `main` therefore breaks core app features (folder/page loading) with
404s, even though the RBAC code is correct.

To keep a from-source build runnable, this fork adds **additive backward-compat
routes** in the cloud that delegate to the current handlers (identical
responses), so AppFlowy Web `main` works unchanged:

| Web (main) calls | Cloud `main` serves | Compat route added |
|---|---|---|
| `GET /api/workspace/{id}/view/{view_id}?depth=N` | `/{id}/folder?root_view_id=…` | `get_workspace_view_compat_handler` (`src/api/workspace.rs`) |
| `GET /api/server-info` | `/api/server` | `server_info_compat_scope` (`src/api/server_info.rs`) |

These are pure aliases (no logic forked), so they carry near-zero merge risk on
upstream sync. If a future upstream merge changes more endpoint names, add the
alias the same way (symptom: the web shows "No access to this page" and the
browser console shows a 404 on a `/view` or other renamed path).

## Strict permission rule (security invariant)

Permissions may only ever be given to **existing members of the workspace**.
Object grants, group membership, and role assignment all validate that the
target user is a workspace member (`ensure_user_in_workspace` in
`src/biz/rbac/mod.rs`) and reject anyone outside it — so there is no permission
leak to non-members. Management actions are gated by capability
(`ensure_can_manage`: workspace Owner **or** the specific capability via an
assigned custom role). Listing endpoints require workspace membership.

## Admin console (`/console`) — server / user administration

The published `appflowy_web` stack ships the **commercial** Next.js super-admin
image, which makes browser-side calls to `APPFLOWY_BASE_URL` and therefore does
**not** work on a `localhost` self-host (the browser and the container disagree
on what `localhost`/`appflowy_cloud` mean). The custom overlay instead builds and
runs the repo's **OSS `admin_frontend`** (Rust/axum, fully server-rendered): the
browser only ever talks to the console, which calls gotrue/appflowy_cloud
server-side over the internal docker network. This works on localhost.

- URL: `http://localhost/console` → login `admin@example.com` / `password`.
- Features: list/create/delete users, invite, change password, SSO, usage.
- Server-side config is via `ADMIN_FRONTEND_GOTRUE_URL` /
  `ADMIN_FRONTEND_APPFLOWY_CLOUD_URL` (internal), set in docker-compose.custom.yml.

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
