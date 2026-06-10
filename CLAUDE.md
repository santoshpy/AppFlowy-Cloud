# CLAUDE.md — AppFlowy-Cloud (team fork)

Self-hosted **team-RBAC fork** of AppFlowy-Cloud (Rust/Actix-web), branch `team-main`,
AGPLv3 (modified source must be offered to users). Pairs with the sibling
`../AppFlowy-Web` fork. `TEAM_SELF_HOST.md` is the build/run/RBAC reference.

## Golden rule: additive, merge-clean changes

This fork periodically merges `upstream/main`. Keep that merge cheap:
- **Prefer new files/modules over editing shared upstream files.** RBAC code lives in
  `src/api/rbac.rs`, `src/biz/rbac/`, `libs/database/src/access_control.rs`,
  `libs/access-control/src/casbin/` — not scattered into upstream handlers.
- When you must touch an upstream file, **confine edits to registration lines**
  (a `.service(...)`, a `mod` decl) and **match its existing style**.
- Don't refactor/reformat adjacent upstream code. Note unrelated dead code; don't delete it.
- Every changed line should trace to the request — a clean diff is a clean next merge.

## How to work here

- **Think first.** State assumptions; if the request has multiple readings or a simpler
  path, say so before coding. Don't hide confusion.
- **Simplest thing that works.** No speculative abstractions/config, no error handling for
  impossible cases. A single-use helper doesn't need a trait.
- **Goal-driven.** Turn the task into a checkable goal and loop until green (e.g.
  "non-member grant is rejected" → prove it with a test/curl, not an assertion).

## Commands (verify before claiming done)

```bash
# Rust — SQLX_OFFLINE is on; the .sqlx/ cache is committed
SQLX_OFFLINE=true cargo check --bin appflowy_cloud
cargo fmt --check                                              # rustfmt.toml: width 100, 2-space
cargo clippy --all-targets --all-features --tests -- -D warnings
cargo test

# Build & run the custom stack (needs ../AppFlowy-Web checked out)
docker build --build-arg PROFILE=debug -t appflowyinc/appflowy_cloud:custom .
docker compose -f docker-compose.yml -f docker-compose.custom.yml up -d --build
# Hot-swap one rebuilt service (.env: APPFLOWY_CLOUD_VERSION=custom):
docker compose up -d --no-deps --force-recreate appflowy_cloud
```

## Project specifics

- **New SQLx queries:** prefer runtime-checked `sqlx::query_as::<_, Row>("…").bind(…)` so you
  don't regenerate `.sqlx/` metadata. Use compile-time `query!` only if you also run
  `cargo sqlx prepare --workspace`.
- **Security invariant (never weaken):** permissions go **only to existing workspace
  members**. Grants, group membership, and role assignment all call `ensure_user_in_workspace`
  (`src/biz/rbac/mod.rs`) and reject outsiders. Management is gated by `ensure_can_manage`
  (Owner **or** the specific capability).
- **Web↔cloud API drift:** cloud `main` renamed some endpoints ahead of AppFlowy-Web. If the
  web shows "No access to this page" / a `/api/.../view` 404, add an **additive backward-compat
  route** delegating to the current handler — see `get_workspace_view_compat_handler`
  (`src/api/workspace.rs`) and `server_info_compat_scope` (`src/api/server_info.rs`).
- **RBAC enforcement** is Casbin (`libs/access-control/src/casbin/`): object grants + `g2`
  user→group grouping + workspace fallback. Keep the DB and the live enforcer in sync on every
  grant/revoke.

## Verifying in the browser

Use the **Playwright MCP** against `http://localhost`. Test users: `test@local.dev` /
`Password123!` (app); `admin@example.com` / `password` (`/console` super-admin).

Last updated: June 10, 2026 11:17 NPT
