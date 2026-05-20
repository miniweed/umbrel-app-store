# Miniweed Tunnel - Session Handoff

Last updated: 2026-05-20

## Current state

- Branch: `main`
- Latest pushed commit: `32c740b`
- Latest released app version in store: `1.6.21`
- Latest web image: `ghcr.io/miniweed/umbrel-tunnel-web:1.6.21`
- Latest wg image: `ghcr.io/miniweed/umbrel-tunnel-wg:1.0.5`

## What was completed in this chat

### Releases published in this session

1. `0dda7f8` - `1.6.16` critical hardening release
2. `d61d7eb` - `1.6.17` web startup permission hotfix
3. `78c740c` - `1.6.18` restricted-entrypoint compatibility fix
4. `4c10991` - `1.6.19` removed `/data/wg-ready` dependency
5. `324ca6e` - `1.6.20` attempted web UID/GID alignment for Umbrel volumes
6. `32c740b` - `1.6.21` restored web write compatibility on bind mounts

### Security and robustness changes delivered

- Strict IPv4 validation for `vpsIp` and `vpsTargets[].ip` in API schemas.
- Backup restore now validates `config.json` against `ConfigSchema` and rejects invalid payloads with issues.
- Added compose hardening:
  - `cap_drop: [ALL]`
  - `security_opt: no-new-privileges:true`
  - least-privilege `cap_add` where needed.
- Web CSP remains strict for SPA routes (`script-src 'self'`, no `unsafe-inline`).
- Added error-tolerant data-dir initialization to avoid hard crash if `/data/Caddyfile` cannot be created at boot.
- Removed fragile cross-container readiness file design:
  - `wg-client` no longer writes `/data/wg-ready`
  - `caddy` now waits for `/data/Caddyfile` plus `http://127.0.0.1:8080/status`.

### Umbrel install/debug findings validated live

- `1.6.16` and later exposed real-world bind-mount permission edge cases across clean reinstalls.
- `wg` restart loop root cause was `Permission denied` writing `/data/wg-ready` (now removed in `1.6.19`).
- `web` keygen/save failures (`EACCES` on `/data/config.json.tmp`) persisted with non-root users on some Umbrel setups.
- Final compatibility decision in `1.6.21`: run web process as root while keeping dropped capabilities and no-new-privileges.

## Validation performed

- Repeatedly ran `npm test -- --runInBand` in `miniweed-tunnel/web`.
- Latest run status: `31 passed, 31 total`.
- Built and pushed multi-arch images for:
  - `web:1.6.17`, `web:1.6.18`, `web:1.6.20`, `web:1.6.21`
  - `wg:1.0.5`

## Known remaining concerns

1. Fresh-install flow can still be slow at Umbrel "99%" stage; now observed to recover and finish, but bootstrap latency should be profiled.
2. Running web as root is a compatibility tradeoff; revisit a safer non-root model once Umbrel volume ownership behavior is characterized across environments.
3. `NEXT_SESSION.md` is now updated, but root-level analysis docs remain untracked unless intentionally committed.

## Untracked local files at handoff

- `INFORME_FINAL_MEJORAS_1.6.15.md`
- `MINIWEED_1.6.15_ANALISIS.md`

## Suggested resume point

1. Validate `1.6.21` on one more clean install path end-to-end (install, keygen, VPS script, tunnel up, exposed service reachable).
2. Investigate and reduce install-time "99%" delay (service startup dependency timing/logging).
3. Plan post-hotfix hardening pass to recover non-root web execution without breaking Umbrel bind-mount compatibility.
