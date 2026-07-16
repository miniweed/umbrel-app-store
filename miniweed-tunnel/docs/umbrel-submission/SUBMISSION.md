# Official Umbrel App Store submission — ready-to-go pack

Everything needed for the PR to `getumbrel/umbrel-apps`. Nothing here touches
Umbrel's repos; it's staging. The official-store manifest tracks the same
upstream version line as the community store (`1.6.x`), per review feedback.

**PR:** https://github.com/getumbrel/umbrel-apps/pull/5758 (open; first review
round by @nmfretz addressed — auth boundary, mount split, secret isolation,
digest pinning — plus a follow-up hardening pass in `1.6.47`: the web server
only accepts connections from the app's own `app_proxy` or loopback, so other
containers on the shared Docker network can't bootstrap API access. Third
review round addressed in `1.6.49`: `DAC_OVERRIDE` on `web`/`caddy` so fresh
installs with `1000:1000`-owned data dirs can write, and the `wg` container
now mounts only `data/wg/` — the subdir holding the generated `wg0.conf` —
instead of the whole app data dir; existing configs migrate on first boot.)

## Status checklist

- [x] All user-facing text in English (UI, backend errors, VPS script, manifest, docs)
- [x] Multi-arch images (linux/amd64 + linux/arm64) built by CI
- [x] Web container hardened: `cap_drop: ALL` + `no-new-privileges`, and a
      proxy-peer gate: only the app's `app_proxy` (Umbrel-authenticated) can
      reach the web server; other containers get 403
- [x] Secrets isolated: `APP_SEED` only reaches `web`; `caddy`/`wg` get a
      derived token from `exports.sh`
- [x] Mounts split: Caddy has no access to app data; `wg` mounts only
      `data/wg/` (the generated `wg0.conf`) read-only
- [x] Data persisted in volumes (`${APP_DATA_DIR}/...`), bind-mount dirs committed
      with `.gitkeep`
- [x] `app_proxy` with Umbrel auth (`PROXY_AUTH_ADD: true`)
- [x] Manifest (`umbrel-app.yml`) with `version: "1.6.49"` (the packaged upstream
      version, per review), `gallery: []`, `releaseNotes: ""`, `submitter`, `submission`
- [x] `docker-compose.yml` with all images pinned by multi-arch digest
- [x] App tested end-to-end on real umbrelOS (tunnel + HTTPS working)
- [x] **Icon**: 256×256 SVG (no rounded corners) — `icon-256.svg` (+ `icon-256.png`)
- [x] **Gallery**: 4 real screenshots at **1440×900 PNG** in `gallery/`
      (`01-instructions`, `02-configuration`, `03-vps-setup`, `04-services`),
      embedded in the PR body.

## Image digests (verify against ghcr.io before re-pinning)

- `ghcr.io/miniweed/umbrel-tunnel-web:1.6.49`
  `(pending publish — re-pin after CI pushes the tag)`
- `ghcr.io/miniweed/umbrel-tunnel-wg:1.0.6`
  `sha256:22fbcbc01c31ec70c623ac670f195353c5fa37525ccecb18be86d9df2ed87469`

Note: `publish-images.yml` skips any image whose version tag already exists on
ghcr.io, so pinned tags can't drift; publishing new content requires a version
bump. Digest re-pin commits still use `[skip ci]` to save a no-op CI run.

## Files in the PR (`miniweed-tunnel/` in the fork)

- `umbrel-app.yml` → `./umbrel-app.yml` from this folder
- `docker-compose.yml` → `./docker-compose.yml` from this folder
- `exports.sh` → `../../exports.sh` (derives `TUNNEL_WG_TOKEN` from `APP_SEED`)
- `data/.gitkeep`, `data/wg/.gitkeep`, `caddy/data/.gitkeep`,
  `caddy/config/.gitkeep` (bind-mount dirs)

## Updating the PR branch

```bash
gh repo clone miniweed/umbrel-apps -- --branch add-miniweed-tunnel
cd umbrel-apps
# copy the updated files listed above into miniweed-tunnel/
git add miniweed-tunnel && git commit -m "<what changed>"
git push origin add-miniweed-tunnel
```

## PR body

See `PR-BODY.md` (icon + the 4 gallery screenshots are embedded from this repo's
`main` branch via raw.githubusercontent.com URLs).
