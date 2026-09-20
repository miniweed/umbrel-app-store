# Official Umbrel App Store submission — ready-to-go pack

Everything needed for the PR to `getumbrel/umbrel-apps`. Nothing here touches
Umbrel's repos; it's staging. The official-store manifest tracks the same
upstream version line as the community store (`1.7.x`), per review feedback.

**PR:** https://github.com/getumbrel/umbrel-apps/pull/5758 (open). Review
history: auth boundary, mount split, secret isolation, digest pinning (`1.6.47`);
proxy-peer gate so only the app's gateway can reach the web server (`1.6.47`);
`DAC_OVERRIDE` + `wg` mounting only `data/wg/` (`1.6.49`); dropping `SYS_MODULE`
(`1.6.50`). **This update (`1.7.0`) adds umbrelOS 2.0 compatibility** while
staying compatible with umbrelOS 1.x: the peer gate now also trusts the host
gateway IP (in umbrelOS 2.x umbreld runs the app gateway in-process on the
host; the old `app_proxy` container no longer exists) — on 1.x only for the
widget fetch, the UI/API keep requiring `app_proxy` (sticky detection: has
`app_proxy` resolved since boot). Adds an optional
`three-stats` home-screen widget backed by an unauthenticated, secret-free
`/api/widget` endpoint (`1.7.1` fixes its response: umbreld requires a
`refresh` field in the body, without it the widget rendered dashes), and
`backupIgnore` for regenerable data (LE certs + health snapshots). The submission manifest keeps `port: 3019` (unique in the
official store — 3016 is taken by ChainForensics there; the community-store
manifest stays on 3016 so existing users keep their URL; the container port
`APP_PORT` is 3016 in both). Aligns `exports.sh` with Umbrel's standard
`derive_entropy` helper.

## Status checklist

- [x] All user-facing text in English (UI, backend errors, VPS script, manifest, docs)
- [x] Multi-arch images (linux/amd64 + linux/arm64) built by CI
- [x] Web container hardened: `cap_drop: ALL` + `no-new-privileges`, and a
      proxy-peer gate: only the app's gateway (app_proxy container on 1.x,
      in-process host gateway on 2.x) can reach the web server; other
      containers get 403. On 1.x the host IP is admitted only for
      `GET /api/widget`. `GET /api/config` masks the preshared key as well as
      the private key
- [x] Secrets isolated: `APP_SEED` only reaches `web`; `caddy`/`wg` get a
      derived token from `exports.sh` (`derive_entropy`)
- [x] Mounts split: Caddy has no access to app data; `wg` mounts only
      `data/wg/` (the generated `wg0.conf`) read-only
- [x] Data persisted in volumes (`${APP_DATA_DIR}/...`), bind-mount dirs committed
      with `.gitkeep`
- [x] `app_proxy` uses framework defaults (Umbrel auth is enabled by default;
      `PROXY_AUTH_ADD` is not set)
- [x] Manifest (`umbrel-app.yml`) with `version: "1.7.1"`, `gallery: []`,
      `releaseNotes: ""`, `backupIgnore`, `submitter`, `submission`
- [x] `docker-compose.yml` with all images pinned by multi-arch digest
- [x] App tested end-to-end on real umbrelOS (tunnel + HTTPS working), plus
      umbrelOS 2.0 (beta) compatibility
- [x] **Icon**: 256×256 SVG (no rounded corners) — `icon-256.svg` (+ `icon-256.png`)
- [x] **Gallery**: 5 real screenshots at **1440×900 PNG** in `gallery/`
      (`01-dashboard`, `02-instructions`, `03-configuration`, `04-vps-setup`,
      `05-services`), embedded in the PR body.

## Image digests (verify against ghcr.io before re-pinning)

- `ghcr.io/miniweed/umbrel-tunnel-web:1.7.1` (rebuild + repin before pushing the PR update)
  `sha256:f8ee121a4f685359b78505ee5151330230205d2a58c8b2e33a60331ed82ef682`
- `ghcr.io/miniweed/umbrel-tunnel-wg:1.0.6` (unchanged)
  `sha256:22fbcbc01c31ec70c623ac670f195353c5fa37525ccecb18be86d9df2ed87469`
- `caddy:2.8-alpine` (unchanged)
  `sha256:af32e97399febea808609119bb21544d0265c58a02836576e32a2d082c262c17`

Note: `publish-images.yml` skips any image whose version tag already exists on
ghcr.io, so pinned tags can't drift; publishing new content requires a version
bump. Digest re-pin commits still use `[skip ci]` to save a no-op CI run.

## Files in the PR (`miniweed-tunnel/` in the fork)

- `umbrel-app.yml` → `./umbrel-app.yml` from this folder
- `docker-compose.yml` → `./docker-compose.yml` from this folder
- `exports.sh` → `../../exports.sh` (derives `TUNNEL_WG_TOKEN` via `derive_entropy`)
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

See `PR-BODY.md` (icon + the 5 gallery screenshots are embedded from this repo's
`main` branch via raw.githubusercontent.com URLs).
