# Official Umbrel App Store submission — ready-to-go pack

Everything needed to open the PR to `getumbrel/umbrel-apps`. Nothing here touches
Umbrel's repos; it's staging. The community store keeps the 1.6.x line; the
official store starts at **1.0.0**.

## Status checklist

- [x] All user-facing text in English (UI, backend errors, VPS script, manifest, docs)
- [x] Multi-arch image (linux/amd64 + linux/arm64) built by CI
- [x] Web container hardened: `cap_drop: ALL` + `no-new-privileges` (runs as root
      so it can manage its own data dir across upgrades; wg/caddy need caps anyway)
- [x] Data persisted in volumes (`${APP_DATA_DIR}/data`)
- [x] `app_proxy` with Umbrel auth (`PROXY_AUTH_ADD: true`)
- [x] Manifest (`umbrel-app.yml`) with `version: "1.0.0"`, `gallery: []`, `releaseNotes: ""`, `submitter`
- [x] `docker-compose.yml` with all images pinned by digest
- [x] App tested end-to-end on real umbrelOS (tunnel + HTTPS working)
- [ ] **Icon**: 256×256 SVG, no rounded corners — `../../icon.svg` (host on svgur/imgur to attach)
- [ ] **Gallery**: 3–5 screenshots at **1440×900 PNG** (USER to provide) — or simple
      screenshots for the Umbrel team to design the final gallery
- [ ] Optional: push a `umbrel-tunnel-web:1.0.0` image tag for the digest (the digest
      itself already pins content; tag is cosmetic)

## Files to copy into the PR

Create the folder `miniweed-tunnel/` in a fork of `getumbrel/umbrel-apps` with:
- `umbrel-app.yml`  → use `./umbrel-app.yml` from this folder
- `docker-compose.yml` → use `./docker-compose.yml` from this folder

Web image digest (multi-arch, current :1.6.35 — re-verify before submitting):
`sha256:b8f749cf5a00709db6912f54ecf8905d3e93ad73115d0481507cd4773d36b96e`

## Steps to open the PR (when ready)

```bash
gh repo fork getumbrel/umbrel-apps --clone --remote
cd umbrel-apps
git checkout -b add-miniweed-tunnel
mkdir miniweed-tunnel
cp <this-folder>/umbrel-app.yml miniweed-tunnel/umbrel-app.yml
cp <this-folder>/docker-compose.yml miniweed-tunnel/docker-compose.yml
git add miniweed-tunnel && git commit -m "Add Tunnel app"
git push -u origin add-miniweed-tunnel
gh pr create --repo getumbrel/umbrel-apps --title "Add Tunnel" --body-file <this-folder>/PR-BODY.md
```

Then set `submission:` in `umbrel-app.yml` to the PR URL and push the update.

## PR body (paste into the PR / see PR-BODY.md)

Title: **Add Tunnel**

Summary: Tunnel exposes a user's Umbrel services to the internet through their own
VPS using WireGuard (E2E encryption) + Caddy (automatic HTTPS). A self-hosted
alternative to Cloudflare Tunnel that works behind CGNAT, with no router port
forwarding.

Security note for reviewers:
- Inbound traffic enters via the user's VPS and travels an encrypted WireGuard
  tunnel; the home router never opens a port.
- The `wg` container needs `NET_ADMIN` + `SYS_MODULE` for WireGuard (same as the
  official Tailscale app). The `web` container runs non-root with `cap_drop: ALL`.
- The VPS setup script is generated server-side, shows a SHA-256 to verify, hardens
  SSH with lockout protection, sets a restrictive firewall with rollback, and ships
  a kill-switch. Secrets are encrypted at rest; the audit log is a hash chain.
- The app has its own login (password + sessions) on top of Umbrel's app proxy.

Testing checklist (fill the platform you tested):
- [x] Installed and ran on umbrelOS (state persists across app restart)
- [ ] Raspberry Pi / [ ] Umbrel Home / [x] Linux VM / other: ____

Links:
- Source repo: https://github.com/miniweed/umbrel-app-store
- Icon: <svgur/imgur link to icon.svg>
- Gallery: <attach 3–5 screenshots>
