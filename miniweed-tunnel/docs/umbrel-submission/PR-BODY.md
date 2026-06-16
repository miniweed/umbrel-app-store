## Tunnel

Tunnel exposes a user's Umbrel services to the internet through **their own VPS**
using **WireGuard** (end-to-end encryption) + **Caddy** (automatic HTTPS via
Let's Encrypt). A 100% self-hosted alternative to Cloudflare Tunnel that works
behind CGNAT, with no router port forwarding.

### How it works
Inbound traffic enters through the user's VPS (public IP) and travels an encrypted
WireGuard tunnel to the Umbrel, where Caddy terminates HTTPS and reverse-proxies
to the chosen internal service. The home router never opens a port.

### Notes for reviewers (security)
- The `wg` container needs `NET_ADMIN` + `SYS_MODULE` for WireGuard (same as the
  official Tailscale app). The `web` and `caddy` containers use `cap_drop: ALL`
  and `no-new-privileges`.
- The VPS setup script is generated server-side, prints a **SHA-256** to verify
  before running, hardens SSH with lockout protection, configures a restrictive
  firewall with a rollback.
- Secrets (WireGuard keys) are **encrypted at rest**; the audit log is a
  tamper-evident hash chain. Access to the panel is protected by Umbrel's
  authenticated app proxy (`PROXY_AUTH_ADD: true`).
- All images are pinned by multi-arch digest.

### Testing
- [x] Installed and ran on umbrelOS; state persists across app restart.
- [x] End-to-end verified: tunnel up, HTTPS service reachable.
- Platform tested: Linux VM / Umbrel.

### Links
- Source: https://github.com/miniweed/umbrel-app-store
- Icon (256×256 SVG): <svgur/imgur link>
- Gallery: attached (3–5 screenshots, 1440×900)
