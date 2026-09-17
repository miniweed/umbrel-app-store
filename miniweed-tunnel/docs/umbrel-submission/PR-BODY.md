## Tunnel

Tunnel exposes a user's Umbrel services to the internet through **their own VPS**
using **WireGuard** (end-to-end encryption) + **Caddy** (automatic HTTPS via
Let's Encrypt). A 100% self-hosted alternative to Cloudflare Tunnel that works
behind CGNAT, with no router port forwarding.

### How it works
Inbound traffic enters through the user's VPS (public IP) and travels an encrypted
WireGuard tunnel to the Umbrel, where Caddy terminates HTTPS and reverse-proxies
to the chosen internal service. The home router never opens a port.

### umbrelOS 2.0 compatibility

umbrelOS 2.0 serves the dashboard and apps over local HTTPS with a private,
self-signed CA (LAN/VPN only). Tunnel solves the remaining problem: **public
HTTPS on the user's own domain** with certificates trusted by every browser
(Let's Encrypt), reachable from anywhere on the internet. The two are
complementary; Tunnel is still needed for public exposure.

The app is compatible with both umbrelOS 1.x and 2.x:
- On **1.x**, the management UI is fronted by Umbrel's `app_proxy` container.
- On **2.x**, the `app_proxy` container no longer exists; umbreld runs the app
  gateway in-process on the host. The app's internal peer gate now also trusts
  the host gateway IP (read from the container's routing table), so the UI stays
  reachable under 2.x while remaining fail-closed to other containers.
- The gate tells the two apart by whether `app_proxy` ever resolved since boot
  (sticky). On 1.x the host IP is admitted **only** for umbreld's server-side
  `GET /api/widget`; the UI and API still require `app_proxy`, so the boundary
  reviewed in earlier rounds is unchanged there. The widget endpoint is the
  only new surface: unauthenticated by design (umbreld fetches it without
  cookies) and secret-free (status text, healthy-service count, public domain).

The manifest's `port` now correctly matches the `app_proxy` `APP_PORT` (3016),
and a new unauthenticated `/api/widget` endpoint powers an optional
`three-stats` home-screen widget (tunnel status, healthy services, public
domain) without exposing any secrets.

### Notes for reviewers (security)

**Trust boundaries — what runs where.** There are two separate domains, and the
privileged action happens only on the user's own server, never on the Umbrel host:

- **On the Umbrel host (this app):** fully sandboxed. `web` runs with
  `cap_drop: ALL` + `no-new-privileges`; `caddy` adds only `NET_BIND_SERVICE`;
  only `wg` needs `NET_ADMIN` for WireGuard (no `SYS_MODULE`). No `privileged`,
  no host network, no host bind mounts. The app cannot affect the Umbrel host
  or other apps.
- **On the user's own VPS:** the generated setup script is run by the user, as root,
  on a server *they* own and rent — the same trust model as any VPS setup guide.
  The app never touches that machine itself.

**The VPS script is fully auditable and safe by design.**
- Built **only from the distro's apt packages** — it never downloads and runs
  remote code (no `curl | sh`).
- **Deterministic** (same config → same script) and prints a **SHA-256** the user
  verifies before running.
- Installs a **restrictive firewall with automatic rollback** (a 120s kill-switch
  reverts the rules if the tunnel doesn't come up, preventing lockout) and
  **SSH hardening** that is skipped safely if no authorized key is present.

**App-side guardrails.**
- Anti-SSRF: reverse-proxy targets are validated; loopback, link-local, cloud
  metadata (169.254.169.254) and control ports (Docker, Caddy admin, the wg API)
  are blocked, with DNS-rebinding pinning. Only RFC1918 internal services can be
  exposed (the app's purpose).
- Secrets (WireGuard private/preshared keys, service targets) are **encrypted at
  rest** (AES-256-GCM, scrypt-derived key); the audit log is a tamper-evident
  SHA-256 hash chain.
- Panel access is protected by Umbrel's authenticated app gateway on both 1.x
  and 2.x; the internal peer gate (loopback + the app gateway) rejects other
  containers on the shared Docker network with 403. `GET /api/config` masks
  both the private key and the preshared key (the VPS script, generated
  server-side, is their only consumer). All images are pinned by multi-arch
  digest.
- Known platform limitation on 2.x: the in-process gateway shares the host's
  bridge IP with any app running `network_mode: host`, and umbreld adds no
  verifiable secret to proxied requests, so such an app is indistinguishable
  from the gateway at the TCP level. This is inherent to the 2.x gateway design
  and applies to every app; on 1.x the stricter `app_proxy`-only rule remains.

**Backups.** `backupIgnore` excludes only regenerable data (Let's Encrypt
certificates under `caddy/data/` and health snapshots). Tunnel configuration and
WireGuard keys are always backed up, and the app regenerates its proxy config
from saved settings on startup, so a restore never leaves the proxy waiting on
a missing Caddyfile.

### Testing
- [x] Installed and ran on umbrelOS; state persists across app restart.
- [x] End-to-end verified: tunnel up, HTTPS service reachable.
- [x] umbrelOS 2.0 (beta) compatibility verified: UI reachable via the
      in-process gateway, widget endpoint returns without auth.
- [ ] Both architectures (amd64 + arm64) — see notes.
- Platform tested: Linux VM / Umbrel.

### Links
- Source: https://github.com/miniweed/umbrel-app-store
- Icon (256×256 SVG, no rounded corners): https://raw.githubusercontent.com/miniweed/umbrel-app-store/main/miniweed-tunnel/docs/umbrel-submission/icon-256.svg

<img src="https://raw.githubusercontent.com/miniweed/umbrel-app-store/main/miniweed-tunnel/docs/umbrel-submission/icon-256.png" width="128" alt="Tunnel icon">

### Gallery (1440×900)
![Dashboard](https://raw.githubusercontent.com/miniweed/umbrel-app-store/main/miniweed-tunnel/docs/umbrel-submission/gallery/01-dashboard.png)
![Instructions](https://raw.githubusercontent.com/miniweed/umbrel-app-store/main/miniweed-tunnel/docs/umbrel-submission/gallery/02-instructions.png)
![Configuration](https://raw.githubusercontent.com/miniweed/umbrel-app-store/main/miniweed-tunnel/docs/umbrel-submission/gallery/03-configuration.png)
![VPS Setup](https://raw.githubusercontent.com/miniweed/umbrel-app-store/main/miniweed-tunnel/docs/umbrel-submission/gallery/04-vps-setup.png)
![Services](https://raw.githubusercontent.com/miniweed/umbrel-app-store/main/miniweed-tunnel/docs/umbrel-submission/gallery/05-services.png)
