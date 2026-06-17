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

**Trust boundaries — what runs where.** There are two separate domains, and the
privileged action happens only on the user's own server, never on the Umbrel host:

- **On the Umbrel host (this app):** fully sandboxed. `web` runs with
  `cap_drop: ALL` + `no-new-privileges`; `caddy` adds only `NET_BIND_SERVICE`;
  only `wg` needs `NET_ADMIN` + `SYS_MODULE` for WireGuard — the same model as the
  official **Tailscale** app. No `privileged`, no host network, no host bind
  mounts. The app cannot affect the Umbrel host or other apps.
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
- Panel access is protected by Umbrel's authenticated app proxy
  (`PROXY_AUTH_ADD: true`). All images are pinned by multi-arch digest.

### Testing
- [x] Installed and ran on umbrelOS; state persists across app restart.
- [x] End-to-end verified: tunnel up, HTTPS service reachable.
- Platform tested: Linux VM / Umbrel.

### Links
- Source: https://github.com/miniweed/umbrel-app-store
- Icon (256×256 SVG, no rounded corners): https://raw.githubusercontent.com/miniweed/umbrel-app-store/main/miniweed-tunnel/docs/umbrel-submission/icon-256.svg

<img src="https://raw.githubusercontent.com/miniweed/umbrel-app-store/main/miniweed-tunnel/docs/umbrel-submission/icon-256.png" width="128" alt="Tunnel icon">

### Gallery (1440×900)
![Instructions](https://raw.githubusercontent.com/miniweed/umbrel-app-store/main/miniweed-tunnel/docs/umbrel-submission/gallery/01-instructions.png)
![Configuration](https://raw.githubusercontent.com/miniweed/umbrel-app-store/main/miniweed-tunnel/docs/umbrel-submission/gallery/02-configuration.png)
![VPS Setup](https://raw.githubusercontent.com/miniweed/umbrel-app-store/main/miniweed-tunnel/docs/umbrel-submission/gallery/03-vps-setup.png)
![Services](https://raw.githubusercontent.com/miniweed/umbrel-app-store/main/miniweed-tunnel/docs/umbrel-submission/gallery/04-services.png)
