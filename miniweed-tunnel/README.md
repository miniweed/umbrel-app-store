# Tunnel

Expose your Umbrel services to the internet through **your own VPS** — no router
port-forwarding, works behind CGNAT. A 100% self-hosted alternative to Cloudflare
Tunnel, built on **WireGuard** (end-to-end encryption) and **Caddy** (automatic
HTTPS with Let's Encrypt).

## How it works

```
            HTTPS (443)                WireGuard tunnel
 Internet ───────────────►  VPS  ◄════════════════════►  Umbrel
 user                    (public IP)                    (Caddy + your apps)
                          Caddy/iptables                reverse_proxy → app
```

1. The app generates a WireGuard key pair on your Umbrel.
2. You run a setup script (as root) on a cheap VPS you control. The script
   installs WireGuard + a firewall, and forwards public ports 80/443 over the
   tunnel to your Umbrel.
3. Caddy on the Umbrel side terminates HTTPS and reverse-proxies each request to
   the internal service you choose.

Your Umbrel never opens a port on your home router; all inbound traffic enters
through the VPS and travels the encrypted tunnel.

## Requirements

- An Umbrel running umbrelOS.
- A small VPS (Debian/Ubuntu) with a public IP, and TCP **80/443** + UDP **51820**
  open in your provider's firewall panel.
- A domain (and the ability to point a DNS `A` record at the VPS IP).

## Quick start

1. **Configuration** → *Generate keys*, then enter the VPS public IP and your
   Let's Encrypt email.
2. **VPS Setup** → copy/download the script and run it as root on the VPS.
   Verify the printed SHA-256.
3. Paste the VPS public key (printed by the script) back into **Configuration**
   and save.
4. **Services** → add a service (subdomain + internal URL) and save.
5. Point your subdomain's DNS `A` record at the VPS IP.

Open `https://<your-subdomain>` — it should load your internal service over HTTPS.

## Features

- **One-command VPS setup** with a generated, SHA-256-verifiable script.
- **Automatic HTTPS** for each exposed service via Caddy + Let's Encrypt.
- **Per-service health checks** shown in the dashboard.
- **Secure key rotation** — rotate WireGuard keys without breaking the tunnel.
- **Emergency kill-switch** — one script to stop the tunnel and block the port.
- **Optional CrowdSec** hardening on the VPS.

Access to the panel is protected by your Umbrel account (the app runs behind
Umbrel's authenticated app proxy).

## Security

- WireGuard end-to-end encryption; the VPS only forwards encrypted traffic.
- Secrets (WireGuard private/preshared keys) are encrypted at rest on the Umbrel
  side; the audit log is a tamper-evident hash chain.
- The generated VPS script hardens SSH (with lockout protection), sets up a
  restrictive firewall with a rollback, and prints a SHA-256 you can verify
  before running it.
- Anti-SSRF checks on health probes and strict input validation on the API.

See [SECURITY.md](SECURITY.md) to report issues.

## Repository layout

- `web/` — Node/Express API + Preact UI (the app image).
- `wg-client/` — WireGuard client container + minimal control API.
- `vps-setup/` — helper scripts and runbooks for the VPS side.
- `miniweed-tunnel/` packaging (`umbrel-app.yml`, `docker-compose.yml`) for the
  Umbrel community app store.

## Development

```bash
cd web
npm test                 # backend tests
npm --prefix ui run dev  # UI dev server (proxies /api to localhost:3016)
DATA_DIR=/tmp/mw-dev PORT=3016 node server.js   # backend
```

## License

MIT. Developed with assistance from Claude (Anthropic).
