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

## Setup guide

### 1. Rent a VPS

Get a small VPS (Debian/Ubuntu) from any provider (Hetzner, OVH, DigitalOcean,
Vultr…). The cheapest tier is enough. Note its **public IP** and, in the
provider's firewall/security-group panel, **open** `TCP 80`, `TCP 443` and
`UDP 51820`.

### 2. Point your domain's DNS at the VPS

Create these records at your DNS provider, all pointing to the **VPS public IP**:

| Type | Name | Value |
|------|------|-------|
| A | `@` | VPS IP (apex / root domain) |
| A | `www` | VPS IP |
| A | `*` | VPS IP (**wildcard** — covers every `service.yourdomain.com`) |

The **wildcard `*`** is important: each exposed service uses a subdomain, so the
wildcard makes all of them resolve to the VPS without adding a record per service.
(If your DNS host doesn't allow a wildcard `A`, add one `A` record per subdomain
you expose.)

### 3. Configure the app

1. **Configuration** → *Generate keys*, then enter the VPS public IP and your
   Let's Encrypt email.
2. **VPS Setup** → copy/download the script and run it as **root** on the VPS.
   Verify the printed **SHA-256**. The script sets up the tunnel and hardens the
   server (firewall + rollback, SSH hardening). It is built only from your
   distro's packages — it never downloads and runs remote code.
3. Paste the VPS public key (printed by the script) back into **Configuration**
   and save.
4. **Services** → add a service (subdomain + internal URL) and save.

Open `https://<subdomain>.yourdomain.com` — it should load your internal service
over HTTPS (the certificate is issued automatically on first request).

## Features

- **One-command VPS setup** with a generated, SHA-256-verifiable script.
- **Automatic HTTPS** for each exposed service via Caddy + Let's Encrypt.
- **Per-service health checks** shown in the dashboard.
- **In-app instructions** tab guiding you through the whole setup.

Access to the panel is protected by your Umbrel account (the app runs behind
Umbrel's authenticated app proxy).

## Security

- **Trust boundaries:** on Umbrel the app is sandboxed (`web` drops all
  capabilities; only the `wg` container needs `NET_ADMIN`/`SYS_MODULE` for
  WireGuard, like the official Tailscale app). The root setup script runs only on
  *your own VPS*, never on the Umbrel host.
- WireGuard end-to-end encryption; the VPS only forwards encrypted traffic.
- The generated VPS script is built **only from your distro's packages** (no remote
  code), is deterministic, prints a SHA-256 you can verify, hardens SSH (with
  lockout protection) and sets up a restrictive firewall with automatic rollback.
- Secrets (WireGuard keys, service targets) are encrypted at rest (AES-256-GCM);
  the audit log is a tamper-evident hash chain.
- Anti-SSRF checks on reverse-proxy targets and strict input validation on the API.

See [SECURITY.md](SECURITY.md) for the full trust model and how to report issues.

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
