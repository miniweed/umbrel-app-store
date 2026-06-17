# miniweed — Umbrel Community App Store

A community [Umbrel](https://umbrel.com) app store. It currently ships one app:

## Tunnel

**Expose your Umbrel services to the internet through your own VPS — no router port forwarding, works behind CGNAT.**

A 100% self-hosted alternative to Cloudflare Tunnel. Inbound traffic enters through
a small VPS you control and travels an encrypted **WireGuard** tunnel to your
Umbrel; **Caddy** terminates HTTPS with automatic Let's Encrypt certificates.

- 🔒 End-to-end encryption (WireGuard) — your home router never opens a port
- 🌐 Automatic HTTPS via Caddy + Let's Encrypt
- 🛠️ One-command VPS setup script (firewall with rollback, SSH hardening, optional CrowdSec)
- ✅ Every generated script shows a SHA-256 you can verify before running it
- 🔑 Panel protected by Umbrel's authenticated app proxy

See [`miniweed-tunnel/README.md`](miniweed-tunnel/README.md) for the full setup
guide (renting a VPS, DNS records, hardening).

## Add this store to Umbrel

1. Open the **App Store** in your umbrelOS.
2. Click the **⋯** menu (top right) → **Community App Stores**.
3. Add the store URL:

   ```
   https://github.com/miniweed/umbrel-app-store
   ```

4. Install **Tunnel** from the store.

> Community app stores are installed at your own risk. Review the source before installing.

## Repository layout

| Path | Purpose |
| --- | --- |
| `umbrel-app-store.yml` | Community store manifest |
| `miniweed-tunnel/` | The Tunnel app (manifest, compose, web UI, WireGuard client, VPS scripts) |
| `miniweed-tunnel/web/` | Node/Express backend + Preact UI |
| `miniweed-tunnel/docs/` | Documentation and Umbrel submission pack |

## License

[MIT](LICENSE)
