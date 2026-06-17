# Security Policy

## Trust boundaries / architecture

Tunnel spans two separate domains. The privileged action happens only on the
user's own server, never on the Umbrel host.

**Umbrel host (this app).** Fully sandboxed:

- `web` — `cap_drop: ALL`, `no-new-privileges`. Runs the API/UI only.
- `caddy` — `cap_drop: ALL` + `NET_BIND_SERVICE` only (to bind 80/443),
  `no-new-privileges`; shares the `wg` network namespace.
- `wg` — `cap_drop: ALL` + `NET_ADMIN` + `SYS_MODULE` (required for WireGuard,
  the same model as the official Tailscale app).

No `privileged` containers, no host networking, no host bind mounts. The app
cannot affect the Umbrel host or other installed apps.

**User's VPS.** The generated setup script is run by the user, as root, on a
server they own and rent — the same trust model as any VPS setup guide. The app
never touches that machine itself. The script:

- is built **only from the distro's apt packages** (no remote code / no `curl | sh`),
- is **deterministic** and prints a **SHA-256** to verify before running,
- installs a restrictive firewall with a **120s automatic rollback** (anti-lockout)
  and SSH hardening that is skipped safely if no authorized key exists.

## Defenses

- **WireGuard** end-to-end encryption between Umbrel and the VPS.
- **Anti-SSRF** on reverse-proxy targets: loopback, link-local, cloud metadata and
  control ports are blocked, with DNS-rebinding pinning; only RFC1918 services can
  be exposed.
- **Encryption at rest** for secrets and service targets (AES-256-GCM, scrypt KDF).
- **Tamper-evident audit log** (SHA-256 hash chain).
- Panel access protected by Umbrel's authenticated app proxy.

## Threat Model (current)

- In scope:
  - MITM between user and VPS.
  - Exposure of app data at rest.
  - Unauthorized API/UI access.
  - SSRF / abuse of the reverse-proxy target configuration.
- Out of scope:
  - Root compromise of the host Umbrel OS.
  - Security of the user's VPS beyond what the setup script configures.
  - Physical compromise of the machine.

## Reporting a Vulnerability

Open a private security report if possible, or create an issue without exploit details.

- Contact: maintainers via GitHub issues/discussions.
- Include:
  - affected version/tag
  - reproduction steps
  - impact assessment

## Disclosure Process

- We acknowledge within 7 days.
- We aim to triage/fix critical issues first.
- Coordinated disclosure window target: 90 days.
