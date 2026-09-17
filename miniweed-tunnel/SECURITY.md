# Security Policy

## Trust boundaries / architecture

Tunnel spans two separate domains. The privileged action happens only on the
user's own server, never on the Umbrel host.

**Umbrel host (this app).** Fully sandboxed:

- `web` — `cap_drop: ALL`, `no-new-privileges`. Runs the API/UI only.
- `caddy` — `cap_drop: ALL` + `NET_BIND_SERVICE` only (to bind 80/443),
  `no-new-privileges`; shares the `wg` network namespace.
- `wg` — `cap_drop: ALL` + `NET_ADMIN` (required for WireGuard).

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
- Panel access protected by Umbrel's authenticated app gateway (`app_proxy` on
  umbrelOS 1.x; in-process gateway on umbrelOS 2.x — both are supported).
- Internal peer gate: the web server answers only loopback and the app gateway;
  every other container on the shared Docker network gets 403 before touching
  any route. On 1.x the host IP is admitted solely for umbreld's `GET /api/widget`
  (secret-free); the UI and API still require `app_proxy`. Detection is sticky
  (has `app_proxy` resolved since boot), so an `app_proxy` restart or a DNS hiccup
  never downgrades the gate.
- The API never returns the WireGuard private key or the preshared key; both are
  masked and only consumed server-side when generating the VPS script.

## Threat Model (current)

- In scope:
  - MITM between user and VPS.
  - Exposure of app data at rest.
  - Unauthorized API/UI access.
  - SSRF / abuse of the reverse-proxy target configuration.
- Out of scope:
  - Root compromise of the host Umbrel OS.
  - On umbrelOS 2.x, apps running with `network_mode: host`: they share the
    host's bridge IP with umbreld's in-process gateway and umbreld adds no
    verifiable secret to proxied requests, so the app cannot tell them apart
    at the TCP level. This is a platform property that affects every 2.x app;
    on 1.x the stricter `app_proxy`-only rule applies.
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
