# Miniweed Tunnel - Session Handoff (Compacted)

Last updated: 2026-05-19

## Current state

- Branch: `main`
- Working tree at handoff: clean
- Latest pushed commit: `83fd442`
- Latest released app version in store: `1.6.0`

## What was completed in this chat

### Commits produced in this phase

1. `7ed26a4` - Harden API contract typing and CI drift checks
2. `a8f1dfd` - Extend failover coverage for manual and recovery paths
3. `b6847e0` - Harden CrowdSec setup verification and recovery guidance
4. `972b644` - Release miniweed-tunnel 1.5.5 with hardening updates
5. `5c9d4c3` - Release miniweed-tunnel 1.5.6 with config validation hotfix
6. `8c8b407` - Release miniweed-tunnel 1.5.7 with required-field UI highlights
7. `9ac006c` - Harden auth, failover policy, and SPA CSP behavior
8. `83fd442` - Release miniweed-tunnel 1.6.0 with security hardening

### Security and architecture hardening delivered

- Added formal Zod validation on:
  - `POST /api/auth/password`
  - `POST /api/auth/login`
- Extended config at-rest encryption to include auth-sensitive runtime data:
  - `auth.passwordHash`
  - `auth.sessions`
- Added backward-compatible decrypt/normalize flow so legacy plaintext config still loads.
- Introduced configurable failover policy via config/API:
  - `failoverPolicy.activeFailuresRequired`
  - `failoverPolicy.candidateSuccessesRequired`
  - `failoverPolicy.cooldownMs`
  - with sane defaults and validation bounds.
- CSP tightened by route:
  - strict CSP for SPA routes (`/`, `/app`, `/app/*`) without `unsafe-inline`
  - compatibility CSP retained for `/legacy` routes temporarily.

### Product and UX improvements delivered

- SPA config tab now highlights required fields for script generation:
  - Umbrel public key
  - VPS public IP
- Setup validation hotfix shipped to avoid false `validation` failures during initial setup with optional empty fields.

### P4-20 + P4-21 hardening delivered

- Added/expanded failover edge-case tests including manual/auto interplay and recovery paths.
- CrowdSec setup script hardening:
  - safer installer invocation
  - post-install health checks and warnings
  - improved smoke + recovery docs.

### Contract and CI status

- OpenAPI runtime snapshot and generated TS types are in place and updated.
- CI drift guard (`api:contract:drift`) is active and enforces contract file sync.
- CI now also enforces compose wiring guard to prevent regressions where `web` points to stale pinned image instead of local build context (`tools/check-compose-web-build.js`).

## Validation performed in this phase

- `npm test -- --runInBand` in `miniweed-tunnel/web` -> passing (27 tests).
- `npm run ui:build` in `miniweed-tunnel/web` -> passing.
- `npm run api:contract` in `miniweed-tunnel/web` -> passing.

## Feedback checklist status (external review)

1. Zod on auth password/login: **DONE**.
2. CSP `unsafe-inline`: **PARTIAL DONE** (removed for SPA, kept for legacy compatibility).
3. Session storage plaintext in config: **DONE** (sessions and passwordHash sealed at rest).
4. Failover thresholds hardcoded: **DONE** (policy configurable via config/API).
5. MX validation for email: **DONE** (DNS MX lookup is implemented and enforced on config save).

## Plan status vs `MEJORAS_SIN_DEPLOY.md`

### Done enough for now (without provider API)

- P0-1, P0-2, P0-3, P0-3-bis
- P1-4, P1-5, P1-6, P1-7, P1-8
- P2-9, P2-10, P2-11, P2-12
- P3-13, P3-14, P3-15
- P3-16 mostly implemented (SPA default + legacy fallback)
- P3-17 strongly advanced (contract generation, typed client usage, CI drift guard)
- P4-18, P4-19
- P4-20 strongly implemented + additional edge-case coverage
- P4-21 strongly advanced without provider API

### Still pending / next high-value work

1. P3-16 parity final pass:
   - remaining minor UX/messaging parity vs legacy
   - decide and execute legacy route deprecation/removal timeline
2. P3-17 deep adoption:
   - deeper end-to-end use of generated types across SPA state/UI boundaries
3. CSP finalization:
   - remove `unsafe-inline` from legacy path (or retire legacy route fully)
4. Test/runtime hygiene:
   - finish investigation of intermittent Jest open-handle warning (if still seen in some environments)
5. Optional ops hardening:
   - expose failover policy controls in SPA UI (currently backend/API-ready)

## Suggested resume point

When resuming, start from:

- `miniweed-tunnel/NEXT_SESSION.md`
- `MEJORAS_SIN_DEPLOY.md`

Suggested immediate focus order:

1. Verify `1.6.0` behavior in Umbrel install/update flow and fresh setup flow.
2. Final P3-16 parity sweep and legacy route strategy.
3. CSP full closure (legacy removal or nonce/hash migration).
