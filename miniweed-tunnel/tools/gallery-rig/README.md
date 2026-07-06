# Gallery screenshot rig

Reproduces the store gallery screenshots (1440×900 PNG) against the real app
running locally, with a simulated WireGuard side so the UI shows a connected,
fully configured state. Used for `docs/umbrel-submission/gallery/`.

## How it works

- `fake-wg-api.js` — stands in for the `wg` container API on `127.0.0.1:8080`:
  `/keygen` returns valid X25519 keys; `/status` reports connected iff the file
  `./wg-connected` exists (the shoot script creates it between phases).
- `shoot.js` — Playwright (Chromium, viewport 1440×900):
  - Phase A (fresh data dir, "No tunnel"): captures `02-configuration` with the
    required-field outlines.
  - Seeds the config via the API (keygen + POST /api/config) so no toasts appear,
    with two example services pointing at `LAN_IP` ports 8096/8123 — run real
    listeners there so the health pills come out green.
  - Phase B ("Connected"): captures `01-instructions`, `03-vps-setup` (script +
    SHA-256 visible) and `04-services`.

## Run

```bash
npm i playwright && npx playwright install chromium   # once, anywhere
export APP_SEED=$(printf 's%.0s' {1..64})
export LAN_IP=<your LAN IP>                            # non-loopback, reachable

node fake-wg-api.js &                                  # in this directory
python3 -m http.server 8096 --bind 0.0.0.0 &           # dummy service targets
python3 -m http.server 8123 --bind 0.0.0.0 &
rm -f wg-connected && rm -rf data && mkdir data
(cd ../../web && DATA_DIR=$PWD/../tools/gallery-rig/data PORT=3125 \
  WG_API_HOST=127.0.0.1 node server.js) &

node shoot.js                                          # writes out/*.png
```

Then copy `out/*.png` over `docs/umbrel-submission/gallery/` and commit with
`[skip ci]` alongside any digest pin. The PR body hotlinks these files from
`main`, so the PR gallery updates automatically.
