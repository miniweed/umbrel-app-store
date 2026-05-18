# Contributing

## Development

- Web API/UI code: `miniweed-tunnel/web`
- WireGuard helper API: `miniweed-tunnel/wg-client/wg-api.py`

## Local checks

```bash
cd miniweed-tunnel/web
npm ci
npm test
```

```bash
python3 -m py_compile miniweed-tunnel/wg-client/wg-api.py
```

## Pull Requests

- Keep changes focused and small when possible.
- Add/update tests with behavior changes.
- Include security impact notes when touching auth/crypto/networking.
