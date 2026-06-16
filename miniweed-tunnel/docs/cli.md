# CLI reference

The backend accepts `ssh-ed25519` (OpenSSH) or DER/SPKI base64 public keys for
command-line authentication, and exposes endpoints for key rotation, the remote
kill-switch and multi-VPS failover.

```bash
API_URL="http://umbrel.local:3016"
API_TOKEN="<api_token>"
```

## Public-key authentication

### 1) Register a public key

```bash
KEY_NAME="laptop-cli"
PUBKEY="$(cat ~/.ssh/id_ed25519.pub)"

curl -sS -X POST "$API_URL/api/auth/pubkeys" \
  -H "Content-Type: application/json" \
  -H "x-tunnel-api-token: $API_TOKEN" \
  -d "{\"name\":\"$KEY_NAME\",\"publicKey\":\"$PUBKEY\"}"
```

Save the returned `keyId`.

### 2) Request a challenge

```bash
KEY_ID="<keyId>"

CHALLENGE_JSON="$(curl -sS -X POST "$API_URL/api/auth/challenge" \
  -H "Content-Type: application/json" \
  -d "{\"keyId\":\"$KEY_ID\"}")"

CHALLENGE_ID="$(printf '%s' "$CHALLENGE_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["challengeId"])')"
NONCE_B64="$(printf '%s' "$CHALLENGE_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
```

### 3) Sign the challenge and verify

```bash
SIG_B64="$(NONCE_B64="$NONCE_B64" node -e '
const fs=require("fs"), crypto=require("crypto");
const nonce=Buffer.from(process.env.NONCE_B64,"base64");
const key=fs.readFileSync(process.env.PRIV_KEY_PATH||`${process.env.HOME}/.ssh/id_ed25519`,"utf8");
process.stdout.write(crypto.sign(null, nonce, key).toString("base64"));
')"

VERIFY_JSON="$(curl -sS -X POST "$API_URL/api/auth/verify" \
  -H "Content-Type: application/json" \
  -d "{\"challengeId\":\"$CHALLENGE_ID\",\"signature\":\"$SIG_B64\"}")"

SESSION_TOKEN="$(printf '%s' "$VERIFY_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sessionToken"])')"

curl -sS "$API_URL/api/config" -H "Cookie: mw_session=$SESSION_TOKEN"
```

Note: the backend expects a raw Ed25519 signature (base64) over the decoded
`nonce` bytes.

## Key rotation (assisted)

```bash
# 1) Prepare a rotation plan + VPS rollback script
curl -sS -X POST "$API_URL/api/rotate/prepare" \
  -H "Content-Type: application/json" -H "x-tunnel-api-token: $API_TOKEN"

# 2) Run the returned script on the VPS, then confirm:
curl -sS -X POST "$API_URL/api/rotate/confirm" \
  -H "Content-Type: application/json" -H "x-tunnel-api-token: $API_TOKEN" \
  -d '{"planId":"<planId>","apply":true}'
```

## Remote kill-switch

```bash
curl -sS "$API_URL/api/kill-switch/script?format=plain" \
  -H "x-tunnel-api-token: $API_TOKEN" -o miniweed-killswitch.sh
chmod +x miniweed-killswitch.sh
# On the VPS, optionally parameterized:
WG_PORT=51820 STATUS_FILE=/tmp/miniweed.status sudo bash miniweed-killswitch.sh
```

It stops `wg-quick@wg0` and blocks UDP/51820. Optional systemd install:

```bash
sudo install -m 700 miniweed-killswitch.sh /mnt/killswitch.sh
sudo bash miniweed-tunnel/vps-setup/killswitch-service.sh
sudo systemctl start miniweed-killswitch.service
```

## Multi-VPS / failover

```bash
# Target status
curl -sS "$API_URL/api/vps/targets" -H "x-tunnel-api-token: $API_TOKEN"

# Manual failover
curl -sS -X POST "$API_URL/api/vps/failover" \
  -H "Content-Type: application/json" -H "x-tunnel-api-token: $API_TOKEN" \
  -d '{"targetId":"vps-b"}'

# Automatic failover (no targetId)
curl -sS -X POST "$API_URL/api/vps/failover" \
  -H "Content-Type: application/json" -H "x-tunnel-api-token: $API_TOKEN" -d '{}'

# Per-VPS setup script (optionally with CrowdSec)
curl -sS "$API_URL/api/vps-setup-script?vpsId=vps-b&withCrowdsec=1" \
  -H "x-tunnel-api-token: $API_TOKEN"
```

## CrowdSec (optional)

CrowdSec support is fully script-based on the VPS (no cloud provider API). Enable
it with `withCrowdsec=1` when requesting the setup script. See
[`../vps-setup/crowdsec-recovery.md`](../vps-setup/crowdsec-recovery.md) for the
lockout recovery runbook and `vps-setup/crowdsec-smoke.sh` for a smoke check.
