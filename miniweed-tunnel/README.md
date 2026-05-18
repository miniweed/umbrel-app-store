# Tunnel

Tunnel expone servicios internos de Umbrel mediante un VPS propio usando WireGuard + Caddy.

## Flujo básico

1. Genera claves WireGuard desde la UI.
2. Configura IP del VPS.
3. Descarga y ejecuta el script de setup en el VPS.
4. Pega la clave pública del VPS en la UI y guarda.

## Auth por clave pública (CLI)

El backend acepta claves `ssh-ed25519` (OpenSSH) o DER/SPKI base64.

### 1) Registrar clave pública

```bash
API_URL="http://umbrel.local:3016"
API_TOKEN="<token_api>"
KEY_NAME="laptop-cli"
PUBKEY="$(cat ~/.ssh/id_ed25519.pub)"

curl -sS -X POST "$API_URL/api/auth/pubkeys" \
  -H "Content-Type: application/json" \
  -H "x-tunnel-api-token: $API_TOKEN" \
  -d "{\"name\":\"$KEY_NAME\",\"publicKey\":\"$PUBKEY\"}"
```

Guarda el `keyId` de la respuesta.

### 2) Pedir challenge

```bash
KEY_ID="<keyId>"

CHALLENGE_JSON="$(curl -sS -X POST "$API_URL/api/auth/challenge" \
  -H "Content-Type: application/json" \
  -d "{\"keyId\":\"$KEY_ID\"}")"

CHALLENGE_ID="$(printf '%s' "$CHALLENGE_JSON" | python3 - <<'PY'
import json,sys
data=json.loads(sys.stdin.read())
print(data['challengeId'])
PY
)"

NONCE_B64="$(printf '%s' "$CHALLENGE_JSON" | python3 - <<'PY'
import json,sys
data=json.loads(sys.stdin.read())
print(data['nonce'])
PY
)"
```

### 3) Firmar challenge y verificar

```bash
SIG_B64="$(NONCE_B64="$NONCE_B64" node -e '
const fs=require("fs");
const crypto=require("crypto");
const nonce=Buffer.from(process.env.NONCE_B64,"base64");
const key=fs.readFileSync(process.env.PRIV_KEY_PATH||`${process.env.HOME}/.ssh/id_ed25519`,"utf8");
const sig=crypto.sign(null, nonce, key);
process.stdout.write(sig.toString("base64"));
')"

VERIFY_JSON="$(curl -sS -X POST "$API_URL/api/auth/verify" \
  -H "Content-Type: application/json" \
  -d "{\"challengeId\":\"$CHALLENGE_ID\",\"signature\":\"$SIG_B64\"}")"

SESSION_TOKEN="$(printf '%s' "$VERIFY_JSON" | python3 - <<'PY'
import json,sys
print(json.loads(sys.stdin.read())['sessionToken'])
PY
)"

curl -sS "$API_URL/api/config" -H "Cookie: mw_session=$SESSION_TOKEN"
```

Nota: el backend espera firma Ed25519 "raw" en base64 sobre los bytes del `nonce` (después de decodificar base64).
