#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import subprocess
import json
import time
import base64
import hashlib
import os
import hmac

EXPECTED_TOKEN = os.environ.get('WG_API_TOKEN', '').strip()

class WGHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def is_authorized(self):
        if not EXPECTED_TOKEN:
            return False
        provided = self.headers.get('x-wg-api-token', '') or ''
        # Compara como bytes: compare_digest lanza TypeError con str no-ASCII.
        try:
            return hmac.compare_digest(provided.encode('utf-8'), EXPECTED_TOKEN.encode('utf-8'))
        except Exception:
            return False

    def do_GET(self):
        if not self.is_authorized():
            self.send_json(401, {'error': 'unauthorized'})
            return

        if self.path == '/keygen':
            priv = subprocess.check_output(['wg', 'genkey']).decode().strip()
            pub = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).decode().strip()
            psk = subprocess.check_output(['wg', 'genpsk']).decode().strip()
            self.send_json(200, {'privateKey': priv, 'publicKey': pub, 'presharedKey': psk})

        elif self.path == '/status':
            try:
                raw = subprocess.check_output(
                    ['wg', 'show', 'wg0'], stderr=subprocess.STDOUT
                ).decode()

                latest = subprocess.check_output(
                    ['wg', 'show', 'wg0', 'latest-handshakes'], stderr=subprocess.STDOUT
                ).decode().strip().splitlines()

                now = int(time.time())
                peer_count = 0
                handshaked_peers = 0
                last_handshake_age_sec = None

                for line in latest:
                    parts = line.split('\t')
                    if len(parts) != 2:
                        continue
                    peer_count += 1
                    try:
                        ts = int(parts[1])
                    except ValueError:
                        continue
                    if ts > 0:
                        handshaked_peers += 1
                        age = max(0, now - ts)
                        if last_handshake_age_sec is None or age < last_handshake_age_sec:
                            last_handshake_age_sec = age

                connected = handshaked_peers > 0
                pub = subprocess.check_output(['wg', 'show', 'wg0', 'public-key'], stderr=subprocess.STDOUT).decode().strip()
            except subprocess.CalledProcessError as e:
                raw = e.output.decode()
                connected = False
                peer_count = 0
                handshaked_peers = 0
                last_handshake_age_sec = None
                pub = ''
            except Exception as e:
                raw = str(e)
                connected = False
                peer_count = 0
                handshaked_peers = 0
                last_handshake_age_sec = None
                pub = ''

            fingerprint = ''
            if pub:
                try:
                    key_bytes = base64.b64decode(pub)
                    digest = hashlib.sha256(key_bytes).digest()[:16]
                    fingerprint = ':'.join(f'{b:02x}' for b in digest)
                except Exception:
                    fingerprint = ''
            self.send_json(200, {
                'connected': connected,
                'raw': raw,
                'peerCount': peer_count,
                'handshakedPeers': handshaked_peers,
                'lastHandshakeAgeSec': last_handshake_age_sec,
                'publicKey': pub,
                'publicKeyFingerprint': fingerprint,
            })

        else:
            self.send_json(404, {'error': 'not found'})


if __name__ == '__main__':
    if not EXPECTED_TOKEN:
        raise RuntimeError('WG_API_TOKEN is required')
    print('[wg-api] Listening on :8080', flush=True)
    HTTPServer(('0.0.0.0', 8080), WGHandler).serve_forever()
