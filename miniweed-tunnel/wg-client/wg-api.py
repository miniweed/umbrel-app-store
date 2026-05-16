#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import subprocess
import json
import time

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

    def do_GET(self):
        if self.path == '/keygen':
            priv = subprocess.check_output(['wg', 'genkey']).decode().strip()
            pub = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).decode().strip()
            self.send_json(200, {'privateKey': priv, 'publicKey': pub})

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
            except subprocess.CalledProcessError as e:
                raw = e.output.decode()
                connected = False
                peer_count = 0
                handshaked_peers = 0
                last_handshake_age_sec = None
            except Exception as e:
                raw = str(e)
                connected = False
                peer_count = 0
                handshaked_peers = 0
                last_handshake_age_sec = None
            self.send_json(200, {
                'connected': connected,
                'raw': raw,
                'peerCount': peer_count,
                'handshakedPeers': handshaked_peers,
                'lastHandshakeAgeSec': last_handshake_age_sec,
            })

        else:
            self.send_json(404, {'error': 'not found'})


if __name__ == '__main__':
    print('[wg-api] Listening on :8080', flush=True)
    HTTPServer(('0.0.0.0', 8080), WGHandler).serve_forever()
