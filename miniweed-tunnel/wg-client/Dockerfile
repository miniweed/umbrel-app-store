FROM alpine:3.19

LABEL org.opencontainers.image.source="https://github.com/miniweed/umbrel-app-store"
LABEL org.opencontainers.image.description="Umbrel Tunnel WireGuard client"
LABEL org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    ip6tables \
    iproute2 \
    bash \
    python3

COPY entrypoint.sh /entrypoint.sh
COPY wg-api.py /wg-api.py
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
