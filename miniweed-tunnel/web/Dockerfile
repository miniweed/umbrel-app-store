FROM node:20-alpine

LABEL org.opencontainers.image.source="https://github.com/miniweed/umbrel-app-store"
LABEL org.opencontainers.image.description="Umbrel Tunnel web UI and API"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY package.json ./
RUN npm install --production

COPY server.js ./
COPY api-spec ./api-spec
COPY config ./config
COPY lib ./lib
COPY public ./public
COPY docker-entrypoint.sh ./

RUN mkdir -p /data \
  && chown -R node:node /app /data \
  && chmod 755 /app/docker-entrypoint.sh

# Run as non-root (UID 1000 matches Umbrel's data-dir owner).
USER node

EXPOSE 3000
ENTRYPOINT ["/app/docker-entrypoint.sh"]
