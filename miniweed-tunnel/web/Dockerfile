FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache su-exec

COPY package.json ./
RUN npm install --production

COPY server.js ./
COPY api-spec ./api-spec
COPY lib ./lib
COPY public ./public
COPY docker-entrypoint.sh ./

RUN addgroup -S mw \
  && adduser -S -G mw mw \
  && mkdir -p /data \
  && chown -R mw:mw /app /data \
  && chmod 755 /app/docker-entrypoint.sh

EXPOSE 3000
ENTRYPOINT ["/app/docker-entrypoint.sh"]
