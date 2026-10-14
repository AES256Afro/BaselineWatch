# BaselineWatch runs straight from its TypeScript source on Node 24 (type stripping), so there
# is no build stage: install production dependencies, copy the source, run as the node user.
FROM node:24-alpine

ENV NODE_ENV=production \
    BW_HOST=0.0.0.0 \
    BW_PORT=8790 \
    BW_DATA_DIR=/data

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src ./src
COPY public ./public
RUN mkdir -p /data && chown node:node /data

USER node
VOLUME ["/data"]
EXPOSE 8790

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8790/health >/dev/null || exit 1

CMD ["node", "--disable-warning=ExperimentalWarning", "src/server.ts"]
