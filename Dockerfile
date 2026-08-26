FROM node:22-slim AS builder
WORKDIR /app
# Build tools needed by better-sqlite3 if no prebuilt binary matches the runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json* ./
RUN npm install
COPY tsconfig.json ./
COPY src/ src/
RUN npx tsc

FROM node:22-slim
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./
RUN mkdir -p /app/data

EXPOSE 8443
# Config path defaults to /app/data/config.yaml (persistent volume).
# If missing on first start, the container auto-generates it from
# CCG_REFRESH_TOKEN env or a mounted credentials.json. Override path with
# CCG_CONFIG_PATH env or by passing an arg to node.
CMD ["node", "dist/index.js"]
