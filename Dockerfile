FROM node:22-slim

# openssl CLI — pkcs12.util.js spawns it for .pfx bundles (cert auth).
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

# logs/ must exist and be node-owned before USER node — winston's file
# transport throws EACCES otherwise and the process dies before app.listen().
RUN mkdir -p /app/logs && chown -R node:node /app

ENV NODE_ENV=production
EXPOSE 8080

USER node

# Migrations before the server, per the roleManagement pattern. A failed
# migration exits non-zero so the container never starts.
CMD ["sh", "-c", "node scripts/migrate.js && node server.js"]
