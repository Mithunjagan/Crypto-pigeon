# Relay-only production image.  The daemon's libsignal/SQLCipher native
# dependencies are deliberately excluded from the relay dependency graph.
FROM node:22-bookworm-slim AS build

WORKDIR /app

COPY package.json package-lock.json .npmrc ./
COPY packages/protocol/package.json packages/protocol/package.json
COPY packages/shared-types/package.json packages/shared-types/package.json
COPY apps/relay-server/package.json apps/relay-server/package.json

RUN npm ci --include=dev --ignore-scripts \
    --workspace=@crypto-pigeon/protocol \
    --workspace=@crypto-pigeon/shared-types \
    --workspace=@crypto-pigeon/relay-server

COPY packages/protocol packages/protocol
COPY packages/shared-types packages/shared-types
COPY apps/relay-server apps/relay-server


RUN npm run build --workspace=@crypto-pigeon/protocol \
 && npm run build --workspace=@crypto-pigeon/shared-types \
 && npm run build --workspace=@crypto-pigeon/relay-server

FROM node:22-bookworm-slim AS runtime

WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json .npmrc ./
COPY packages/protocol/package.json packages/protocol/package.json
COPY packages/shared-types/package.json packages/shared-types/package.json
COPY apps/relay-server/package.json apps/relay-server/package.json

RUN npm ci --omit=dev --ignore-scripts \
    --workspace=@crypto-pigeon/protocol \
    --workspace=@crypto-pigeon/shared-types \
    --workspace=@crypto-pigeon/relay-server

COPY --from=build /app/packages/protocol/dist packages/protocol/dist
COPY --from=build /app/packages/shared-types/dist packages/shared-types/dist
COPY --from=build /app/apps/relay-server/dist apps/relay-server/dist

EXPOSE 8443

CMD ["node", "apps/relay-server/dist/server.js"]
