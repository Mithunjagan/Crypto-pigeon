# Build from repository root: docker build -f apps/relay-server/Dockerfile .
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
COPY packages/protocol/package.json packages/protocol/package.json
COPY packages/shared-types/package.json packages/shared-types/package.json
COPY apps/relay-server/package.json apps/relay-server/package.json
RUN npm ci --include=dev --ignore-scripts --workspace=@crypto-pigeon/protocol --workspace=@crypto-pigeon/shared-types --workspace=@crypto-pigeon/relay-server
COPY packages/protocol/src packages/protocol/src
COPY packages/protocol/tsconfig.json packages/protocol/tsconfig.json
COPY packages/shared-types/src packages/shared-types/src
COPY packages/shared-types/tsconfig.json packages/shared-types/tsconfig.json
COPY apps/relay-server/src apps/relay-server/src
COPY apps/relay-server/tsconfig.json apps/relay-server/tsconfig.json
RUN npm run build --workspace=@crypto-pigeon/shared-types && npm run build --workspace=@crypto-pigeon/protocol && npm run build --workspace=@crypto-pigeon/relay-server

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8443 DATABASE_POOL_MAX=5
COPY package.json package-lock.json .npmrc ./
COPY packages/protocol/package.json packages/protocol/package.json
COPY packages/shared-types/package.json packages/shared-types/package.json
COPY apps/relay-server/package.json apps/relay-server/package.json
RUN npm ci --omit=dev --ignore-scripts --workspace=@crypto-pigeon/protocol --workspace=@crypto-pigeon/shared-types --workspace=@crypto-pigeon/relay-server
COPY --from=build /app/packages/protocol/dist packages/protocol/dist
COPY --from=build /app/packages/shared-types/dist packages/shared-types/dist
COPY --from=build /app/apps/relay-server/dist apps/relay-server/dist
USER node
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "apps/relay-server/dist/server.js"]
