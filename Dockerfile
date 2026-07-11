FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/relay/package.json apps/relay/package.json
COPY apps/client/package.json apps/client/package.json
RUN npm ci
COPY apps/relay apps/relay
RUN npm run build --workspace=@crypto-pigeon/relay

FROM node:24-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/apps/relay/dist ./apps/relay/dist
CMD ["node", "apps/relay/dist/server.js"]
