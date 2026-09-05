FROM node:22-bookworm-slim AS build
WORKDIR /repo
COPY package.json package-lock.json ./
COPY packages ./packages
COPY eslint.config.mjs ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts --no-audit --no-fund --maxsockets=5 && npm run build
COPY examples/express-idp ./examples/express-idp
RUN --mount=type=cache,target=/root/.npm cd examples/express-idp && npm ci --ignore-scripts --no-audit --no-fund --maxsockets=5 && npm run typecheck

FROM node:22-bookworm-slim
WORKDIR /repo
COPY --from=build /repo/node_modules ./node_modules
COPY --from=build /repo/packages ./packages
COPY --from=build /repo/examples/express-idp ./examples/express-idp
WORKDIR /repo/examples/express-idp
USER node
EXPOSE 3001
CMD ["node", "--import", "tsx", "src/server.ts"]
