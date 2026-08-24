FROM node:22-alpine AS auth-build

WORKDIR /workspace
COPY package*.json ./
RUN npm ci
COPY src ./src
COPY tsconfig.json tsup.config.ts ./
RUN npm run build

FROM node:22-alpine

WORKDIR /workspace
ENV NODE_ENV=production

COPY package*.json ./
RUN npm install --omit=dev --ignore-scripts
COPY --from=auth-build /workspace/dist ./dist

COPY examples/express-cookies-redis/package*.json ./examples/express-cookies-redis/
COPY examples/express-cookies-redis/src ./examples/express-cookies-redis/src
COPY examples/express-cookies-redis/tsconfig.json ./examples/express-cookies-redis/

WORKDIR /workspace/examples/express-cookies-redis
RUN npm ci --omit=dev

EXPOSE 3001
CMD ["npm", "start"]
