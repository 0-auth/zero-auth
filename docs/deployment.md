# Deployment

## Netlify

Netlify can build this repository directly from GitHub. The included
`netlify.toml` keeps the docs versioned under `/v1/` and redirects `/` there.

Create a Netlify site connected to the repository with these settings:

| Setting | Value |
| --- | --- |
| Production branch | `master` |
| Build command | `npm run docs:build:versioned` |
| Output directory | `docs/.vitepress/dist` |
| Node.js version | `22` |
| Environment variable | `DOCS_BASE=/v1/` |

After the first deployment, the versioned docs are available at:

```text
https://<your-site>.netlify.app/v1/
```

For a custom domain, add it under **Domain management → Add a domain**. Keep
`DOCS_BASE=/v1/` if the docs should remain versioned; use `DOCS_BASE=/` only
when the docs should load at the domain root.

Preview locally with the production build:

```bash
npm run docs:build
npm run docs:preview
```

## Production checklist

- Set separate, random secrets for access and refresh tokens.
- Never use the development fallback secrets from the example app.
- Use HTTPS in production.
- Set cookie `secure: true` when using HTTP-only cookies.
- Set `NODE_ENV=production`.
- Use a shared refresh-token store when running multiple instances.

## Environment variables

Keep secrets outside the repository. A typical deployment has:

```bash
NODE_ENV=production
JWT_ACCESS_SECRET=<random-access-secret-at-least-32-characters>
JWT_REFRESH_SECRET=<different-random-refresh-secret-at-least-32-characters>
```

Read them when creating the auth instance:

```ts
const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
});
```

Your platform should provide these values through its secret manager or
protected environment settings.

## Express behind a reverse proxy

If TLS terminates at a reverse proxy or load balancer, configure Express to
trust the proxy according to your infrastructure:

```ts
app.set("trust proxy", 1);
```

This helps Express correctly understand secure forwarded requests. Only trust
proxy hops that you control.

## HTTP-only cookies

Use secure cookie settings in production:

```ts
const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
  cookies: {
    options: {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
    },
  },
});
```

If a browser frontend calls a different origin, configure CORS and send
credentials on the client request. Choose `sameSite: "none"` only when the
cross-site flow requires it, and keep `secure: true`.

## Docker

Build the package and run the API in a small Node image:

```dockerfile
FROM node:20-slim
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY dist ./dist
COPY server ./server

ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "server/index.js"]
```

Build the library before building the image:

```bash
npm run build
docker build -t my-api .
docker run --rm -p 3000:3000 \
  -e JWT_ACCESS_SECRET="$JWT_ACCESS_SECRET" \
  -e JWT_REFRESH_SECRET="$JWT_REFRESH_SECRET" \
  my-api
```

Adapt the `server` path to your API entry point. Do not copy `.env` files into
the image.

## Multiple instances

Access-token verification is stateless. Refresh-token rotation is not: the
callbacks in `refreshOptions` need a shared store such as Redis or a database
when requests can reach different instances.

The in-memory revocation store is suitable for local development and single
process tests, not for a horizontally scaled production deployment.

## Serverless

Create the auth instance outside the request handler so warm invocations can
reuse it. Store refresh-token revocation data externally; function memory can
be discarded between invocations.
