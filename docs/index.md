---
layout: home
title: zero-auth — Authentication for Node.js APIs
titleTemplate: false
hero:
  name: zero-auth
  text: Authentication without the auth platform
  tagline: JWTs, refresh rotation, secure cookies, and RBAC for Node.js APIs.
  actions:
    - theme: brand
      text: Start building
      link: /quick-start
    - theme: alt
      text: Browse the API
      link: /api/
features:
  - icon: "01"
    title: Small surface area
    details: One createAuth call, familiar Express middleware, and TypeScript-first types.
  - icon: "02"
    title: Secure token lifecycle
    details: Short-lived access tokens, refresh rotation, revocation hooks, and reuse detection.
  - icon: "03"
    title: Bring your own storage
    details: No hosted auth platform or user database. Connect your own store and deployment.
---

<div class="home-intro">
  <p class="eyebrow">A focused auth layer for teams that want control</p>
  <h2>Ship auth your team can understand.</h2>
  <p>
    Keep identity in your application, use standard JWTs at the edge, and add
    stronger refresh-token protection when your product needs it.
  </p>
</div>

<div class="home-grid">
  <a class="home-card" href="/guides/bearer-tokens">
    <span class="home-card-kicker">For APIs</span>
    <strong>Bearer tokens</strong>
    <span>For mobile apps, CLIs, and separate frontends.</span>
  </a>
  <a class="home-card" href="/guides/cookies">
    <span class="home-card-kicker">For browsers</span>
    <strong>HTTP-only cookies</strong>
    <span>Keep browser tokens away from JavaScript.</span>
  </a>
  <a class="home-card" href="/guides/refresh-rotation">
    <span class="home-card-kicker">For security</span>
    <strong>Refresh rotation</strong>
    <span>Detect replay and revoke a complete token family.</span>
  </a>
</div>

## Get productive quickly

```ts
const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
});

app.get("/profile", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});
```

<div class="home-actions">
  <a href="/examples/rest-api">Run the complete Express example →</a>
  <a href="/security">Review the security checklist →</a>
</div>
