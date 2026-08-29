---
layout: home
title: zero-auth — Authentication for Node.js APIs
titleTemplate: false
hero:
  name: zero-auth
  text: Authentication without the auth platform
  tagline: JWTs, refresh rotation, secure cookies, CSRF, and access control for Node.js APIs.
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
    title: Secure browser sessions
    details: HTTP-only cookies with signed double-submit CSRF protection for state-changing requests.
  - icon: "04"
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
  <a class="home-card" href="./guides/bearer-tokens">
    <span class="home-card-kicker">For APIs</span>
    <strong>Bearer tokens</strong>
    <span>For mobile apps, CLIs, and separate frontends.</span>
  </a>
  <a class="home-card" href="./guides/cookies">
    <span class="home-card-kicker">For browsers</span>
    <strong>HTTP-only cookies</strong>
    <span>Keep browser tokens away from JavaScript.</span>
  </a>
  <a class="home-card" href="./guides/refresh-rotation">
    <span class="home-card-kicker">For security</span>
    <strong>Refresh rotation</strong>
    <span>Detect replay and revoke a complete token family.</span>
  </a>
  <a class="home-card" href="./guides/access-control">
    <span class="home-card-kicker">For authorization</span>
    <strong>Roles and permissions</strong>
    <span>Protect routes with coarse or fine-grained access checks.</span>
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

`zero-auth` signs and verifies tokens, but your application owns users,
passwords, storage, rate limits, and authorization policy. Start with the
[quick start](/quick-start), then choose a [bearer-token](/guides/bearer-tokens)
or [cookie](/guides/cookies) integration.

## Documentation map

- **Build:** [quick start](/quick-start), [configuration](/configuration), and [client examples](/clients)
- **Secure:** [access control](/guides/access-control), [CSRF](/guides/cookies#csrf-protection), and [security checklist](/security)
- **Operate:** [refresh rotation](/guides/refresh-rotation), [deployment](/deployment), and [troubleshooting](/faq)
- **Reference:** [errors](/errors) and the [generated API reference](/api/)
- **Maintain:** [testing](/testing), [versioning](/versioning), [changelog](/changelog), and [release process](/releasing)

<div class="home-actions">
  <a href="./examples/rest-api">Run the complete Express example →</a>
  <a href="./security">Review the security checklist →</a>
</div>
