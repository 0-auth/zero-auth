# Client examples

The API supports bearer tokens and HTTP-only cookies. Pick one approach per
client and keep access tokens out of URLs and logs.

## Browser with `fetch` and bearer tokens

```ts
const loginResponse = await fetch("https://api.example.com/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email, password }),
});

const { accessToken, refreshToken } = await loginResponse.json();

const profileResponse = await fetch("https://api.example.com/profile", {
  headers: { Authorization: `Bearer ${accessToken}` },
});
```

For browser applications, avoid long-term token storage in `localStorage` when
an HTTP-only cookie flow is suitable. If you use bearer tokens, define an
explicit in-memory or carefully protected session strategy.

## Browser with HTTP-only cookies

The server sets the cookies during login. The browser sends them when the
request includes credentials:

```ts
await fetch("https://api.example.com/auth/login", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email, password }),
});

const response = await fetch("https://api.example.com/profile", {
  credentials: "include",
});
```

JavaScript cannot read an HTTP-only cookie. Add CSRF protection for
cookie-authenticated state-changing requests:

```ts
app.use(auth.csrf());

const csrfResponse = await fetch("https://api.example.com/auth/csrf-token", {
  credentials: "include",
});
const { csrfToken } = await csrfResponse.json();

await fetch("https://api.example.com/account", {
  method: "POST",
  credentials: "include",
  headers: { "x-csrf-token": csrfToken },
});
```

The endpoint should call `auth.csrfToken(res)` to set and return the token.
Read the [security checklist](/security) before deploying.

## Axios

Bearer tokens can be attached with an Axios request interceptor:

```ts
import axios from "axios";

const api = axios.create({ baseURL: "https://api.example.com" });
let accessToken: string | undefined;

api.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

const login = await api.post("/auth/login", { email, password });
accessToken = login.data.accessToken;

const profile = await api.get("/profile");
```

For cookies, configure Axios with credentials instead:

```ts
const api = axios.create({
  baseURL: "https://api.example.com",
  withCredentials: true,
});
```

## Mobile or native clients

Native clients commonly keep the access token in memory and use a platform
secure storage mechanism for the refresh token. The request shape is the same:

```text
POST /auth/login
Content-Type: application/json

{"email":"user@example.com","password":"..."}
```

Then send the access token on API requests:

```text
Authorization: Bearer <access-token>
```

When the API returns `AUTH_TOKEN_EXPIRED`, call `/auth/refresh`, replace both
tokens, and retry the original request once. Avoid infinite retry loops.

## CLI with curl

```bash
response=$(curl -s -X POST https://api.example.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"your-password"}')

curl https://api.example.com/profile \
  -H "Authorization: Bearer <access-token>"
```

Never put tokens in command history or shell scripts that are shared with
others.
