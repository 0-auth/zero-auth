# Client examples

The API supports bearer tokens and HTTP-only cookies. Choose one transport per
client and never put tokens in URLs, logs, analytics events, or error reports.

## Choose a transport

| Client | Recommended transport | Reason |
| --- | --- | --- |
| Browser application | HTTP-only cookies with CSRF protection | Keeps token values away from JavaScript |
| Mobile application | Bearer access token plus secure refresh storage | Uses native secure-storage APIs |
| CLI | Bearer tokens | Explicit headers are simple to script |
| Server-to-server | Bearer tokens | Avoids browser cookie behavior |

## Browser with fetch and bearer tokens

~~~ts
const loginResponse = await fetch("https://api.example.com/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email, password }),
});

const { accessToken, refreshToken } = await loginResponse.json();

const profileResponse = await fetch("https://api.example.com/profile", {
  headers: { Authorization: "Bearer " + accessToken },
});
~~~

Keep the access token in memory when practical. If the refresh token must
survive a restart, use platform secure storage. Do not use localStorage as a
default for sensitive sessions.

## Browser with HTTP-only cookies

The server sets the cookies during login. The browser sends them when the
request includes credentials:

~~~ts
await fetch("https://api.example.com/auth/login", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email, password }),
});

const response = await fetch("https://api.example.com/profile", {
  credentials: "include",
});
~~~

JavaScript cannot read an HTTP-only cookie. Add CSRF protection for
cookie-authenticated state-changing requests:

~~~ts
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
~~~

The endpoint should call <code>auth.csrfToken(res)</code> to set and return the
token. Read the [security checklist](/security) before deploying.

## Axios

Bearer tokens can be attached with an Axios request interceptor:

~~~ts
import axios from "axios";

const api = axios.create({ baseURL: "https://api.example.com" });
let accessToken: string | undefined;

api.interceptors.request.use((config) => {
  if (accessToken) config.headers.Authorization = "Bearer " + accessToken;
  return config;
});

const login = await api.post("/auth/login", { email, password });
accessToken = login.data.accessToken;

const profile = await api.get("/profile");
~~~

For cookies, configure Axios with credentials instead:

~~~ts
const api = axios.create({
  baseURL: "https://api.example.com",
  withCredentials: true,
});
~~~

Cookie clients still need the CSRF token header for state-changing requests.

## Mobile or native clients

Native clients commonly keep the access token in memory and use platform secure
storage for the refresh token:

~~~text
Authorization: Bearer <access-token>
~~~

When the API returns <code>AUTH_TOKEN_EXPIRED</code>, call the refresh endpoint,
replace both tokens when rotation is enabled, and retry the original request
once. Avoid infinite retry loops.

## CLI with curl

~~~bash
curl -s -X POST https://api.example.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"your-password"}'

curl https://api.example.com/profile \
  -H "Authorization: Bearer <access-token>"
~~~

For cookie sessions, preserve the cookie jar:

~~~bash
curl -c cookies.txt -b cookies.txt \
  https://api.example.com/auth/csrf-token

curl -X POST -c cookies.txt -b cookies.txt \
  -H "x-csrf-token: <csrf-token>" \
  https://api.example.com/account
~~~

Never put tokens in command history or shared shell scripts.

## Handling failures

- <code>401 AUTH_TOKEN_MISSING</code>: send an access token or include auth cookies.
- <code>401 AUTH_TOKEN_EXPIRED</code>: refresh once, then retry once.
- <code>401 AUTH_TOKEN_INVALID</code>: discard the token; with rotation, check for replay.
- <code>403 AUTH_FORBIDDEN</code>: the authenticated user lacks the role or permission.
- <code>403 AUTH_CSRF_INVALID</code>: fetch a new CSRF token and send its matching header/cookie pair.
