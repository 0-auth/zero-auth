# Authentication flows

These diagrams show where `zero-auth` fits into a typical API.

## Login and protected request

```text
Client                         Express API                    zero-auth
  |                                |                              |
  | POST /auth/login               |                              |
  |------------------------------->|                              |
  |                                | validate credentials         |
  |                                |------------------------------>| 
  |                                |        generateTokenPair()    |
  |                                |<------------------------------|
  |       accessToken + refreshToken                              |
  |<-------------------------------|                              |
  |                                |                              |
  | GET /api/profile               |                              |
  | Authorization: Bearer token    |                              |
  |------------------------------->|                              |
  |                                | protect() verifies token     |
  |                                |------------------------------>| 
  |                                | req.user                      |
  |                                |<------------------------------|
  |            protected response  |                              |
  |<-------------------------------|                              |
```

## Cookie-based browser flow

```text
Browser                 Express API                 Browser cookie jar
   |                         |                              |
   | POST /auth/login        |                              |
   |------------------------>|                              |
   |                         | sendAuthTokens(res, user)    |
   |                         |----------------------------->|
   |                         | Set-Cookie: access_token     |
   |                         | Set-Cookie: refresh_token    |
   |<------------------------|                              |
   |                         |                              |
   | GET /api/me             |                              |
   |------------------------>| Cookie: access_token          |
   |                         | protect() reads cookie        |
   |<------------------------|                              |
   |                         |                              |
   | POST /auth/logout       |                              |
   |------------------------>|                              |
   |                         | clearAuth(res)                |
   |<------------------------| expired cookies               |
```

## Refresh token rotation

```text
Client                    API                         Token store
  |                         |                             |
  | POST /auth/refresh     |                             |
  | refresh token          |                             |
  |------------------------>|                             |
  |                         | isRevoked(oldJti)          |
  |                         |---------------------------->|
  |                         | not revoked                 |
  |                         |<----------------------------|
  |                         | revokeRefreshToken(oldJti)  |
  |                         |---------------------------->|
  |                         | registerRefreshToken(newJti)|
  |                         |---------------------------->|
  |  new access + refresh   |                             |
  |<------------------------|                             |
```

Each refresh request invalidates the previous refresh token when
`refreshOptions.rotate` is enabled.

## Refresh token reuse detection

```text
Stolen/replayed token        API                       Token store
          |                   |                            |
          | refresh request  |                            |
          |------------------>|                            |
          |                   | isRevoked(oldJti)          |
          |                   |--------------------------->|
          |                   | revoked                     |
          |                   |<---------------------------|
          |                   | onRefreshReuse(context)    |
          |                   |--------------------------->|
          |                   | revoke entire token family |
          |       401 error   |                            |
          |<------------------|                            |
```

Use a shared store such as Redis for rotation and family revocation when the
API runs on more than one instance.
