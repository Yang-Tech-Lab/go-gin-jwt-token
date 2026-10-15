# Gin JWT authentication example

Set a strong signing secret and run the service:

```bash
export JWT_SECRET='replace-with-a-long-random-secret'
go run .
```

For this self-contained example, log in using the demonstration credentials below. Replace the check in `loginHandler` with your application's database and password-hash verification before production use.

```bash
curl -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo-password"}'
```

Use the returned `token` with protected routes:

```bash
curl http://localhost:8080/profile -H 'Authorization: Bearer <token>'
```

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `JWT_SECRET` | *(required)* | HS256 signing key; use a long random value |
| `JWT_ISSUER` | `go-gin-jwt-token` | Expected/issued `iss` claim |
| `JWT_AUDIENCE` | *(unset)* | When set, `aud` is issued and validated |
| `JWT_TTL_MINUTES` | `15` | Token lifetime |
| `JWT_CLOCK_SKEW_SECONDS` | `60` | Leeway for `exp`/`iat` clock drift |
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `GIN_MODE` | debug | Set `release` in production |

Tokens carry a unique `jti` claim; implement `auth.RevocationList` (e.g. backed by Redis) and inject it via `Config.Revocation` to support logout/revocation.
