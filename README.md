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
