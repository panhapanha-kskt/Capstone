# SOC Go gateway

The Go gateway serves the existing Python dashboard and API routes. Python remains the detection engine and SOC state owner. Run Python on loopback with `SOC_INTERNAL_TOKEN` and give the gateway the same value; Python then rejects direct requests that bypass Go.

## Local demo on this machine

`run-local.sh` starts Python demo mode on private port 9002 and Go on `http://127.0.0.1:9000`. The login page requires a username, password, and access token for the same analyst. Existing local accounts are `analyst-1`, `analyst-2`, `senior-1`, and `ir-lead`; their generated passwords are in the ignored, mode-600 file `dashboard/data/gateway-initial-passwords.json`. Their original access tokens remain in `dashboard/data/gateway-access-tokens.json`. Copy both secrets into a password manager and remove the plaintext files when no longer needed.

From the repository root:

```sh
dashboard/go-gateway/run-local.sh
```

Keep that terminal open. Ctrl+C stops both services. The binary is stored in ignored local data at `dashboard/data/soc-gateway`.

## Provisioning and deployment

Go 1.24 or newer is required to build the gateway. Build from this directory with `go build -o ../data/soc-gateway .`. The module uses only Go's standard library. Run `python3 provision-users.py` once to create local usernames, generated 24-character passwords, 64-character random access tokens, and their hashes. The script refuses to overwrite existing credential records. Passwords must be at least 12 characters and contain a letter, number, and symbol; the login form and server both check this rule. The stored password hash uses PBKDF2-HMAC-SHA256 with 600,000 iterations and a random 16-byte salt per user. Access tokens are stored as SHA-256 hashes. Keep `dashboard/data/gateway-password-credentials.json` restricted to the service account (`chmod 600`). Each `analyst` value must match an ID in Python's `analysts.json`.

Generate a separate 32-byte-or-longer random `SOC_INTERNAL_TOKEN` for Go and Python. For a non-loopback deployment, configure `--tls-cert`, `--tls-key`, and `--public-host`; the gateway refuses public HTTP. Put Python on a private loopback port. The Go gateway is not yet integrated into `scripts/soc.sh` on WSL.

The gateway binds JSON POST `actor` fields and GET `actor` query parameters to the signed-in analyst, filters `/api/analysts` to that analyst, checks request origin and Host, caps JSON POST bodies at 64 KiB, and rate-limits failed sign-ins. Sessions are opaque, eight-hour, in-memory cookies with `HttpOnly` and `SameSite=Strict` (`Secure` with TLS). Restarting Go signs users out. The training API still requires its separate admin token.

Run `go test ./...` and `go test -race ./...` for gateway checks. The Python internal guard has a focused test in `tests/test_dashboard_soc.py`.
