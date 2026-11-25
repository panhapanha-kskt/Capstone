# Go gateway implementation result

**Date:** 2026-11-25

## Implemented

1. Added `dashboard/go-gateway/`, a Go standard-library reverse proxy that keeps Python's existing `/soc`, `/triage`, `/alerts`, `/events`, static assets, and API contracts. The Go server has header, read, write, and idle timeouts, a 16 KiB header cap, and a 64 KiB JSON POST cap.
2. Added analyst token sign-in and eight-hour opaque in-memory sessions. The gateway uses `HttpOnly`, `SameSite=Strict` cookies, with `Secure` on TLS, checks Host and same-origin request metadata, removes client-supplied internal identity headers, and overwrites write-body and read-query actor values from the session. `/api/analysts` returns only the signed-in analyst. The frontend reads the authenticated analyst identity and prevents switching when there is one authenticated identity.
3. Added an optional Python `SOC_INTERNAL_TOKEN` guard that rejects direct browser/API requests when deployed behind Go. The same Python SOC logic and data model remain in use. Gateway setup and token provisioning are documented in `dashboard/go-gateway/README.md`.

## Verification

- Official Go 1.27.4 toolchain downloaded temporarily; archive SHA-256 matched the published `91a44a2b8a716600ad94a4f143e156116620db8828086a6e3602291be9bd0bb4`.
- `go test ./...`, `go test -race ./...`, and `go vet ./...` passed.
- Python internal-token guard passed a direct module assertion. A focused pytest case was added, but pytest is not installed in the available Python environments, so the Python pytest suite could not be run here.
- Isolated end-to-end demo: direct Python `/api/state` returned 403; authenticated Go `/triage`, `/alerts`, `/events`, `/api/state`, and `/api/analysts` returned 200; `/api/analysts` returned only `analyst-1` and `authenticated: true`. Test processes were stopped after verification. The pre-existing port 9000 service was not changed or restarted.

## Local activation after port 9000 was stopped

The user stopped the old port 9000 process. The Go gateway now serves `127.0.0.1:9000`; the unchanged Python demo runs on `127.0.0.1:9002` with the internal guard. Four random analyst access tokens, SHA-256 credential hashes, and the internal secret were provisioned in ignored, mode-600 files under `dashboard/data/`. The Go executable is stored there as `soc-gateway`, and `dashboard/go-gateway/run-local.sh` restarts the paired services. A fresh live check after starting with this script returned 200 for `/soc`, `/triage`, `/alerts`, `/events`, `/api/state`, and `/api/analysts` after login, 303 for anonymous `/triage`, and 403 for direct Python `/api/state`.

After a user reported a cross-origin error, the gateway's origin check was corrected to trust an exact matching `Origin` when a browser also reports `Sec-Fetch-Site: same-site`. Validated requests are now forwarded to Python with `Sec-Fetch-Site: same-origin`. A regression test was added, the Go tests passed, and the active stack was restarted. A browser-style login and a safe POST to a nonexistent alert succeeded through the gateway; the POST returned the expected 404 rather than a cross-origin 403.

The user's browser later revealed `Origin: null` with `Sec-Fetch-Site: none` on the login form. The gateway now accepts that exact combination for token sign-in only; protected SOC writes still require the stricter origin check. The gateway tests passed, and a live request with those exact headers and the provisioned token returned 303 from `/login`, followed by 200 from authenticated `/triage`.

## Username and password login update

The local Go `/login` page now uses username and password fields. Passwords require at least 12 characters with a letter, number, and symbol, checked by the form and Go server. Local analyst accounts were provisioned with generated 24-character passwords; Go stores only random-salted PBKDF2-HMAC-SHA256 hashes at 600,000 iterations in `dashboard/data/gateway-password-credentials.json`. The initial plaintext passwords are in an ignored, mode-600 file for the operator to copy into a password manager. Failed sign-ins are rate-limited by client IP. Go tests and race tests passed, and a live browser-header sign-in returned 303 followed by 200 for `/triage` and `/alerts`.

The user then requested that access tokens remain part of sign-in. `/login` now requires all three matching fields: username, password, and the existing access token. Existing access tokens were preserved and their SHA-256 hashes were added to the per-user credential records; token-only and password-only login are rejected.

The final three-field build passed `go test -race ./...` and `go vet ./...`. The live page returned 200 with all three fields; a matching three-field sign-in returned 303, authenticated `/triage` and `/alerts` returned 200, and a password-only sign-in returned 401.

## Browser navigation fix

A real Chrome form submission returned `Origin: null` with `Sec-Fetch-Site: same-origin`. The gateway rejected that combination, so the browser never obtained a session and navigation to Triage, Alerts, Event Explorer, and Sources & Collection fell back to login. The origin guard now accepts this browser-generated same-origin metadata while continuing to reject `Origin: null` with `Sec-Fetch-Site: cross-site`. A regression test and `go test -race ./...` passed. After restarting the live gateway, a full headless Chrome flow entered all three credentials, reached `/soc`, and rendered populated `/triage`, `/alerts`, `/events`, and `/devices` views without JavaScript errors.

## Remaining limits

This is a compatibility gateway. Python still owns SOC writes and file-backed state. The Go gateway does not yet provide a transactional database, durable sessions, route-specific Go permission checks, idempotency, or a demonstrated speed improvement. Existing Python per-role rules still apply after actor binding. The active port 9000 stack is a localhost demo; production deployment still needs TLS, managed token distribution, and durable service supervision.
