# PushLogger — real-time query log push for Technitium

Alternative to copying/polling Technitium's own log files (`infra/technitium-elk/data/dns_logs`),
which can miss or merge queries under heavy concurrent load. This is a DNS App installed directly
into Technitium: it implements `IDnsQueryLogger`, so **Technitium calls it the instant each query
is answered** — no interval, no risk of missing a burst of queries.

## How it works

1. Technitium calls `App.InsertLogAsync(...)` synchronously in the query-answering path. That
   method only enqueues the entry (non-blocking `Channel<T>.Writer.TryWrite`) and returns
   immediately — it never blocks or throws, so a slow/unreachable listener can never delay a
   real DNS answer.
2. A background task drains the queue and does the actual `HTTP POST` of each entry as JSON to
   `scripts/technitium_push_listener.py`'s `/push` endpoint, reached via this host's docker
   bridge gateway IP (e.g. `172.20.0.1` — find yours with `ip addr show`, the `br-...`
   interface; it's whatever `--push-host` is set to).
3. That listener reformats the JSON into the exact text line Technitium's own log files use and
   appends it to `data/raw/<date>.log` — so `extractor.parse_technitium_log_line` and the rest
   of the pipeline need no changes.
4. If the queue fills up (listener down for a while), oldest entries are dropped
   (`BoundedChannelFullMode.DropOldest`) rather than growing without bound or blocking DNS.

## Quick start (any machine, first time or after a reinstall)

```bash
# 1. Start Technitium if it isn't running:
cd infra/technitium-elk && docker compose up -d && cd -

# 2. Log into http://localhost:5380 (set up the admin account if prompted), then
#    Settings > Sessions > Create Token, and run:
./scripts/setup_pushlogger.sh --api-key <token>
```

That one command detects the server's version, builds the plugin against it if needed,
installs/updates it, turns on query logging, points it at the push listener, saves the key to
`.env`, and (re)starts the listener. It is **safe to re-run** any time — after deleting and
reinstalling Technitium with a brand new API key, or after upgrading to a different Technitium
version, just run it again with the new `--api-key`. See `scripts/setup_pushlogger.sh --help`
for the full option list (custom `--url`, `--push-port`, etc).

## Networking: finding your bridge IP

The container reaches the host's push listener via this host's docker bridge gateway address
(not `127.0.0.1` — that's the container's own loopback, not the host's). Find yours with:

```bash
ip addr show | grep -A1 'br-' | grep inet
```

Pass whichever address that shows to `setup_pushlogger.sh --push-host <ip>` (default
`172.20.0.1`, this machine's). It can differ on another machine or if this project's docker
network gets recreated — the push listener itself binds `0.0.0.0` so it's reachable no matter
which bridge ends up in play.

## Building manually

Only needed if you want to build without installing (`setup_pushlogger.sh` does this step for
you automatically, rebuilding only when the detected server version changed since the last
build). No NuGet package is published for the two assemblies a DNS App compiles against
(`DnsServerCore.ApplicationCommon.dll`, `TechnitiumLibrary.Net.dll`) — Technitium builds them
from source as part of the full server build. `build.sh` clones the matching-version tags of
both repos and builds them itself, so the reference DLLs (and the .NET TargetFramework
PushLogger compiles against) always match your actual running server version — a mismatch
causes the app to load with zero recognized DNS apps, see "Gotchas" below. Everything this
needs lives under `infra/technitium-build/` (gitignored — cloned Technitium source and build
output, not our code), not outside the project. If a previous run left those repos checked out
at a *different* version, `build.sh` detects that (via a `.checked_out_tag` marker) and
re-clones automatically — you never need to clean that folder by hand when switching versions.

```bash
# Check your server's exact version first: Settings > General in the web console,
# or GET /api/user/session/get
./build.sh 15.6.2        # produces ./PushLogger.zip

# Needs a .NET SDK new enough for the target server's TargetFramework (build.sh detects and
# prints it from the cloned source). setup_pushlogger.sh looks for one at
# infra/technitium-build/dotnet-sdk first, before falling back to a system `dotnet` on PATH.
# If neither exists yet, install one kept inside the project rather than system-wide:
#   curl -sL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 10.0 --install-dir ../technitium-build/dotnet-sdk
#   DOTNET=../technitium-build/dotnet-sdk/dotnet ./build.sh 15.6.2
```

## Installing manually (what `setup_pushlogger.sh` automates)

```bash
TOKEN=<your TECHNITIUM_API_KEY>

curl -s -X POST "http://localhost:5380/api/settings/set?token=$TOKEN&logQueries=true"

curl -s -X POST "http://localhost:5380/api/apps/install?name=PushLogger&token=$TOKEN" \
  -F "file=@PushLogger.zip;type=application/zip"

CONFIG='{"pushUrl":"http://172.20.0.1:8787/push","pushToken":"'"$TOKEN"'","timeoutMs":2000,"maxQueueSize":10000}'
curl -s -X POST "http://localhost:5380/api/apps/config/set?name=PushLogger&token=$TOKEN" \
  --data-urlencode "config=$CONFIG"

# After rebuilding:
curl -s -X POST "http://localhost:5380/api/apps/update?name=PushLogger&token=$TOKEN" \
  -F "file=@PushLogger.zip;type=application/zip"

# To remove entirely:
curl -s "http://localhost:5380/api/apps/uninstall?name=PushLogger&token=$TOKEN"
```

## Running the listener manually

```bash
python3 ../../scripts/technitium_push_listener.py --host 172.20.0.1 --port 8787
```

A separate, standalone process from `dashboard/server.py`: the listener only writes to
`data/raw`; the dashboard only watches `data/raw` and reruns the pipeline on change (its
default `--watch` already points there), so run both.

## Gotchas

- **Fresh Technitium install, nothing ever gets pushed**: query logging is **off by default**
  (`logQueries: false`). `setup_pushlogger.sh` turns it on; if configuring by hand, don't skip
  the `/api/settings/set?logQueries=true` call.
- **`"dnsApps": []` on install, `"version": "0.0"`**: the zip is missing `PushLogger.deps.json`
  — Technitium's app loader (`DnsApplicationAssemblyLoadContext`) discovers an app's assemblies
  by scanning the folder for `*.deps.json` files, not `.dll` directly. `build.sh` already
  includes it; if you zip by hand, don't forget it.
- **Assembly version mismatch**: `DnsApplication.cs` matches the `IDnsQueryLogger` interface by
  exact `Type ==` equality, which only holds if the compiled `DnsServerCore.ApplicationCommon`
  assembly identity (name + version) *and* TargetFramework match what the live server already
  has loaded — hence building from the exact matching git tag every time, and re-cloning rather
  than reusing a checkout left over from a different version.
- **Deleted/reinstalled Technitium, or a new API key**: nothing persists across a container
  recreation except the `data/dns_logs` volume — the installed app, `logQueries` setting, and
  old token are all gone. Just re-run `./scripts/setup_pushlogger.sh --api-key <new token>`.
- Config changes via `/api/apps/config/set` call `InitializeAsync` again, which this app handles
  (it tears down and restarts its worker/channel on every call, including the first), so
  re-configuring at runtime is safe.
