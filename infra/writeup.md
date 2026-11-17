# Session Write-up: Real-Time Push Logging for Technitium DNS

## Goal

Replace polling/copying Technitium's log files with a true **real-time push** pipeline: the
moment Technitium answers a DNS query, that query lands in `data/raw/<date>.log`, with no
fixed interval and no risk of missing queries under heavy concurrent load.

## Files created

### `infra/technitium-apps/PushLogger/App.cs`
The actual DNS App (C#) installed **inside** Technitium itself. Implements two Technitium
interfaces:
- `IDnsApplication` — the generic plugin lifecycle (`InitializeAsync`, `Description`, `Dispose`).
- `IDnsQueryLogger` — Technitium calls `InsertLogAsync(...)` **synchronously, in the
  query-answering path**, right after every single query is resolved.

Design choices, and why:
- `InsertLogAsync` only enqueues the entry into an in-memory `Channel<T>` and returns
  immediately — it never blocks or throws. If it did either, a slow or unreachable listener
  could delay or break real DNS answers for every user, not just test traffic.
- A background task (`WorkerLoopAsync`) drains that channel and does the actual `HTTP POST`
  of each entry as JSON to the listener.
- The channel is bounded (`maxQueueSize`, default 10,000) with `DropOldest` behavior: if the
  listener is down for a while, Technitium drops the oldest queued entries instead of growing
  memory without bound or ever blocking DNS resolution.
- `FormatRData` converts each answer record (A/AAAA/CNAME/NS/PTR/MX/TXT) to a plain string for
  the JSON payload; anything else falls back to just the record type name.
- The timestamp is passed through as-is (no UTC conversion) because the extractor
  (`src/dns_detect/features/extractor.py: parse_technitium_log_line`) requires the literal word
  `Local` in the log line, matching Technitium's own native log format.

### `infra/technitium-apps/PushLogger/PushLogger.csproj`
Build definition for the App above. The two assemblies a Technitium DNS App compiles against
(`DnsServerCore.ApplicationCommon.dll`, `TechnitiumLibrary.Net.dll`) aren't published as NuGet
packages — Technitium builds them from source as part of the full server build. Both are
referenced with `Private=false`, meaning they're **not** copied into this app's own output —
the live server process already has them loaded, and Technitium matches the `IDnsQueryLogger`
interface by exact `Type ==` equality, so a mismatched copy would simply fail to be recognized.
`TargetFramework` is parameterized (`TechnitiumTargetFramework` MSBuild property, default
`net10.0`) so `build.sh` can set it to whatever the live server actually targets.

### `infra/technitium-apps/build.sh`
Builds everything above against the **exact** Technitium version you're running, every time,
rather than trusting a cached DLL:
1. Clones `TechnitiumSoftware/TechnitiumLibrary` at tag `dns-server-v<version>` and
   `TechnitiumSoftware/DnsServer` at tag `v<version>` into `~/technitium-build/` (only once;
   reused on later runs).
2. Detects the server's `TargetFramework` straight from the cloned source
   (`DnsServerCore.ApplicationCommon.csproj`) instead of hardcoding it.
3. Builds `TechnitiumLibrary.Net.dll` and `DnsServerCore.ApplicationCommon.dll` from that
   source and copies them into `~/technitium-build/refs/`.
4. Publishes `PushLogger` against those reference DLLs.
5. Zips `PushLogger.dll` + `PushLogger.deps.json` + `PushLogger.pdb` into `PushLogger.zip`.

Usage: `DOTNET=~/.dotnet10/dotnet ./build.sh 15.6.2` (version must match your running server —
check `Settings > General` in the Technitium web console, or `GET /api/user/session/get`).

**Gotcha baked into this script, worth calling out:** a zip containing only `PushLogger.dll`
installs "successfully" but loads **zero** DNS apps (`"dnsApps": []`, `"version": "0.0"`) with
no error message anywhere. Technitium's app loader discovers an app's assemblies by scanning
the installed folder for `*.deps.json` files, not `.dll` files directly — so the `.deps.json`
(produced automatically by `dotnet publish`) has to be in the zip too. This cost real debugging
time before being root-caused by reading Technitium's own loader source.

### `infra/technitium-apps/README.md`
Full documentation of the above: how the push flow works end to end, how to build, how to
install/configure/update/uninstall the app via the Technitium API, how to run the listener, and
the two gotchas (missing `.deps.json`; assembly/TargetFramework version mismatch).

### `scripts/technitium_push_listener.py`
The piece that answers "do I need a Python file running?" — **yes**. HTTP push has to land
somewhere; this is a small, dependency-free (stdlib only) HTTP server that:
- Listens on `--host`/`--port` (must be an interface the Technitium **container** can reach,
  e.g. its docker bridge gateway — not `127.0.0.1`).
- Checks a shared-secret `token` on every push against `TECHNITIUM_PUSH_TOKEN` (or, if unset,
  `TECHNITIUM_API_KEY`) read from `.env`.
- Reformats the pushed JSON into the exact text line Technitium's own log files use and
  appends it to `data/raw/<date>.log` under a `threading.Lock()` (safe for many concurrent
  pushes at once).
- Exposes `GET /healthz` for a quick liveness check.

This is a **separate, standalone process** from `dashboard/server.py` — the listener only
writes to `data/raw`; the dashboard only watches `data/raw` (its default `--watch` target) and
reruns the detection pipeline on change. Both need to be running; neither depends on the other
directly.

### `.env` (new, gitignored — not committed)
Created with the `TECHNITIUM_API_KEY` you generated via Technitium's **Settings → Sessions →
Create Token**. This key is used both to call the Technitium API (installing/configuring the
app) and as the push listener's shared secret.

## Files modified

### `.env.example`
Added two documented, empty placeholders so the required variables are discoverable without
reading code:
```
TECHNITIUM_API_KEY=
TECHNITIUM_PUSH_TOKEN=
```

## Live actions taken against the running Technitium server (not file changes, but part of the setup)

1. **Enabled query logging.** A fresh Technitium install has `logQueries: false` by default —
   nothing is ever handed to `IDnsQueryLogger` (built-in or custom) until this is turned on.
   Flipped via `POST /api/settings/set?logQueries=true`.
2. **Built the plugin** against the live server's actual version, detected as `15.6.2`, with
   `./build.sh 15.6.2` (using a user-local .NET 10 SDK at `~/.dotnet10`, since the system `dotnet`
   is older).
3. **Installed it**: `POST /api/apps/install?name=PushLogger` with `PushLogger.zip`. Result
   confirmed `"isQueryLogger": true` on first try.
4. **Configured it**: `POST /api/apps/config/set?name=PushLogger` with
   `{"pushUrl":"http://172.20.0.1:8787/push","pushToken":"<API key>","timeoutMs":2000,"maxQueueSize":10000}`.
5. **Started the listener**: `python3 scripts/technitium_push_listener.py --host 172.20.0.1 --port 8787`.

## Verification

A `dig` test against the docker bridge address the host uses turned out to actually be hitting
WSL2's own system DNS resolver (`/etc/resolv.conf` → `nameserver 10.255.255.254`), not the
Technitium container — so it never touched Technitium at all (`totalQueries` stayed `0`).
Rather than fight that host-networking quirk, the push path itself was verified by asking
Technitium to resolve a query against **itself**
(`GET /api/dnsClient/resolve?server=this-server&domain=...`), which runs through its real
internal resolution engine from inside the container. That query appeared in
`data/raw/2026-11-14.log` within well under a second, correctly formatted:

```
[2026-11-14 17:27:18 Local] [127.0.0.1:57457] [UDP] QNAME: pushtest-inside-container.example.com; QTYPE: A; QCLASS: IN; RCODE: NoError; ANSWER: []
```

This confirms the full chain works: Technitium → `PushLogger` DNS App → HTTP POST →
`technitium_push_listener.py` → `data/raw/<date>.log`, with no polling interval anywhere.

**Known open item, unrelated to the push system itself:** ordinary `dig @<host-ip>` from
outside the container doesn't currently reach Technitium's port 53 on this host — that's a
docker/WSL2 port-publishing quirk, not a defect in the push pipeline, and wasn't resolved this
session (would need `docker` group access or `docker compose logs technitium-dns` to diagnose).

## How to run it going forward

Two processes, both need to be running at the same time:

```bash
python3 scripts/technitium_push_listener.py --host 172.20.0.1 --port 8787
python3 dashboard/server.py
```

To stop the listener: `pkill -f technitium_push_listener.py` (or `kill <pid>` from `ps aux`).

## How to use new API-Key

run this script to display use case message and then follow it to set new api key.

```bash
./scripts/setup_pushlogger.sh --help
```
