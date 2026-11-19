# Audit — Training page label / unlabel (2026-11-18)

Auditors: Agent 1 (static code audit), Agent 2 (live test against the running dashboard at `127.0.0.1:9000`, demo mode), Agent 3 (verification of root causes in code, consolidation, fix proposals).
No source file was modified by this audit. All fixes in section 6 are proposals only.

## 1. Summary & verdict

**Short answer:** the `/training` page has no per-item label/unlabel feature at all. The dashboard's real labelling mechanism is the **Alerts page verdict** (exported as training labels via `/api/feedback/export`). On that mechanism, **labelling works end-to-end** (UI → POST → atomic JSON persist → survives reload → appears in the training export) but **unlabelling does not exist** (no UI control, no endpoint, `verdict: null` is rejected with 400). The audit also found one **High** data-integrity defect: a verdict can be set on a well-formed but **nonexistent** alert fingerprint, which creates an orphan record that is exported as a training label.

| Capability | Result | Evidence |
|---|---|---|
| `/training` per-item **label** | **ABSENT** (FAIL) | No control in `training-gui/api/static/index.html`; no route in `training-gui/api/main.py`; `POST /training/api/label` → 404 (A1, A4–A6). Only run-level `pcap_label` (index.html:89, sent at :166). |
| `/training` per-item **unlabel** | **ABSENT** (FAIL) | Same as above; no endpoint, no UI. |
| Alerts verdict **label** | **WORKS** (PASS) with defects | B1–B4, B12 pass. Defects: B16 nonexistent fp accepted (High), B14 double-submit duplicates audit (Low/Medium), B11 no-op re-verdict audited (Low), B13 blank record created by rejected request (Low). |
| Alerts verdict **unlabel** | **NOT POSSIBLE** (FAIL) | No UI (empty option disables Save, alerts.html:660,664); `verdict:null`/`""` → 400 (server.py:453-454); `/unverdict`, `/clear`, `/unlabel` → 404 (server.py:3044). |

Other findings: training console swallows errors and has no in-flight guard on **Start training** (server-side single-job check is racy, job/registry writes are non-atomic and unlocked); `--demo` does not put the training API into demo mode (real training writes the production `models/` folder); no PUT/PATCH/DELETE handlers (501); no HTTP access log anywhere.

## 2. Scope (route, files, endpoints audited)

**Routes**
- `GET /training`, `/training/` — served by `dashboard/server.py` `do_GET` (2579), branch at 2586-2593, from `dashboard/training-gui/api/static/index.html` via `self.send` (no CSP nonce injection).
- `GET|POST /training/api*` — proxied by `proxy_training_api` (server.py:2530-2576) to a private FastAPI app started by `start_training_api` (server.py:3159-3194; uvicorn on 127.0.0.1 port 0, `log_level="error"`, `access_log=False` at 3181), called from `main()` at 3252. Routing: do_GET 2595-2597, do_POST 2788-2790.
- `POST /api/alerts/{fp}/{action}` — `ALERT_FP_RE` (server.py:1378), dispatched in do_POST 2796-2803 → `_alert_action` (3037-3056).
- `POST /api/alerts/bulk` — `_alerts_bulk` (3058-3098).
- `GET /api/feedback/export[?format=csv|ndjson]` — server.py:2683-2697, rows from `feedback_rows` (989-1013), labels from `VERDICT_TO_LABEL` (985-986).

**Files**
- `dashboard/server.py` (Store, validation, routing, proxy, export)
- `dashboard/alerts.html` (verdict UI, `apiPOST`, `doAction`, bulk)
- `dashboard/training-gui/api/static/index.html` (212 lines, training console)
- `dashboard/training-gui/api/main.py` (138 lines, FastAPI routes)
- `dashboard/training-gui/core/jobs.py`, `core/registry.py`, `core/settings.py`
- Data: `dashboard/data/alert_management.json`, `dashboard/data/audit_log.json`, `dashboard/data/analysts.json`; `dashboard/training-gui/gui_data/` (datasets, runs, registry.json)

**Training API endpoints** (main.py, all `Depends(admin)` except `/`): `GET /api/config` (56), `GET /api/datasets` (61), `POST /api/datasets` (66), `GET /api/datasets/{name}/validate` (83), `POST /api/train` (88), `GET /api/jobs` (97), `GET /api/jobs/{run_id}` (102), `POST /api/jobs/{run_id}/cancel` (108), `GET /api/models` (113), `GET /api/models/{version}/compare` (118), `POST /api/models/{version}/promote` (123), `POST /api/models/rollback` (128), `GET /` (133), static mount (138). **No label/unlabel endpoint.**

## 3. Code audit findings (from Agent 1)

All line numbers below were re-verified by Agent 3 with `grep -n` / `sed -n` on 2026-11-18.

**3.1 /training console**
- Sign-in gate (index.html:50-54, `signin` handler :132); `api()` wrapper :123-131 adds `X-Admin-Token`, throws on non-2xx, clears token on 401.
- Tabs Data / Train / Runs / Models call only dataset, train, jobs, models endpoints listed in section 2.
- The only label-related controls are run-level: `<select id="pl">` (:89; `""`=Unlabeled, `"0"`=Benign, `"1"`=Attack) and `#ah` "Allow heuristic labels" (:95), sent as `pcap_label` / `allow_heuristic_labels` in the train body (:166). Server side: `TrainRequest.pcap_label: Literal["", "0", "1"]` (main.py:48), `allow_heuristic_labels: bool` (:49). These label whole `.pcap` inputs for one run; they are not per-sample labels and cannot be "unlabelled" afterwards.
- Swallowed errors: initial token check `.catch(()=>{})` (:134); `loadAll` tab loader `.catch(()=>{})` (:208); runs poller `.catch(()=>{})` (:209); cancel handler has no try/catch (:187); `compare()` has no try/catch (:195-196).
- No button is disabled while a request is in flight (Start training :97/:163-169).
- Auth: `admin` dependency (main.py:20-22) compares `X-Admin-Token` with `S.ADMIN_TOKEN` (settings.py:24, default `"admin"`). `guarded()` (main.py:25-32) maps FileNotFound/KeyError→404, RuntimeError/ValueError→409. The dashboard's `check_request` (server.py:1484-1511) requires the header to be present for POST `/training/api*` (1504-1507) and loopback Host.
- Persistence: `training-gui/gui_data/` — `runs/<id>/job.json` written with plain `write_text` (core/jobs.py:103), cancel marker (jobs.py:111), registry `_save` plain `write_text` (core/registry.py:21). No locks, no tmp+replace.
- `start_job` (jobs.py:66) checks `running_job()` (:69-70) but `job.json` (what `list_jobs`/`running_job` scan, :57, :62-63) is only written at :103 after `Popen`; no lock → check-then-act race.
- Mode: `TRAINGUI_MODE` defaults to `"capstone"` (settings.py:12); production dir `<repo>/models` in capstone mode (settings.py:19). server.py `--demo` (3218, 3241-3242) only sets `STATE.mode`; it never sets `TRAINGUI_MODE`.

**3.2 Real labelling = Alerts verdict**
- UI (alerts.html:657-666): `<select>` with `<option value="">— choose —</option>` (:660), reason input (:663), **Save verdict** `disabled=${!verdict}` → `onAction("verdict",{verdict, reason}).then(...).catch(()=>{})` (:664), "Current: …" line (:666). No "Clear verdict" control.
- `doAction` (alerts.html:1064-1068) → `apiPOST('/api/alerts/{fp}/{action}', {actor, ...payload})` then `refresh()`. `apiPOST` (alerts.html:278-284) sets `X-SOC-Request: 1`, throws on non-2xx. No in-flight flag anywhere. Bulk: `runBulk` → `apiPOST("/api/alerts/bulk", …)` (alerts.html:893).
- Server: `ALERT_FP_RE = ^/api/alerts/([0-9a-f]{8,32})(/[a-z]+)?$` (server.py:1378). `_alert_action` (3037-3056): `_json_body` → `_actor` (1418-1427, only ids in analysts.json else `unknown-analyst`) → `_find_alert_by_fp` (3043; result only used as a hint) → action allow-list (3044) → `authorize` (1437-1446; `PERMISSIONS["verdict"]=1`, server.py:211-216) → `STORE.apply_alert_action` (483-498) → `EXPORTS.trigger()` (3055).
- `Store._apply_one_locked` (375-481) first calls `ensure_alert_record` (377 → 341-367, get-or-create, inserts into the cache), **then** validates. Verdict branch 451-470: `verdict ∈ VALID_VERDICTS` (198-199), reason ≤ 4096 bytes, Tier 1 FP on High/Critical → 403, then unconditional overwrite and `VERDICT_SET old→new` audit entry (470).
- `apply_alert_action` returns early on non-200 (488-490) without removing the record created at 377; the cache is persisted wholesale on the next successful write (491, 339, 528).
- `Store` (235) is lock-protected; `_atomic_write` (310-326) = tmp + fsync + `.bak` copy + `os.replace`. `STORE_DIR` (163) = `SOC_DASHBOARD_DATA_DIR` or `dashboard/data`; alerts file (165). `--demo` uses the same store as production.
- Export: `VERDICT_TO_LABEL` (985-986), `feedback_rows` (989-1013) emits one row for every management record with a truthy verdict, whether or not the fp exists in the live feed (`in_live_feed: bool(a)`), `feedback_csv` (1016, formula-injection safe), route 2683-2697.
- `Handler.log_message` is a no-op (2475-2476); uvicorn `access_log=False` (3181).
- Only `do_GET` (2579) and `do_POST` (2782) exist → `BaseHTTPRequestHandler` returns 501 for PUT/PATCH/DELETE.

**3.3 Line numbers from Agent 1 that differ from verified code**
- Verdict validation starts at **453** (branch `elif action == "verdict":` at 451); `VERDICT_SET` audit append at **470**. Matches "451-470".
- `_alert_action` is **3037-3056** (Agent 1: ~3038-3058); `_alerts_bulk` is **3058-3098** (Agent 1: ~3060-3100). Off by 1-2.
- `PERMISSIONS` starts at **211** (Agent 1: ~212).
- The record is created at **server.py:377** (`ensure_alert_record`, defined 341-367) — not cited by Agent 1; this is the B13/B16 root cause.
- main.py "route at 138" is the static mount (`app.mount("/static", …)`), not an API route; the last route is `GET /` at 133.
- All other cited lines (198, 235, 310, 985, 989, 1016, 1378, 1418, 1437, 2475, 2530, 2579, 2683, 2782, 3159, 3252; alerts.html 278-284, 657-666, 1064-1068, 893; index.html 89, 95, 166, 187, 196, 208; jobs.py 103, 111; registry.py 21) are correct.

## 4. Live test results — PASS/FAIL table with evidence (from Agent 2)

**Environment.** Dashboard already running at `http://127.0.0.1:9000` in demo mode ("DNS Detect Live"), not started by the auditors; server console not visible and there is no access log (section 5, I10). Built-in browser pane was hidden (0x0), so evidence is DOM text, network log and `fetch` results — no screenshots. Backup taken **before** any write: `C:\Programming-CTF\Capstone\outputs\audit_backup_2026-11-18\` (`alert_management.json` 2391 B, `audit_log.json` 3219 B).
Test alerts: `91a5916eb0d13747` (Medium, DNS Tunneling, no prior verdict); `86647bcb6aa5fcfa` (second, unlabelled); `1479a32b65f7a5d4` (High). Initial state: 150 alerts in rolling demo feed (68 High / 82 Medium), 0 with verdicts, export total 0, 4 management records, 9 audit entries. Actor `analyst-1` (Tier 1).
`/training` initial state: sign-in gate; Data tab shows 1 dataset "Project default (data/raw)"; Train tab has `ds`, `tp`, `pb`, `rt`, `pl` selects + seed + `ns`, `ah`, Start training; Runs "No runs yet"; Models "No finished runs yet" + Roll back; no class counts shown.

### 4.1 Part A — `/training`

| ID | Test | Result | Evidence |
|---|---|---|---|
| A1 | Per-item label / unlabel controls exist on `/training` | **FAIL (absent)** | DOM: only run-level `#pl` (Unlabeled/Benign/Attack for .pcap) and `#ah`; no per-row label/unlabel anywhere in Data/Train/Runs/Models. |
| A2 | `GET /training/api/jobs` with token | PASS | 200 `[]` |
| A3 | `GET /training/api/jobs` without token | PASS | 401 `{"detail":"Invalid admin token"}` |
| A4 | `POST /training/api/label` | PASS (no such endpoint) | 404 |
| A5 | `POST /training/api/unlabel` | PASS (no such endpoint) | 404 |
| A6 | `POST /training/api/datasets/x/label` | PASS (no such endpoint) | 404 |
| A7 | `DELETE /training/api/jobs` | PASS | 501 "Unsupported method ('DELETE')" |
| A8 | Browser console | PASS | Only errors caused by the probes themselves. |

### 4.2 Part B — Alerts verdict (the real labelling path)

| ID | Test | Result | Evidence |
|---|---|---|---|
| B1 | Label via UI: `true_positive`, reason "audit test" on `91a5916eb0d13747` | PASS | 1 × `POST /api/alerts/91a5916eb0d13747/verdict` → 200 `{"ok":true,"record":{…"verdict":"true_positive","verdict_reason":"audit test","verdict_by":"analyst-1"}}`; UI "Current: True positive by analyst-1 · 22:39". |
| B2 | Persists after page reload | PASS | Same "Current:" line after reload. |
| B3 | Appears in training export | PASS | `/api/feedback/export` total 1, `label: 1`. |
| B4 | On disk + audit | PASS | `alert_management.json` has verdict; `audit_log.json` `VERDICT_SET None → true_positive`. |
| B5 | Unlabel via UI | **FAIL** | No "Clear verdict" control; choosing "— choose —" disables Save. |
| B6 | API `{"verdict": null}` | FAIL (as unlabel) | 400 "verdict must be one of (...)". |
| B7 | API `{"verdict": ""}` | FAIL (as unlabel) | 400 same. |
| B8 | `POST …/unverdict`, `…/clear`, `…/unlabel` | FAIL (as unlabel) | 404 `{"error":"unknown action"}`. |
| B9 | Bulk `verdict: null` | FAIL (as unlabel) | 200 envelope, `succeeded 0, failed 1`, item code 400. |
| B10 | Is unlabel possible at all? | **FAIL** | No — verdict remains `true_positive`. |
| B11 | Same-value re-label (`true_positive` again) | PASS with defect | 200; adds a no-op audit entry `true_positive → true_positive`. |
| B12 | Overwrite to `false_positive`, then back | PASS | 200, export `label 0`; back to `true_positive` 200, `label 1`. |
| B13 | `verdict: null` on unlabelled `86647bcb6aa5fcfa` | PASS with side effect | 400, no verdict, no audit — **but** the rejected request created a blank management record (verdict null) that was persisted on the next successful write. |
| B14 | Rapid double-click Save verdict | **FAIL** | 2 POSTs, both 200; audit entries for the fp 4 → 6 (two identical `VERDICT_SET` at 15:40:35). |
| B15 | Malformed fp `zzzz` | PASS | 404. |
| B16 | Nonexistent well-formed fp `deadbeefdeadbeef00` | **FAIL** | 200; orphan record created (verdict `true_positive`, rule/severity null) + audit entry; appears in training export with `label 1`. |
| B17 | Invalid verdict `banana` | PASS | 400. |
| B18 | Missing `X-SOC-Request` header | PASS | 403. |
| B19 | Actor `unknown-person` | PASS | 403 (resolved to `unknown-analyst`, Tier 0). |
| B20 | Tier 1 `false_positive` on High `1479a32b65f7a5d4` | PASS | 403 (also via UI for `fp_model_logic`). |
| B21 | UI error surfacing | PASS | UI shows "Last action failed: …" despite `.catch(()=>{})` at the call site. |
| B22 | Browser console | PASS | Clean apart from probe-induced errors. |

### 4.3 Test residue (state left on disk / in memory)

- `dashboard/data/alert_management.json`: **7 records** (was 4):
  - `91a5916eb0d13747` — verdict `true_positive` by `analyst-1` (test label)
  - `86647bcb6aa5fcfa` — blank record (from B13 / B9)
  - `deadbeefdeadbeef00` — orphan, verdict `true_positive`, **currently exported as a training label = 1**
- `dashboard/data/audit_log.json`: **17 entries** (was 9).
- In-memory only: blank record for `1479a32b65f7a5d4` (from B20's rejected request) — will be written to disk by the next successful alert write unless the server is restarted after restore.
- The server's own `.bak` files (`alert_management.json.bak`, `audit_log.json.bak`) now hold mid-test state, not the original.

**Restore procedure:** (1) stop the dashboard server (so its in-memory cache cannot overwrite the files); (2) copy `alert_management.json` and `audit_log.json` from `C:\Programming-CTF\Capstone\outputs\audit_backup_2026-11-18\` into `C:\Programming-CTF\Capstone\dashboard\data\` (overwrite); (3) optionally also overwrite the two `.bak` files with the same backup copies; (4) restart the server; (5) confirm `GET /api/feedback/export` → `total: 0` and the management file has 4 records. Note: the audit log is append-only by design; restoring it removes the audit evidence of this test — keep the current `audit_log.json` aside (e.g. in the backup folder as `audit_log.after_test.json`) if the evidence should be retained. No training job was started, so `training-gui/gui_data/` and `models/` are untouched.

## 5. Issues found — severity, root cause, file:line

| ID | Test(s) | Severity | Verified location | Root cause |
|---|---|---|---|---|
| I1 | B16 | **High** | server.py:3043 (`alert_hint = _find_alert_by_fp(fp) or {}` — result never used to reject); server.py:377 → 341-367 (`ensure_alert_record` get-or-create); bulk server.py:3084-3086 (same; additionally bulk `fps` are only checked with `isinstance(f, str)` at 3084 — no `ALERT_FP_RE`-style format check, so any string up to 200 per call becomes a record key); export server.py:995-997 (`feedback_rows` exports every record with a verdict, `in_live_feed` false is only a flag) | No existence check: any 8-32 hex fp matching `ALERT_FP_RE` (1378) gets a management record and a verdict, and the orphan is exported as a training label. Poisons training data; also unbounded record creation. |
| I2 | B5-B10 | **Medium** (missing feature) | server.py:453-454 (null/"" rejected), 3044 (action allow-list has no clear action), 467-470 (verdict only ever overwritten); alerts.html:660, 664 (empty option disables Save; no Clear button); bulk server.py:3073-3076 (no clear mapping) | Unlabel was never designed: no API, no UI, no audit action. A wrong label can only be overwritten with another label, never withdrawn from the training export. |
| I3 | B14 | Low/Medium | alerts.html:664 (no in-flight guard on Save), 1064-1068 (`doAction` no de-dupe), 278-284 (`apiPOST`); server.py:466-470 (no idempotency) | Double-click sends two POSTs; server applies both and appends two identical `VERDICT_SET` entries. Same pattern for every alert action button. |
| I4 | B11 | Low | server.py:466-470 | Verdict branch always writes `verdict_by/at` and appends `VERDICT_SET` even when `old_verdict == verdict` and reason unchanged; also silently re-attributes the label to the latest actor. |
| I5 | B13, B9 | Low | server.py:377 (record created before validation at 453); 488-490 (early return leaves record in cache); 491/339/528 (whole cache persisted later); bulk server.py:528 persists unconditionally even when every item failed | Get-or-create happens before validation and is not rolled back on 4xx, so rejected requests leave blank records that are later persisted. |
| I6 | — (code) | Medium | index.html:163-169 (Start training, no disable/in-flight guard); core/jobs.py:69-70 vs 103 (check-then-act: `running_job()` scans `job.json`, written only after `Popen`), no lock; jobs.py:103, 111 and registry.py:21 non-atomic `write_text` | A double-click or two tabs can launch two concurrent training jobs (both pass the check before either writes `job.json`) that both write to the production models dir; a crash mid-write can leave a truncated `job.json` / `registry.json`. |
| I7 | — (code) | Low | index.html:134, 187, 195-196, 208, 209 | Errors swallowed (`.catch(()=>{})`) or unhandled (cancel, compare): user gets no feedback when a load/cancel/compare fails. |
| I8 | — (code) | Medium/Info | server.py:3241-3242 (`--demo` only sets `STATE.mode`), 3252; training-gui/core/settings.py:12, 19, 27 | `--demo` does not set `TRAINGUI_MODE=demo`; the training API stays in capstone mode, runs the real trainer and writes `<repo>/models` (production) even in a demo session. |
| I9 | A7 | Info | server.py: only `do_GET` (2579) and `do_POST` (2782) | No PUT/PATCH/DELETE handlers → 501. Acceptable by design; relevant only because an unlabel endpoint must be a POST action. |
| I10 | — | Info | server.py:2475-2476 (`log_message` no-op); 3181 (`access_log=False`) | No HTTP access log for the dashboard or the proxied training API; live testing had to rely on browser network logs. The JSON audit trail covers only state changes. |
| I11 | A1, A4-A6 | Info / design | training-gui/api/main.py (no route), index.html (no control) | Per-item labelling on `/training` does not exist; only run-level `pcap_label`. Open design question (section 7). |

## 6. Proposed fixes (not yet applied)

> **Update 2026-11-20:** F1, F2, F3, F4, F5 and F8 are applied (Week 7 Task 10). Tests: `tests/test_dashboard_verdicts.py`. The test record `deadbeefdeadbeef00` was removed from `dashboard/data/alert_management.json` (backup `*.before-cleanup-*`, audit action `RECORD_REMOVED`). F6 is partly done (a second job gets 409); F7 and F10 are still open.

Nothing below has been applied. Snippets are sketches against the verified lines; adapt names as needed. Suggested order: F1 → F5 → F2 → F3/F4 → F6 → F8 → F7 → F10.

### F1 — Reject verdicts/actions on unknown alerts (fixes I1 / B16) — High

**Where:** server.py `_alert_action` 3042-3044 and `_alerts_bulk` 3084-3086; alert set lives in `STATE.alerts_data["alerts"]` (read via `_find_alert_by_fp` 1528-1535 / `_live_alerts` 1651-1653); existing records in `STORE._cache["alerts"]["records"]` (`STORE.get_alert_mgmt` 329-331).
Because the demo feed rolls and real alerts age out, "exists" must mean **in the live feed OR already has a management record** (so analysts can still update an alert that left the feed).

```python
# server.py, new helper near _find_alert_by_fp (≈1536)
FP_HEX_RE = re.compile(r"^[0-9a-f]{8,32}$")

def alert_known(fp, live=None):
    if not isinstance(fp, str) or not FP_HEX_RE.match(fp):
        return False
    if (live is not None and fp in live) or (live is None and _find_alert_by_fp(fp)):
        return True
    return STORE.get_alert_mgmt(fp) is not None
```
```diff
 # _alert_action (3042-3044)
         actor = _actor(body)
-        alert_hint = _find_alert_by_fp(fp) or {}
+        alert_hint = _find_alert_by_fp(fp) or {}
+        if not alert_hint and STORE.get_alert_mgmt(fp) is None:
+            self.send_json(404, {"error": "unknown alert"})
+            return
```
```diff
 # _alerts_bulk (3084-3086)
-        fps = [f for f in fps[:200] if isinstance(f, str)]
-        live = {fp_hex(a): a for a in _live_alerts()}
+        live = {fp_hex(a): a for a in _live_alerts()}
+        fps = [f for f in fps[:200] if isinstance(f, str)]
+        unknown = [f for f in fps if not alert_known(f, live)]
+        fps = [f for f in fps if f not in unknown]
         ...
+        # report each unknown fp as {"fp": f, "code": 404, "ok": False, "error": "unknown alert"}
```
Defence in depth (optional): in `feedback_rows` (995-997) skip rows whose record has neither `rule_name` nor a live alert, or add `"orphan": True` and exclude orphans from the training CSV by default.
Also check case/triage callers of `apply_case_action` use known fps (they derive fps from the feed, so they should).
**Data cleanup:** remove `deadbeefdeadbeef00` (restore from backup, section 4.3).
**Test:** `POST /api/alerts/deadbeefdeadbeef00/verdict {"actor":"analyst-1","verdict":"true_positive"}` → 404, `alert_management.json` unchanged, export total unchanged; bulk with `["deadbeefdeadbeef00","not-hex!"]` → 200 envelope, both items code 404, no records created; a real fp still → 200; an fp that has a record but has left the feed → 200.

### F2 — Add "unlabel" (clear verdict) (fixes I2 / B5-B10) — Medium

**Design:** a new POST action, because the server has only `do_POST` (2782) and `ALERT_FP_RE` (1378) allows exactly one lowercase segment `(/[a-z]+)?` — so `/clearverdict` matches (hyphens/underscores would not). Endpoint: `POST /api/alerts/{fp}/clearverdict` body `{"actor": "...", "reason": "optional"}`. Same permission tier as setting a verdict (Tier 1+). Audit action `VERDICT_CLEARED old→None`. Triggers `EXPORTS.trigger()` so the fp disappears from `/api/feedback/export`. Clearing when there is no verdict → 409 (or 200 no-op without audit; pick one, 409 recommended so double-clicks are visible). Optional guard: Tier 1 may only clear a verdict they set, or one on a non-High alert; Tier 2+ may clear any (mirrors the reopen rule at 412-414).
Alternative (not recommended): accept `{"verdict": null}` on `/verdict` — overloads validation, easier to trigger by accident (an empty select).

```diff
 # server.py PERMISSIONS (211-216)
-    "claim": 1, "release": 1, ...
+    "claim": 1, "release": 1, "verdict_clear": 1, ...
```
```diff
 # server.py _apply_one_locked, new branch after the verdict branch (after 470)
+        elif action == "verdict_clear":
+            old_verdict = rec.get("verdict")
+            if old_verdict is None:
+                return 409, {"error": "this alert has no verdict to clear"}, []
+            reason = payload.get("reason")
+            if reason is not None and (not isinstance(reason, str)
+                                       or len(reason.encode("utf-8")) > NOTE_MAX_BYTES):
+                return 400, {"error": f"reason must be a string up to {NOTE_MAX_BYTES} bytes"}, []
+            if tier < 2 and rec.get("verdict_by") not in (actor, None):
+                return 403, {"error": "only Tier 2+ or the analyst who set it can clear this verdict",
+                             "required_tier": 2}, []
+            for k in ("verdict", "verdict_reason", "verdict_by", "verdict_at", "verdict_approved_by"):
+                rec[k] = None
+            audit_entries.append(("VERDICT_CLEARED", old_verdict, None))
```
```diff
 # server.py _alert_action (3044-3047)
-        if action not in ("acknowledge", "assign", "status", "escalate", "notes", "verdict"):
+        if action not in ("acknowledge", "assign", "status", "escalate", "notes", "verdict", "clearverdict"):
             ...
-        action_internal = "note" if action == "notes" else action
+        action_internal = {"notes": "note", "clearverdict": "verdict_clear"}.get(action, action)
```
```diff
 # server.py bulk: VALID_BULK_ACTIONS (191) add "clearverdict"; action_map (3073-3076) add "clearverdict": "verdict_clear"
```
Also update the `apply_alert_action` docstring (486) and `WORKFLOW["require_verdict"]` interplay: clearing a verdict on a Resolved/Closed alert when `--require-verdict` is on should be refused with 409 or should reopen the alert — decide (section 7).

```diff
 // alerts.html after the Save verdict button (664)
+            ${alert.mgmt?.verdict ? html`<button class="btn btn-sec" disabled=${busy}
+               onClick=${()=>{ if(confirm("Remove this verdict? It will be withdrawn from the training export."))
+                 onAction("clearverdict",{reason:vReason}).then(()=>{setVerdict(""); setVReason("");}).catch(()=>{}) }}>
+               Clear verdict</button>` : null}
```
Bulk menu: add a "Clear verdict" option posting `{action:"clearverdict"}` to `/api/alerts/bulk`.
**Tests:** label fp → export total 1; `POST /api/alerts/{fp}/clearverdict` → 200, record verdict fields null, audit `VERDICT_CLEARED true_positive→null`, export total 0, survives reload/restart; clear again → 409; actor `unknown-person` → 403; Tier 1 clearing another analyst's verdict → 403, Tier 2 → 200; bulk clearverdict on 2 fps → succeeded 2; UI button visible only when a verdict exists; unknown fp → 404 (F1).

### F3 — In-flight guard on Save verdict / alert actions (fixes I3 / B14) — Low/Medium

**Where:** alerts.html `doAction` 1064-1068 and the button at 664 (and other action buttons).
```diff
+  const inFlight = useRef(new Set());
   const doAction = useCallback(async (fp, action, payload)=>{
+    const key = fp + "/" + action;
+    if (inFlight.current.has(key)) return;          // drop the second click
+    inFlight.current.add(key); setBusy(true);
     const body = Object.assign({actor: currentActor()}, payload||{});
-    await apiPOST(`/api/alerts/${encodeURIComponent(fp)}/${action}`, body);
-    refresh();
+    try { await apiPOST(`/api/alerts/${encodeURIComponent(fp)}/${action}`, body); refresh(); }
+    finally { inFlight.current.delete(key); setBusy(false); }
   }, [refresh]);
```
and `disabled=${!verdict || busy}` on Save verdict. Server-side defence is F4 (idempotent same-value write).
**Test:** double-click Save → exactly 1 POST in the network log, audit count +1; programmatic two parallel POSTs → second is a no-op after F4.

### F4 — Make same-value re-verdict a no-op (fixes I4 / B11, backs up F3) — Low

**Where:** server.py 466-470.
```diff
             old_verdict = rec.get("verdict")
+            new_reason = (reason or "").strip() or None
+            if old_verdict == verdict and rec.get("verdict_reason") == new_reason:
+                return 200, {"ok": True, "record": rec, "unchanged": True}, []
             rec["verdict"] = verdict
-            rec["verdict_reason"] = (reason or "").strip() or None
+            rec["verdict_reason"] = new_reason
```
Note: `apply_alert_action` (491) still rewrites the file on 200; optionally skip `_atomic_write`/`STATE.bump()` when `audit_entries` is empty. If a changed reason with same verdict should be audited, add `VERDICT_REASON_CHANGED`.
**Test:** set `true_positive` twice with the same reason → 2 × 200, audit +1 only, `verdict_by`/`verdict_at` unchanged on the second call.

### F5 — Do not create records for rejected requests (fixes I5 / B13, B9) — Low

**Where:** server.py 377 (`ensure_alert_record`), 488-490, bulk 528.
Option A (smallest): remember whether the record was created and roll back on non-200.
```diff
 # _apply_one_locked (377)
-        rec = self.ensure_alert_record(fp, seed_from_alert=alert_hint)
+        created = fp not in self._cache["alerts"]["records"]
+        rec = self.ensure_alert_record(fp, seed_from_alert=alert_hint)
+        code, body, entries = self._apply_action_to_rec(rec, ...)   # current body of the function
+        if code != 200 and created:
+            self._cache["alerts"]["records"].pop(fp, None)
+        return code, body, entries
```
Option B: build the default record in a local variable and only insert it into the cache after validation succeeds.
Also in `apply_case_action` (528) skip `_atomic_write` when `ok == 0` and nothing changed.
**Test:** `POST …/86647bcb6aa5fcfa/verdict {"verdict":null}` on a fresh fp → 400, then any successful action on another fp → `alert_management.json` contains no record for `86647bcb6aa5fcfa`; bulk with only invalid items → file mtime unchanged.

### F6 — Training console: single in-flight Start, atomic + locked writes (fixes I6) — Medium

**UI** (index.html:163-169):
```diff
 $("start").onclick=async()=>{
+  const b=$("start"); if(b.disabled)return; b.disabled=true; $("tmsg").textContent="Starting…";
   try{ ... }
   catch(e){ ... }
+  finally{ b.disabled=false }
 };
```
**Server** (core/jobs.py:66-103): serialize `start_job` with a module lock and write `job.json` atomically.
```diff
+import threading
+_start_lock = threading.Lock()
+
+def _atomic_write_text(path, text):
+    tmp = path.with_suffix(path.suffix + ".tmp")
+    tmp.write_text(text); os.replace(tmp, path)
+
 def start_job(dataset, train_path="both", params=None):
-    if running_job():
-        raise RuntimeError("Another training job is already running. Wait or cancel it.")
-    ...
+    with _start_lock:
+        if running_job():
+            raise RuntimeError("Another training job is already running. Wait or cancel it.")
+        ...  # mkdir, Popen
+        _atomic_write_text(d / "job.json", json.dumps(job, indent=2))   # was :103
```
Same `_atomic_write_text` for registry `_save` (core/registry.py:21) plus a lock around load-modify-save in promote/rollback/sync. (This only protects one process; two dashboard instances would still need a file lock.)
**Test:** fire two `POST /training/api/train` concurrently (e.g. `Promise.all`) → one 200, one 409 "already running"; `GET /jobs` shows one running job; kill the process mid-write in a unit test → `job.json` is either old or new, never truncated. Use demo mode (F8) for this test so production models are not touched.

### F7 — Surface training-console errors (fixes I7) — Low

index.html:208/209: replace `.catch(()=>{})` with a handler writing to a status line, e.g. `.catch(e=>showErr(e))` where `showErr` sets a visible `<p class=err>`; :187 wrap cancel in `try{…}catch(e){showErr(e)}`; :195-196 same for `compare()`. Keep the 401 path (already handled in `api()` :127).
**Test:** stop the training API (or return 500 from a stub) → each tab shows an error message instead of stale/empty content.

### F8 — `--demo` should put the training API in demo mode (fixes I8) — Medium/Info

**Where:** server.py 3241-3242, before `start_training_api()` at 3252 (settings.py reads env at import time, settings.py:12).
```diff
     if args.demo:
         STATE.mode = "demo"
+        os.environ.setdefault("TRAINGUI_MODE", "demo")   # must be set before api.main is imported
```
Optionally show the mode in the training UI (`GET /api/config` already exists, main.py:56).
**Test:** start with `--demo`, `GET /training/api/config` → mode `demo`, production dir under `gui_data/`, not `<repo>/models`; start a run and confirm `<repo>/models` mtime unchanged.

### F9 — PUT/PATCH/DELETE (I9) — Info, no change required

Keep POST-only actions (consistent with CSRF header model). Optionally add `do_PUT/do_PATCH/do_DELETE` that return 405 with `Allow: GET, POST` instead of the default 501.

### F10 — Access logging (I10) — Info

Replace the no-op `log_message` (2475-2476) with a minimal stderr or rotating-file logger (method, path without query, status, ms), and set uvicorn `access_log=True` (3181) behind a `--access-log` flag. Do not log bodies or the `X-Admin-Token` header.
**Test:** one request → one log line; token value never appears in the log.

## 7. Open questions / next steps

1. **Should `/training` get per-sample labelling at all?** Today labels for training come from two places: run-level `pcap_label` on `/training`, and per-alert verdicts on the Alerts page exported via `/api/feedback/export`. Options: (a) keep `/training` run-level only and document that per-item labelling happens on Alerts (lowest effort); (b) add a "Feedback labels" view on `/training` that reads `/api/feedback/export`, shows counts per label, and lets a Tier 2+ user include/exclude rows from a training dataset (no new labelling store); (c) full per-sample labelling of dataset rows inside the training GUI (new store, new endpoints, audit — largest effort, duplicates the Alerts workflow). Recommendation: (b). **Decision needed from the user.**
2. **Unlabel semantics:** should clearing a verdict be allowed for Tier 1 on others' verdicts? Should it be refused (409) or reopen the alert when `--require-verdict` is on and the alert is Resolved/Closed? Should `undetermined` be used instead of a true clear?
3. **Existence rule for F1:** confirm that "in live feed OR already has a management record" is the desired definition, given the rolling demo feed and alert ageing.
4. **Export hygiene:** after F1, decide whether existing orphans (records with no rule/severity and not in feed) should be purged automatically or flagged in the export.
5. **Restore the test residue** (section 4.3) before any further evaluation or training run — the orphan `deadbeefdeadbeef00` is currently exported as an attack label.
6. **Re-test after fixes:** re-run A1-A8 and B1-B22 plus the new tests listed under F1-F8 (unlabel round-trip, unknown fp 404, double-click single POST, concurrent train 409, demo-mode training isolation).
7. Change the default training `ADMIN_TOKEN` (`"admin"`, settings.py:24) for any non-demo use; the dashboard already refuses a default token on non-loopback binds (server.py main()).
