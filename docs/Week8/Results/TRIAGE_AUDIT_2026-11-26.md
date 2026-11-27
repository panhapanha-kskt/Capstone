# Triage page audit and fixes

**Date:** 2026-11-26
**Scope:** `/triage`, which is `dashboard/triage.html` plus `dashboard/static/js/triage.js`. Server checks were read in `dashboard/server.py` and `dashboard/evidence.py`. No server, detection or training logic changed.

## Findings fixed

| # | Issue | Impact for a SOC analyst | Fix |
|---|---|---|---|
| T1 | **The open case was rebuilt every 5 s.** The queue poll re-fetched it and replaced the whole case pane even when nothing had changed. | Keyboard focus jumped off the checklist or action buttons. Domain and IP lookup results disappeared. A click could land as the pane redrew. | Re-render only when the case data actually changed. When it does change, restore focus to the same control and keep the lookup result. |
| T2 | **A Tier 2 analyst could take over another analyst's case with no prompt.** Pressing **Claim** or the `c` key sent `force: true` straight away. | Another analyst's case changed owner by accident. | Ask for confirmation, naming the current owner, before a takeover. The server's Tier 2 `force_claim` rule is unchanged. |
| T3 | **The queue could show an empty page.** After cases were closed or escalated, the current page could be past the end of the list. | The queue showed "No cases match" even though cases were still open. | If the page is past the end, move to the last page that has cases. |
| T4 | **The close dialog pre-selected a classification.** It picked `fp_model_logic` when the checks suggested closing, otherwise `undetermined`. | The classification becomes the training label for the next retraining. A pre-selected answer carries the suggestion into the labels whenever an analyst accepts the default. | There's no default now. The analyst must choose a classification, and the suggestion appears only as hint text. Focus opens on the classification field. |

## Checked and not a problem

- **Case keys are URL-safe.** The server only accepts `c-` plus 12 hex digits (`TRIAGE_CASE_RE`), so POST URLs are safe without encoding.
- **Evidence fields are always present.** `query_types`, `encodings`, `zscores`, `timeline` and `samples` always come back (`evidence.case_evidence`). Checklist `auto` is null only for manual items, and the escalation pre-fill already handles that case.
- **Takeover is still enforced on the server.** It requires Tier 2 (`force_claim`), and Tier 1 still gets a 409 or 403.

## Verification

- `node --check dashboard/static/js/triage.js`: pass.
- New `tests/test_triage_page.py` (4 tests) checks each fix. Together with `tests/test_dashboard_triage.py` and `tests/test_dashboard_soc.py`: 51 passed.
- A live browser walkthrough through the gateway is still pending. It needs an analyst sign-in in the browser pane.

## Follow-up improvements (implemented)

| # | Improvement | Detail |
|---|---|---|
| T5 | **"Case changed while you had it open" warning** | When the 5 s refresh brings in history entries from **another** analyst (or the system), the case shows an orange banner. It says who did what and when, adds a "+N more" count if there were several, and tells the analyst to re-check status and owner before acting. A short toast also appears. Your own actions and opening a case never trigger it. **Got it** dismisses the banner, and switching cases clears it. |
| T6 | **Investigating status filter** | Added to the status menu. The server already filters on the exact status, so no backend change was needed. |
| T7 | **Priority filter is remembered** | It's saved like the group and status filters (`tri_sev` in localStorage). Choosing a filter from the count chips now saves it as well. |

Verification: `node --check` passes. `tests/test_triage_page.py` now has 6 tests, and with the triage and SOC test files it's 53 passed. A Node run of the change check gave the expected result in all five cases: another analyst's action is flagged; your own action, a different case, a first load and a reordered history are not.
