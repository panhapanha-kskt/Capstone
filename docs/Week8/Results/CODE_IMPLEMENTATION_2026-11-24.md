# Week 8 code implementation record

**Date:** 2026-11-24  
**Status:** code changed and focused tests passed; authenticated identity and live integration remain open.

## Implemented

| Finding | Code change | Verification |
|---|---|---|
| A11 | [`dashboard/server.py`](../../../dashboard/server.py) now checks a verdict, completed stored case checklist, and Tier 2 authorization for a High/Critical false-positive verdict when an alert transitions to `Closed`. The same write check applies to case, single-alert, and bulk routes. Bulk actions preflight the known requested alerts and abort their writes if one fails; unknown IDs retain the existing per-item response behavior. | Updated SOC, triage, and verdict tests; focused suite below. |
| A10 | Removed `_approved_by` as a Tier 1 exemption inside the alert verdict helper. The HTTP input sanitizer and its existing regression remain in place. | Existing forged-metadata route tests and the focused suite. |
| A16 | `/api/run` checks the `run` permission (Tier 2) before rate limiting, successful audit, or scheduling a pipeline run. | SOC route test covers Tier 1 and unknown denial, Tier 2 allow, repeat-request rate limit, and audit actor. |
| A12 | [`core/settings.py`](../../../dashboard/training-gui/core/settings.py), [`api/main.py`](../../../dashboard/training-gui/api/main.py), and [`streamlit_app.py`](../../../dashboard/training-gui/streamlit_app.py) disable training administration when `ADMIN_TOKEN` is missing or a known placeholder (`admin`, `change-me`); API returns 503 until configured. Configured tokens use constant-time comparison. Training console documentation was updated. | New [`test_training_admin_auth.py`](../../../tests/test_training_admin_auth.py) checks disabled and configured cases. |
| A4 | [`splits.py`](../../../src/dns_detect/models/splits.py) and [`dns_parser.py`](../../../src/dns_detect/parsing/dns_parser.py) parse mixed timestamp formats and normalize naive and offset-aware values to UTC before ordering. Invalid timestamps retain the existing row-index fallback. The parser's CRLF line endings were preserved. | New split regression and [`test_dns_parser_timestamps.py`](../../../tests/test_dns_parser_timestamps.py) cover mixed precision, offsets, and fallback. |
| A9 | Root [`README.md`](../../../README.md) now identifies Isolation Forest as the current `train_models.sh` Path B default. | Checked against `PATH_B_TYPE="iforest"` in [`train_models.sh`](../../../scripts/train_models.sh). |

The implementation agents staged isolated patches, which were reviewed and applied to the repository after the workspace's elevated write approval. The existing user edits in `dashboard/training-gui/api/main.py` and `dashboard/training-gui/core/jobs.py` were preserved; the latter was not changed by this implementation.

## Tests and checks

- Baseline before code changes: **51 passed, 1 skipped** across dashboard SOC/triage, training console, and split strategy tests. The skip was due to missing `httpx`.
- After code changes: **123 passed** across `test_dashboard_soc.py`, `test_dashboard_triage.py`, `test_dashboard_verdicts.py`, `test_training_console.py`, `test_training_admin_auth.py`, `test_splits_strategies.py`, and `test_dns_parser_timestamps.py`.
- `pytest` and `httpx` were installed only in `/private/tmp/week8_testdeps` for verification. Tests used the project's `.venv` Python and local loopback fixtures; dependencies were not added to project requirements.
- The full `tests/` run stopped during collection with ten errors in untouched modules because the available environment is Python 3.9 and those modules evaluate Python 3.10 `dict | None` / `set | None` annotations. This is an environment compatibility limit, not a passing full-suite result.
- `git -c core.whitespace=cr-at-eol diff --check` passes. That setting recognizes the existing CRLF endings in `dns_parser.py`.

## Remaining risk and next work

1. **A1 is still critical.** The server still derives analyst tier from a browser-supplied `actor`. A caller can claim an existing Tier 2 identity, including for `/api/run` and approvals. Add server-authenticated identity and bind audit attribution to it before multi-user or non-loopback deployment. The new tier checks are workflow guardrails until then.
2. **A11 is partially mitigated.** The added `Closed` policy checks do not change the `Resolved` transition; `--require-verdict` still defaults to false. Review the intended resolution policy and whether direct closure should be available when an alert no longer belongs to a live case. Exercise a concurrent close/approval scenario before claiming transaction safety across both stores.
3. **A12 is partially mitigated.** The known training token default is gone, but model administration still uses a shared token. Define a separate authenticated model-admin role, secret provisioning, and rotation. The dashboard can run with training administration disabled until a token is configured.
4. **A4 requires new evaluation.** Corrected timestamp ordering can change split membership and Path B windows. No model was retrained, promoted, or evaluated against the frozen set in this pass. Preserve existing artifacts and rerun candidate evaluation before any model-performance claim.
5. The interface freshness/accessibility work, drift baseline A2, false-alarm target A3, registry A6, external integrations, and real-mode walkthrough remain open in the [implementation blueprint](IMPLEMENTATION_BLUEPRINT.md).

No production SOC actions, external response actions, model promotion, or live Technitium/Elasticsearch verification were performed.
