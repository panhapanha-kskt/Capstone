# Week 8 documentation review and results

**Project:** DNS Traffic Anomaly Detection  
**Review date:** 2026-11-24 (Asia/Phnom_Penh)  
**Scope:** both files present in `docs/Week8/`, with read-only checks of the referenced project source, model card, and tests.

**Follow-on update:** The user then requested codebase implementation. The later source changes, test results, and remaining risks are recorded in [CODE_IMPLEMENTATION_2026-11-24.md](CODE_IMPLEMENTATION_2026-11-24.md). The read-only/source-only statements below describe the initial documentation review, before that follow-on work.

## Work completed

| Work | Result | Evidence |
|---|---|---|
| Inventory and review | Read the complete Week 8 audit and web interface plan; checked their key claims against dashboard, training, parsing, monitoring, and model files. | [`AUDIT_FINDINGS.md`](../AUDIT_FINDINGS.md), [`WEB_INTERFACE_PLAN.md`](../WEB_INTERFACE_PLAN.md) |
| Correct A10 | Reclassified the asserted direct HTTP approval-forgery exploit. `_json_body` removes underscore-prefixed client keys, and the bulk endpoint removes them from its nested payload. An existing test checks both routes. The remaining internal approval-record invariant is a defense-in-depth task. | [`server.py`](../../../dashboard/server.py#L1456), [`test_dashboard_triage.py`](../../../tests/test_dashboard_triage.py#L310) |
| Reconcile priorities | Removed A10 from the confirmed P0 HTTP bypass group in the Week 8 plan; retained A1 and A11 as P0 and listed A10 separately for internal hardening. | [`WEB_INTERFACE_PLAN.md`](../WEB_INTERFACE_PLAN.md) |
| External research | A separate research agent checked current primary guidance on web authorization, incident records, ML monitoring, and accessible interfaces. Recommendations are mapped below. | Source links in the next section |
| Project implementation guide | A separate implementation agent prepared [`IMPLEMENTATION_BLUEPRINT.md`](IMPLEMENTATION_BLUEPRINT.md) with project-specific touchpoints and acceptance criteria. | Review this guide before changing source code. |

## Research applied to this project

1. **Server identity and permission checks (A1, A11, A16).** Bind the actor to an authenticated server-side identity and enforce the same permission and closure rules on every case, single-alert, bulk, and pipeline-run route. A browser-selected analyst ID is insufficient. This follows the [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), and [OWASP API Security 2023 API5](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/).
2. **Incident evidence and response claims (A13, A15).** Store durable, attributable events, case decisions, action outcomes, timestamps, and source references so a case can be reconstructed after restart. Continue to label `SIMULATED` outcomes as such. The relevant guidance is [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) and [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final). Treat raw DNS events and detection alerts as different data sets.
3. **Monitoring and evaluation (A2, A3, A7).** Rebuild the drift baseline from the exact deployed feature schema and representative benign traffic, record dataset and run identity, and compare fusion against fusion on a held-out time-separated set. The promoted model card's 7 false alarms in 1,168 benign queries is approximately 0.60%, above the project's 0.10% target. A saved PSI warning alone does not prove current live drift. See [NIST AI RMF Measure](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/) and its [Measure playbook](https://airc.nist.gov/airmf-resources/playbook/measure/).
4. **Accessible, truthful SOC views.** Make all actions keyboard-operable, manage focus in dialogs, announce status changes, show the last successful refresh, and label retained data stale after failed polling. Check all eight SOC routes at 390, 768, and desktop widths. These are direct applications of [WCAG 2.2](https://www.w3.org/TR/WCAG22/) and the [W3C modal dialog pattern](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/).

## Findings that still determine the work order

| Priority | Findings | Required next implementation evidence |
|---|---|---|
| P0 | A1, A11 | Authenticated Tier 1 and Tier 2 sessions; every write route denies unauthorized actors; one closure policy covers case, single-alert, and bulk paths; second-analyst approval cannot be self-approved. |
| P1 | A12, A16 | No known training-admin default; pipeline run and model promotion require a server-verified operator or model-admin identity. |
| P1 | A2, A3, A4, A6, A7 | Correct feature baseline and timestamp handling, safe registry commit after successful training, direct fusion evaluation, and false-alarm evidence with denominators. |
| P2 | A13, A14, A15 | External action receipt, authenticated device heartbeat with per-metric freshness, durable event/case history. |
| Interface | A8 plus the interface plan | Keyboard, stale-data, responsive, and real-mode walkthrough evidence on all eight routes. |
| Defense in depth | A10 | Preserve the tested HTTP sanitizer and verify internal approval against the persisted independent approval record. |

## Verification and limits

- Source review confirmed `_json_body` strips underscore-prefixed top-level keys, the bulk route strips nested underscore-prefixed payload keys, and `test_legacy_routes_guardrails` asserts that a Tier 1 forged approval is rejected on both HTTP routes.
- Checked all four Week 8 Markdown files after editing: 70 local file links resolve; `git diff --check -- docs/Week8` reports no whitespace errors.
- Attempted `PYTHONDONTWRITEBYTECODE=1 python3 -m pytest ../../tests/test_dashboard_triage.py::test_legacy_routes_guardrails -q -p no:cacheprovider`; it could not run because the available `python3` has no `pytest` module. The prior test file and its documented results are evidence of test coverage, **not** a fresh passing run.
- No live Technitium, Elasticsearch/Kibana, external response connector, or real-mode browser verification was performed in this review. The 2026-11-23 demo findings remain historical evidence only.
- During this initial review, source code outside `docs/Week8/` was inspected read-only. The follow-on code implementation changed project files after separate write approval and preserved the pre-existing modifications in `dashboard/training-gui/api/main.py` and `dashboard/training-gui/core/jobs.py`; see the linked implementation record.
