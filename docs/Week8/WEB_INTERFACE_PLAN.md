# Week 8 web interface improvement plan

**DNS Traffic Anomaly Detection · plan created 2026-11-23**

The Week 8 development scope is the web interface in `dashboard/`. The [audit findings](AUDIT_FINDINGS.md) record model, data, and server concerns for later work. This plan improves how analysts navigate, inspect data, and understand the state the existing APIs provide. It does not treat a display change as a fix for an unreliable source metric or for unauthenticated analyst identity.

## Starting point

The working tree contains shared SOC navigation, mobile layout, status display, an Alerts assignment filter, and Triage queue failure recovery. The eight SOC routes are `/soc`, `/triage`, `/alerts`, `/events`, `/incidents`, `/devices`, `/health`, and `/usecases`. The classic dashboard at `/` and training console at `/training` have separate layouts. The prior dashboard regression run passed 56 tests. A headless Chrome demo check passed on all eight SOC routes. Real-mode browser and export checks are still outstanding.

## Work order

| Order | Task | Interface change | Completion evidence |
|---|---|---|---|
| 1 | Real-mode walkthrough | Run the existing pages against representative real-mode data. Check navigation, polling, filters, Triage case selection, alert actions, incident pages, and pipeline health. Record browser, server mode, data source, and any failures. | A reproducible check record with screenshots or captured responses for each workflow. Do not call a demo check a real-mode result. |
| 2 | Consistent data state | Show loading, last successful update, stale data, disconnected state, and retry where a page depends on polling. Preserve the last loaded data when a refresh fails and label it as stale. | Failed requests are visible on every affected view. Recovery clears the stale indication without a page reload. |
| 3 | Keyboard and screen-reader pass | Audit the Alerts grid and drawer, Triage queue and dialogs, Use Cases controls, Event Explorer detail, and incident actions. Replace interactive spans with buttons where appropriate. Add labels, focus handling, and status announcements. | Every primary action works by keyboard and focus returns to a sensible control after closing a dialog or detail panel. |
| 4 | Narrow-screen layouts | Check the shared shell and each data-heavy view at phone and tablet widths. Keep key actions visible and support horizontal table scrolling without clipping drawers or dialogs. | Browser checks at 390, 768, and desktop widths cover all eight SOC routes. |
| 5 | Honest metric presentation | Add source and freshness context to health and model panels using fields already returned by the API. Make the current drift warning's limitations visible wherever it is shown. | A reader can identify when the metric was produced and distinguish stored monitoring output from current pipeline status. No new model claim appears in the UI. |
| 6 | Remove interface duplication | Move remaining shared shell styles and repeated polling behavior into the existing shared files, preserving page-specific layouts. Review links to the classic dashboard and training console. | One navigation source controls SOC pages, with no dead links and no duplicated polling logic for the same endpoint. |

## Acceptance checks

1. Existing alert, triage, incident, use-case, and training actions still use their normal routes.
2. The dashboard works in demo and real modes. Record the environment and data source for each verification run.
3. Keyboard navigation reaches every visible action, and status changes are readable without relying on color alone.
4. No page silently presents stale data as current after a request fails.
5. Existing dashboard regression tests pass, followed by targeted browser checks for the changed workflows.
6. Update this plan with completed items, evidence, and remaining limitations before closing Week 8.

## SOC platform follow-up track

The 2026-11-23 read-only audit added [A10–A16](AUDIT_FINDINGS.md) and expanded A1. A10 was corrected after the 2026-11-24 source recheck: HTTP input sanitization blocks the previously claimed approval-forgery path. The remaining server, identity, and integration work beyond the interface-only order is:

| Priority | Findings | Work | Completion evidence |
|---|---|---|---|
| P0 | A1, A11 | Authenticate analysts on the server; derive tier from the authenticated session; apply one close/approval policy to case, single-alert, and bulk actions. | Tier 1 cannot impersonate Tier 2 or bypass checklist/verdict rules through another route. A real second analyst must approve a qualifying close. |
| P1 | A12, A16 | Remove the known training token default, define a separate model-admin role, and require authenticated operator permission for `/api/run`. | Default token fails; an authorized admin can train/promote; a Tier 1 request to run the pipeline is denied. |
| P2 | A13, A14 | Integrate and verify outbound delivery and response actions one connector at a time. Add a manager-side endpoint inventory/heartbeat source for Windows, macOS, and Ubuntu with per-metric timestamps. | External receiver records a test alert; a response action has an externally verified outcome; disconnected/stale/unknown agents display distinctly without invented values. |
| P3 | A15, A8 | Define event/case retention and search beyond the 150-alert feed; complete a real-mode walkthrough with Technitium and any configured exporters. | A retained event and case can be reconstructed after restart; page counts reconcile with retained data; real-mode evidence names its source and timestamps. |
| Defense in depth | A10 | Keep underscore-prefixed approval metadata outside client input, verify any internal approval against the persisted request, and add HTTP plus internal-call regression tests. | Forged approval metadata is rejected on single and bulk routes; the approved internal path records the actual second analyst. |

Do not treat a hidden button, browser actor selector, CSRF header, or simulated incident action as proof that these backend tasks are complete. The running audit instance was a loopback-bound demo, so synthetic alert and SLA counts are not acceptance evidence for production monitoring.

## Dependencies and boundaries

The real-mode walkthrough needs a reachable dashboard with representative Technitium logs. Elasticsearch/Kibana export verification additionally needs the configured stack. If those services are unavailable, complete the local interface checks and record the external verification as pending. Model and training fixes A2–A7 in the [audit](AUDIT_FINDINGS.md) need separate implementation and evaluation work. Authentication A1 requires server-side identity and authorization design; an actor selector in the browser cannot provide it.

## Code implementation update — 2026-11-24

The follow-on code pass changed the server closure and run paths, disabled known training-admin token defaults, corrected mixed timestamp parsing, and corrected the Path B default in the root README. See the [implementation record](Results/CODE_IMPLEMENTATION_2026-11-24.md) for changed files, tests, and limits. The six interface work-order items above are still pending; no real-mode browser or external connector check was performed. The P0 identity work is still open, so the tier checks added to `/api/run` and alert closure must not be described as authenticated access control.
