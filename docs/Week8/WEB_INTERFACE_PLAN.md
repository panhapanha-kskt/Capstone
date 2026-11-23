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

## Dependencies and boundaries

The real-mode walkthrough needs a reachable dashboard with representative Technitium logs. Elasticsearch/Kibana export verification additionally needs the configured stack. If those services are unavailable, complete the local interface checks and record the external verification as pending. Model and training fixes A2–A7 in the [audit](AUDIT_FINDINGS.md) need separate implementation and evaluation work. Authentication A1 requires server-side identity and authorization design; an actor selector in the browser cannot provide it.
