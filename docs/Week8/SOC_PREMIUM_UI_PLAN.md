# Week 8 SOC interface and motion plan

**Date:** 2026-11-24  
**Scope:** the eight SOC routes in `dashboard/`, with `/soc` as the first implementation surface. This plan extends [WEB_INTERFACE_PLAN.md](WEB_INTERFACE_PLAN.md) and [IMPLEMENTATION_BLUEPRINT.md](Results/IMPLEMENTATION_BLUEPRINT.md). It records proposed work, not completed UI changes.

## Existing plan and source review

Reviewed the complete Week 8 audit, interface plan, implementation blueprint, documentation review, and code implementation record, plus the dashboard architecture, API reference, testing report, and roadmap. The current `/soc` page has three full-width metric strips, two full-width analysis panels, four small charts, and three historical charts. The information is useful but visually flat and long to scan. `loadMetrics()` silently keeps old values on HTTP or network failure; `render()` skips all work when the state version is unchanged. Several chart headers contain a nonfunctional “Close details” span, and footer items point to `#`. The shared shell already provides navigation, a mobile menu, visible keyboard focus, and a reduced-motion rule for its running indicator. These findings are grounded in `dashboard/soc.html`, `dashboard/static/js/chrome.js`, and `dashboard/static/css/shell.css`.

The audit's data constraints govern visual language. `/api/events` is detection alerts, not a raw DNS event store; the alert feed is bounded at 150; run history is limited to 120 in-memory points; `/api/devices` lacks an agent inventory; incident response actions are simulated or not configured; monitoring drift output has an unreliable baseline; and browser-selected analyst IDs are not authenticated. A polished screen must keep those limitations visible. See [AUDIT_FINDINGS.md](AUDIT_FINDINGS.md), especially A1, A2, A8 and A13–A15.

## Research translated into design decisions

| Primary source | Finding applied here |
|---|---|
| [Microsoft Sentinel Overview](https://learn.microsoft.com/en-us/azure/sentinel/get-visibility) | A SOC overview should expose incident volume and severity, operational efficiency, ingestion health, and direct routes into investigation. Use available, correctly named metrics only. |
| [Microsoft Sentinel incident investigation](https://learn.microsoft.com/en-gb/azure/sentinel/investigate-incidents) | Keep alert, entity, timeline, and action context close together during investigation. This project can deep-link to existing Triage, Alerts, and Incidents pages without inventing unsupported data. |
| [Elastic dashboard guidelines](https://www.elastic.co/docs/extend/integrations/dashboard-guidelines) | Limit panels, establish a clear focal area, give charts space, and move from broad overview to detail down the page. |
| [IBM Carbon motion](https://www.carbondesignsystem.com/building-blocks/foundations/motion/overview) | Use fast, purposeful feedback for routine controls. Reserve expressive movement for a few meaningful moments, such as initial page entry. |
| [WCAG 2.2](https://www.w3.org/TR/WCAG22/) and [W3C animation guidance](https://www.w3.org/WAI/WCAG22/Understanding/animation-from-interactions) | Keep text and graphic contrast, keyboard operation, status messages and motion preferences intact. Disable nonessential motion when reduced motion is requested. |

The layout and timing below are **design inferences** from those sources, not requirements claimed by them.

## Recommended visual direction

Create a restrained operations console: deep navy canvas, layered graphite panels, one cool cyan accent for navigation and data, and severity colors reserved for actual severity or health states. Use a compact typographic hierarchy with large tabular numbers, clear labels, and generous panel spacing. Replace emoji as primary visual markers with consistent simple SVG or CSS icons; retain a text label with every key metric. Use dark surfaces without low-contrast gray copy. Do not make all cards glow or pulse: those effects obscure real alert priority.

On `/soc`, put a compact page heading and source/freshness bar first. Place four to six decision metrics in the first scan row: active alerts, High/Critical alerts (using the API's actual severity model), unacknowledged, escalated, pipeline health, and pending approvals. Make each metric link to a meaningful filtered or related existing route where supported. Next, place the 24-hour trend as the main visual, with severity/status distribution beside it. Put rule false positives, ATT&CK tags, and remaining diagnostic charts below in progressively detailed sections. Preserve the current metrics and calculations unless a naming correction is needed to describe what the API actually returns. Add concise scope labels: “feed”, “last 24 h”, “since server start”, or “from analyst verdicts” as appropriate.

The page must show `Loading`, `Updated HH:MM:SS`, `Stale since HH:MM:SS`, and `Retry` as real text. A failed `/api/state` or `/api/metrics` refresh retains the last valid result but marks the affected section stale. A successful recovery clears stale status. Never animate a value change until the new value is confirmed, and never animate a stale or simulated result in a way that suggests a new detection.

## Motion specification

| Interaction | Proposed treatment | Constraint |
|---|---|---|
| First page entry | One subtle stagger of heading and primary panels, about 180–260 ms total | Run once, not on every 3-second poll. No parallax or full-page movement. |
| Hover or focus on a card/control | Small border or surface change, roughly 90–140 ms | Focus remains visible without relying on motion or color alone. |
| Drawer, menu or detail reveal | Short opacity/transform transition, about 150–220 ms | Focus management, Escape behavior, and static end state are mandatory. |
| Changed numerical value | Brief localized color emphasis or restrained count transition | Only after verified data change; keep the exact number accessible throughout. |
| Running or loading | Subtle indicator with clear text | No perpetual decorative pulsing. Provide an explicit stopped/stale state. |

Use `prefers-reduced-motion: reduce` to remove entrance, transform, count and pulse animations while preserving immediate state changes. Also avoid flashing and large moving backgrounds. Test reduced motion in the browser, not only by inspecting CSS.

## Implementation order for the developer agent

1. **State and trust first:** expose refresh time, request errors, stale data and retry for `/soc` state and metrics; preserve last good data; label demo/real mode and API source. Treat `/api/metrics` failure independently of `/api/state`. Fix fake footer links and inert “Close details” affordances.
2. **Visual system:** add a small set of color, spacing, radius, type and motion tokens in shared CSS. Bring `/soc` into that system, then apply consistent shell and component treatment to the seven other routes without overwriting their specialized workflows. Keep the classic dashboard and training console separate.
3. **Overview composition:** reorder existing content by operational priority, add purposeful links to Triage, Alerts, Incidents and Health, and make charts readable with visible time windows, units, empty states and accessible text summaries. Do not invent metrics or endpoints.
4. **Motion layer:** add restrained entrance and interaction transitions after content and states work. Guard all nonessential animation with reduced-motion handling; avoid animation on each poll.
5. **Accessibility and responsive pass:** make primary controls real buttons or links, provide names for chart summaries and icon controls, keep keyboard focus and status announcements, check contrast, and test at 390, 768 and desktop widths. Tables may scroll horizontally; actions must remain reachable.
6. **Verification and reporting:** run existing dashboard tests, inspect all eight routes in a browser, force polling failures and recovery, inspect reduced motion, and record demo versus real mode. A real Technitium walkthrough and external delivery verification remain separately pending if services are unavailable.

## Acceptance criteria

- At a glance, an analyst can identify the current data mode and freshness, active workload, priority alerts, pipeline state and next route to investigate.
- A manager can locate the last-24-hour performance and verdict metrics without confusing them with current state or a model's frozen test performance.
- No stale metric appears current after either API fails; retry and recovery work without full reload.
- Every primary action works from the keyboard and has visible focus. Status changes are text, not color alone.
- At 390 px, 768 px and desktop width, all eight SOC routes have no clipped primary actions, inaccessible dialogs or misleading overflow.
- Reduced-motion mode removes nonessential movement; normal mode remains restrained and does not replay entrance motion on each poll.
- No UI copy implies authenticated access control, raw event retention, endpoint agents, real response execution, or validated live drift where the source cannot support it.
- The final Week 8 implementation report records changed files, test commands and results, browser and viewport, data mode, screenshots if available, and unresolved real-mode or connector checks.

## Handoff boundary

The source review and external guidance support the above design direction. Final component choices should be validated against the live page in a browser. Port 9000 was unavailable during the initial review, so the source inspection is not a live visual test. Do not claim real-mode completion from a demo fixture or visual redesign.
