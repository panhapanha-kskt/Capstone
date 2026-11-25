# Premium SOC workbench UI plan

**Date:** 2026-11-25  
**Reference:** the running `/soc` overview and [SOC_PREMIUM_UI_PLAN.md](SOC_PREMIUM_UI_PLAN.md).  
**Views:** `/triage`, `/alerts`, and `/events` only.

## Research applied

| Primary guidance | Decision for this project |
|---|---|
| [Elastic dashboard guidelines](https://www.elastic.co/docs/extend/integrations/dashboard-guidelines) and [Carbon dashboards](https://www.carbondesignsystem.com/building-blocks/data-visualization/dashboards) | Put the purpose, data scope, and priority summary before dense tables. Group related controls and evidence in clear panels. The exact three-card composition below is a project design choice. |
| [Atlassian motion](https://atlassian.design/foundations/motion) | Use quick feedback for frequent controls and a short entrance for first page load or a detail drawer. Motion should clarify what changed, with one focal point. The chosen timings are 100–120 ms for hover and 200–250 ms for entrance. |
| [W3C animation from interactions](https://www.w3.org/WAI/WCAG22/Understanding/animation-from-interactions) | Remove nonessential animation when reduced motion is requested. Keep status, severity, and freshness in text rather than motion alone. |

The existing `/soc` screen supplied the visual reference: navy canvas, graphite cards, cyan navigation accent, large tabular numbers, and restrained orange for priority. The original view screenshots showed flat chart strips on Alerts, a large unstructured empty case area on Triage, and a full-width filter/table block on Events. This plan keeps every existing investigation action and the previous defensive UI changes.

## Three implemented design improvements

1. **One coherent workbench language.** Add `dashboard/static/css/soc-workbench.css` and page classes for the three routes. Use a `/soc`-style heading, eyebrow, data context bar, bordered panels, consistent spacing, focus treatment, and responsive layout. Keep demo mode and bounded feed labels visible.
2. **A useful first scan area.** Alerts receives three current-feed cards, a more legible severity donut, compact framed charts, and real keyboard-operable chart scope buttons. Events receives three page/search cards and a grouped filter surface. Triage receives clearer queue/case panels and a purposeful empty case workspace. Counts remain tied to their actual feed or page scope.
3. **Smooth, restrained motion.** Use one 250 ms entrance for the initial view, 100–120 ms hover feedback, and a 200 ms drawer entrance. Do not replay chart or count animation on polling. Remove those transitions under `prefers-reduced-motion: reduce`.

## Acceptance evidence and limits

Review the three [desktop captures](Results/PREMIUM_WORKBENCH_REPORT_2026-11-25.md) beside the existing [SOC overview capture](Results/SOC_PREMIUM_DEMO_1440.png). Test at desktop and true 390 px CSS viewport, including reduced motion. The local server is in demo mode; synthetic totals and the 150-record alert feed are not production SOC metrics. A browser-selected analyst is still not authenticated, and `/api/events` still represents detection alerts rather than a raw event store. The design does not change those backend facts.
