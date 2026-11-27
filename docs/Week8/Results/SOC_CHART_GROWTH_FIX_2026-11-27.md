# /soc charts grew on every refresh

**Date:** 2026-11-27  **File:** `dashboard/soc.html` (CSS only)

## Symptom
With the `/soc` overview left open in demo mode, the panels slowly stretched and the page content was pushed further and further down. The Query Rate, Alerts per Run and Trend charts kept getting taller.

## Cause
Each chart measures its own `<svg>` with `getBoundingClientRect()` and sets the `viewBox` to that size. Two things fed back into each other:

1. **The box ignored its height.** `.p-body` has `flex: 1`, so the `height: 190px` / `230px` on `.chart-body` was overridden and the box stretched to the grid row's height.
2. **The SVG kept a gap below it.** An inline `<svg>` leaves a few pixels of text-baseline space under it, so the box was always slightly taller than the SVG.

On each redraw (every 3 s in demo mode) the SVG got the box's slightly larger height, the box grew to fit it, and so on.

Reproduced in headless Chrome at 1440 px with mocked `/api/state`. Each chart grew about **4.8 px per redraw**, and the page about 15 px.

## Fix
`.chart-body { flex: none; height: …; overflow: hidden }` and `.chart-body > svg { display: block }`.

After the fix, the Query Rate, Alerts per Run and Trend charts all stay at 230 px over repeated redraws. The page height stays constant, and the layout is unchanged otherwise.

`health.html` and `index.html` draw their charts at a fixed size instead of measuring them, so they don't have this problem.

## Test
`tests/test_soc_page.py` checks that the chart box has a fixed height (`flex: none`, a set height, `overflow: hidden`) and that the SVG is a block. With `tests/test_dashboard_soc.py`: 29 passed.
