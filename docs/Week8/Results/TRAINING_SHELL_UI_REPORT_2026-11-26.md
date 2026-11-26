# Training console in the SOC shell

**Date:** 2026-11-26
**Scope:** `/training` (Model training console) brought into the `/soc` shell, visual design and routing.
**Reference:** [PREMIUM_WORKBENCH_UI_PLAN_2026-11-25.md](../PREMIUM_WORKBENCH_UI_PLAN_2026-11-25.md), [SOC_PREMIUM_UI_PLAN.md](../SOC_PREMIUM_UI_PLAN.md). Earlier Week 8 plans kept the training console separate. This change reverses that decision at the user's request.

## Starting point

- **`/training` was a standalone light-theme page.** It is `dashboard/training-gui/api/static/index.html`, which had its own left nav and a "← Back to dashboard" link to `/`. It used global `nav`/`main`/`input`/`table` CSS that would clash with the shared shell. It was the only SOC page that was not in `chrome.js` NAV.
- **It was served without a CSP.** `server.py` returned it through `self.send`, not `send_html`. Every other SOC page gets `Content-Security-Policy` with a per-response script nonce. The page that holds the training admin token was the one page without that protection.
- **Moving between steps or pages felt abrupt.** Step changes swapped sections instantly after the data loaded. Moving between `/soc` and `/training` was a full page change with a different layout.

The original page is kept for comparison as [training_index_before.html](training_index_before.html).

## Research applied

| Source | Decision |
|---|---|
| [MDN BCD @view-transition](https://raw.githubusercontent.com/mdn/browser-compat-data/main/css/at-rules/view-transition.json), [caniuse cross-document VT](https://caniuse.com/cross-document-view-transitions) | Cross-document transitions are a progressive enhancement. Chrome 126+ and Safari 18.2+ support them now; Firefox gets them in 162 (2026-12-08). Firefox 161 navigates instantly, as before. |
| [web.dev: same-document view transitions Baseline](https://web.dev/blog/same-document-view-transitions-are-now-baseline-newly-available) | `document.startViewTransition` is used for step switches, with feature detection and a plain fallback. |
| [Chrome: same-document VT](https://developer.chrome.com/docs/web-platform/view-transitions/same-document), [MDN: Using the View Transition API](https://developer.mozilla.org/en-US/docs/Web/API/View_Transition_API/Using) | The page freezes during the update callback, so data loads run outside the transition. Transition names are unique per page. |
| [Carbon progress indicator](https://carbondesignsystem.com/components/progress-indicator/usage/) | Runs and Models can be opened at any time, so the steps are a status-bearing sub-nav of links, not a gated wizard or tabs. State is shown with icon plus text. |
| [Gatsby accessible client routing study](https://www.gatsbyjs.com/blog/2019-07-11-user-testing-accessible-client-routing) | Focus moves to the step heading on route change, as before. |
| [WCAG 2.2](https://www.w3.org/TR/WCAG22/) 1.4.3, 1.4.11, 2.4.11, 2.3.3 | Error text `#ff897f` (6.9:1 on panel) replaces `#e0564a` (4.23:1). Input borders are `#6a879e` (about 4.2:1). Focus is not hidden under the sticky stepper. Reduced motion removes all transitions. |
| Existing Week 8 motion spec ([Atlassian motion](https://atlassian.design/foundations/motion)) | 100–140 ms hover, 160–200 ms transitions, no animation on polling. |

## Implemented

1. **Security (`dashboard/server.py`, 1 line).** `/training` is now served with `send_html`. It gets the same CSP and a fresh nonce on every `<script>` as the other SOC pages.
2. **Shared navigation (`dashboard/static/js/chrome.js`).** "Model training" (`/training`) is added to the sidebar before "Classic dashboard".
3. **Page structure (`dashboard/training-gui/api/static/index.html`).**
   - **Layout:** the light inline CSS and the back link are removed. The page uses the same `#app-chrome` placeholder and `SOC.mount({active:"training"})` as `/soc`, so it shows the same top bar, sidebar and mobile menu.
   - **Hero and stepper:** a `/soc`-style hero (eyebrow, "Model training" title, lead) sits above a sticky 4-step stepper. The stepper keeps the existing `<nav aria-label="Training steps">`.
   - **Health pill:** refreshes on load and when the tab becomes visible again, with no extra timer.
4. **Visual system (`dashboard/static/css/training.css`, new, 217 lines).** Everything is scoped to `body.soc-training` and uses the `/soc` tokens.
   - **Look:** navy canvas, graphite panels, cyan primary buttons, outline secondary buttons, readable error colour, tabular numbers in tables.
   - **Scrolling:** the log and long tables scroll inside their own boxes.
   - **Responsive:** at ≤760 px the stepper is a 2×2 grid, and at ≤440 px a compact layout.
   - **Admin-token gate:** now covers only the main area, so the SOC sidebar stays usable. It says that this token is separate from the SOC sign-in.
5. **Smooth routing.**
   - **Inside training:** `render()` is split into a quick synchronous step swap and the data load that follows it. The swap crossfades through `document.startViewTransition` only when the step actually changes, the browser supports it, and reduced motion is off. There is no animation on the 2-second Runs log poll or when you select a run. A guard drops a stale route if a newer one arrives mid-swap.
   - **Between SOC pages (`dashboard/static/css/shell.css`):** cross-document view transitions are opted in. The top bar and sidebar stay still while the main content crossfades for 160 ms. The `prefers-reduced-motion: reduce` rule disables every view-transition animation.
6. **Tests.**
   - **New in `tests/test_dashboard_soc.py`:** `/training` carries a CSP nonce on every script, gets a fresh nonce per response, and has no inline handlers. `chrome.js` NAV lists `/training`, and the page mounts the shell.
   - **Fix in `tests/test_training_admin_auth.py`:** the module now uses a temporary training data folder and a test token before importing settings. Without this, a full `pytest tests` run pointed the console tests' cleanup at the real `dashboard/training-gui/gui_data/`, including the 3.6 GB `datasets/train.csv`. The environment blocked that deletion and the file is intact.

## Verification

| Check | Result |
|---|---|
| `pytest tests/test_training_console.py tests/test_training_upload.py tests/test_training_admin_auth.py tests/test_dashboard_soc.py tests/test_dashboard_triage.py` | 115 passed |
| Full `pytest tests` (no TensorFlow installed) | 471 passed, 4 skipped. 7 failed and 2 collection errors, all from missing TensorFlow (`test_bridge`, `test_cleaning`, `test_path_b_load`, `test_stacker`, `test_thresholds_fusion`). |
| `node --check` on the inline training script and `chrome.js` | Pass |
| CSS parse (`training.css`, `shell.css`) | No errors |
| Headless Chrome with mocked API responses | Gate covers the main area only, and the sidebar stays usable. "Model training" shows as current. Each step shows only its section and focuses its heading. The Runs poll stops on leaving Runs. 2×2 stepper at 420 px. No JS errors. |

## Pending

- **Restart the stack.** The `server.py` change only applies after a restart. HTML, CSS and JS load from disk on each request.
- **Live check through the gateway.** A browser check on `127.0.0.1:9000` with a real analyst session and admin token is still to do. It should cover all four steps, upload, train, promote, the CSP console, and the 390/768/1440 px widths with reduced motion on.
- **Firefox page-to-page crossfade.** This starts with Firefox 162 (2026-12-08). Step crossfades inside training already work in current Firefox.
- **Standalone FastAPI use is unstyled.** If the training API is opened on its own port instead of through the dashboard, it doesn't serve the shell CSS and JS. The page still works but has no styling. Only the dashboard-integrated use is documented.

## Training and detection logic unchanged

This is a presentation-only change. `git diff` shows no changes in `dashboard/training-gui/core/`, `dashboard/training-gui/adapters/`, `dashboard/training-gui/api/main.py`, `src/`, `scripts/`, `models/` or `config/`. In the training page script, only the routing and display code changed: the step swap, the transition, the loading class and the health pill. The training defaults (`DEFAULTS`), dataset checks (`CHECK_VERSION`), label mapping, splits, every `/training/api` call, and the train, promote and rollback flows are unchanged. The CSS rule that hides pipeline or feature-table fields depending on dataset kind was carried over unchanged into `training.css`.

## Follow-up: delete uploaded datasets

At the user's request, each uploaded dataset in the Data step now has a **Delete** button next to **Check**. Before, only combined (multi-file) datasets had one. This is file management only; no training or detection logic changed.

- **Backend.** `core/data.py` gains `delete_dataset()`, exposed as `POST /training/api/datasets/{name}/delete` in `api/main.py` and protected by the admin token. It removes only a plain file inside the training datasets folder (`gui_data/datasets/`).
- **What it refuses.** It refuses the project default (`data/raw`), combined datasets (they keep their own delete), folders, and path tricks. It also refuses a file that a combined dataset still lists, naming that dataset, and a file that a running training job is using.
- **Page.** The page asks for confirmation, showing the file name and size and warning that the delete cannot be undone. It then refreshes the list and step status and clears any cached check result for that file.
- **Tests.** Nine new tests in `tests/test_training_console.py` cover delete, the admin token requirement, the refusal cases, and the page wiring. 
- **Results.** The five training and SOC test files: all pass.
- **Restart needed.** The new API route only applies after a server restart.

## Files

`dashboard/server.py`, `dashboard/static/js/chrome.js`, `dashboard/static/css/shell.css`, `dashboard/static/css/training.css` (new), `dashboard/training-gui/api/static/index.html`, `tests/test_dashboard_soc.py`, `tests/test_training_admin_auth.py`, `docs/Week8/Results/training_index_before.html` (new). `dashboard/training-gui/core/data.py` and `dashboard/training-gui/api/main.py` (dataset delete only), `tests/test_training_console.py`. Nothing was committed.
