"""/soc overview layout regressions (audit 2026-11-27)."""

import re
from pathlib import Path

HTML = (Path(__file__).resolve().parent.parent / "dashboard" / "soc.html").read_text(encoding="utf-8")


def test_chart_boxes_cannot_grow_on_redraw():
    # The charts size their SVG from the box they sit in. If that box can stretch (flex:1 from .p-body)
    # and the SVG is inline (baseline gap), every 3 s redraw made each chart ~5 px taller.
    rule = re.search(r"\.chart-body\s*\{([^}]*)\}", HTML).group(1)
    assert re.search(r"flex:\s*none", rule) and re.search(r"height:\s*\d+px", rule) and "overflow: hidden" in rule
    assert re.search(r"\.chart-body\s*>\s*svg\s*\{\s*display:\s*block", HTML)
