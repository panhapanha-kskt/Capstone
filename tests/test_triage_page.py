"""Static checks for the Tier 1 triage page script (audit 2026-11-26)."""

from pathlib import Path

JS = (Path(__file__).resolve().parent.parent / "dashboard" / "static" / "js" / "triage.js").read_text(encoding="utf-8")


def _between(start, end):
    return JS[JS.index(start):JS.index(end, JS.index(start))]


def test_poll_does_not_rerender_an_unchanged_case():
    body = _between("async function loadCase", "function can(")
    assert "sig === caseSig" in body and "return;" in body
    assert "focusToken()" in body and "enrich-out" in body      # focus and lookup result survive a real change


def test_taking_over_another_analysts_case_asks_first():
    body = _between('if (act === "claim")', 'else if (act === "release")')
    assert "window.confirm(" in body and body.index("window.confirm(") < body.index("/claim`")


def test_stale_page_moves_back_inside_the_queue():
    body = _between("function renderQueue", "let queueUpdated")
    assert "st.offset >= q.total" in body and "Math.floor((q.total - 1) / st.limit) * st.limit" in body


def test_close_classification_is_never_preselected():
    body = _between('else if (act === "close")', 'else if (act === "escalate")')
    assert '<option value="" disabled selected>' in body
    assert "fp_model_logic" not in body                         # no default training label
    assert 'if (!$("c-class").value)' in JS


def test_changes_by_another_analyst_are_flagged():
    body = _between("async function loadCase", "function can(")
    assert "othersChanges(st.view, v)" in body
    fn = _between("function othersChanges", "async function loadCase")
    assert "h.actor !== actor()" in fn and "prev.case.key !== next.case.key" in fn
    assert 'data-act="ackchange"' in JS and 'role="status"><b>Case changed while you had it open.' in JS


def test_investigating_filter_and_remembered_priority():
    assert '<option value="Investigating">Investigating</option>' in JS
    assert 'severity: LS.get("tri_sev", "")' in JS and 'LS.set("tri_sev", st.severity)' in JS
    assert '$("f-sev").value = st.severity;' in JS
