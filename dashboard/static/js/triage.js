/* Tier 1 triage workbench (/triage). Vanilla JS; all handlers via addEventListener (CSP: no inline handlers). */
(function(){
  "use strict";
  const esc = SOC.esc;
  const $ = id => document.getElementById(id);
  const LS = {
    get(k, d){ try { const v = localStorage.getItem(k); return v === null ? d : v; } catch(e){ return d; } },
    set(k, v){ try { localStorage.setItem(k, v); } catch(e){} },
  };
  const CLASS_LABELS = {
    true_positive: "True positive: malicious activity confirmed (normally escalate instead)",
    benign_positive: "Benign positive: real activity, but expected or authorised",
    fp_model_logic: "False positive: the detection / model logic is wrong",
    fp_bad_data: "False positive: bad, duplicated or incomplete input data",
    duplicate: "Duplicate of another case",
    undetermined: "Undetermined: not enough information",
  };
  const FP_CLASSES = ["fp_model_logic", "fp_bad_data"];
  const STATUS_CLS = {Open:"sev-High", Acknowledged:"ok", Investigating:"ok", Escalated:"bad", PendingApproval:"bad", Closed:""};

  const st = {
    group: LS.get("tri_group", "source"), status: LS.get("tri_status", "open"), severity: LS.get("tri_sev", ""), q: "", mine: false,
    offset: 0, limit: 50, selected: null, queue: null, view: null, skew: 0, analysts: [], tier: 0,
  };
  const deepLink = new URLSearchParams(location.search);
  const linkedCase = deepLink.get("case");
  if (/^c-[0-9a-f]{12}$/.test(linkedCase || "")){
    st.selected = linkedCase;
    st.group = ["source", "entity"].includes(deepLink.get("group")) ? deepLink.get("group") : "source";
    st.status = ""; st.severity = "";
  }

  const main = SOC.mount({active: "triage"});
  document.body.classList.add("soc-workbench", "soc-triage");
  const emptyCaseHtml = `<div class="case-empty" role="status">
    <span class="case-empty-mark" aria-hidden="true">◎</span>
    <span class="wb-kicker">CASE WORKSPACE</span>
    <h2>Ready for the next case</h2>
    <p>Select a case from the queue to review evidence, complete the checklist, and record a decision.</p>
    <div class="case-empty-steps"><span>01 · Review signals</span><span>02 · Validate evidence</span><span>03 · Decide or escalate</span></div>
  </div>`;
  main.innerHTML = `
    <div class="page-head tri-head">
      <div class="wb-title"><span class="wb-kicker"><span class="wb-live" aria-hidden="true"></span>SECURITY OPERATIONS / INVESTIGATE</span>
        <h1>Triage workbench</h1><p class="subtitle">Prioritize the queue, validate evidence, and move each case to a defensible outcome.</p></div>
      <span class="right">
        <label class="wb-actor">Acting as
          <select id="actor" aria-label="Acting analyst"></select></label>
        <button class="btn sec" id="btn-approvals" hidden>Approvals <b id="n-approvals">0</b></button>
        <button class="btn sec" id="btn-handover">Shift handover</button>
        <button class="btn sec" id="btn-help" title="Keyboard shortcuts (?)">?</button>
      </span>
    </div>
    <div class="me-strip" id="me" aria-label="My shift"></div>
    <div class="tri-grid">
      <section class="tri-col" aria-label="Case queue">
        <div class="tri-col-title"><h2>Case queue</h2><span>Work by priority and due time</span></div>
        <div class="counts" id="counts"></div>
        <div class="qfilters">
          <select id="f-group" aria-label="Group alerts by">
            <option value="source">Group: host + detection type</option>
            <option value="entity">Group: host + domain</option>
          </select>
          <select id="f-status" aria-label="Status">
            <option value="open">Open cases</option><option value="">All</option>
            <option value="Open">Open (untouched)</option><option value="Acknowledged">Acknowledged</option>
            <option value="Investigating">Investigating</option>
            <option value="PendingApproval">Pending approval</option><option value="Escalated">Escalated</option>
            <option value="Closed">Closed</option>
          </select>
          <select id="f-sev" aria-label="Priority"><option value="">Any priority</option>
            <option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select>
          <input id="f-q" type="search" placeholder="Search host, domain, rule" aria-label="Search">
        </div>
        <div class="queue-status" id="queue-status" role="status" aria-live="polite">
          <span id="queue-message">Loading queue…</span>
          <button class="btn sec" type="button" id="queue-retry" hidden>Retry</button>
        </div>
        <div class="qlist" id="qlist" role="listbox" aria-label="Cases" tabindex="0"><div class="empty">Loading…</div></div>
        <div class="pager"><button id="p-prev" aria-label="Previous page">‹</button><span id="p-info">—</span><button id="p-next" aria-label="Next page">›</button></div>
      </section>
      <section class="tri-col" aria-label="Case">
        <div class="case" id="case">${emptyCaseHtml}</div>
      </section>
    </div>

    <dialog id="dlg-close" aria-labelledby="dlg-close-h">
      <div class="dh" id="dlg-close-h">Close case</div>
      <div class="db">
        <label>Classification (becomes the training label for the next model retraining)
          <select id="c-class"></select></label>
        <div class="banner" id="c-fp-note" hidden>High/Critical false-positive closures need a <b>Tier 2 approval</b> (four-eyes). Your request will be queued.</div>
        <div id="c-manual"></div>
        <label>Comment: why? (required, at least 10 characters)
          <textarea id="c-comment" placeholder="e.g. Internal update service; names are product SKUs, not encoded data. Checked with the asset owner."></textarea></label>
        <div class="err" id="c-err"></div>
      </div>
      <div class="df"><button class="btn sec" data-close>Cancel</button><button class="btn" id="c-submit">Close case</button></div>
    </dialog>

    <dialog id="dlg-esc" aria-labelledby="dlg-esc-h">
      <div class="dh" id="dlg-esc-h">Escalate to Tier 2</div>
      <div class="db">
        <div class="nag info">Every field is required. Tier 2 should not have to redo your triage.</div>
        <div id="e-manual"></div>
        <label>Summary <textarea id="e-summary"></textarea></label>
        <label>Evidence (observed facts) <textarea id="e-evidence"></textarea></label>
        <label>Checks done and results <textarea id="e-checks"></textarea></label>
        <label>Hypothesis <textarea id="e-hyp" placeholder="e.g. dns2tcp-style tunnel from this host to the apex domain"></textarea></label>
        <label>Recommended action <textarea id="e-rec" placeholder="e.g. Tier 2: confirm the process on the host, then request a block of the apex domain"></textarea></label>
        <div class="err" id="e-err"></div>
      </div>
      <div class="df"><button class="btn sec" data-close>Cancel</button><button class="btn dng" id="e-submit">Escalate</button></div>
    </dialog>

    <dialog id="dlg-declare" aria-labelledby="dlg-declare-h">
      <div class="dh" id="dlg-declare-h">Declare a security incident</div>
      <div class="db">
        <div class="nag info">Use this when the evidence meets your incident criteria. The incident will link to this investigation and keep a snapshot of its evidence and history.</div>
        <label>Incident title <input id="d-title" maxlength="240" placeholder="e.g. Suspected DNS tunneling from host"></label>
        <label>Severity <select id="d-severity"><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></label>
        <label>Why this is an incident <textarea id="d-reason" placeholder="State the observed activity, affected asset, and why it needs incident response."></textarea></label>
        <div class="err" id="d-err" role="alert"></div>
      </div>
      <div class="df"><button class="btn sec" data-close>Cancel</button><button class="btn" id="d-submit">Declare incident</button></div>
    </dialog>

    <dialog id="dlg-release" aria-labelledby="dlg-release-h">
      <div class="dh" id="dlg-release-h">Release case back to the queue</div>
      <div class="db"><label>Next step for whoever picks it up <textarea id="r-next"></textarea></label></div>
      <div class="df"><button class="btn sec" data-close>Cancel</button><button class="btn" id="r-submit">Release</button></div>
    </dialog>

    <dialog id="dlg-handover" aria-labelledby="dlg-handover-h">
      <div class="dh" id="dlg-handover-h">Shift handover</div>
      <div class="db" id="h-body">Loading…</div>
      <div class="df"><a class="btn sec" href="/api/reports/handover?format=md" download>Download Markdown</a>
        <button class="btn sec" data-close>Close</button><button class="btn" id="h-ack">Acknowledge handover</button></div>
    </dialog>

    <dialog id="dlg-approvals" aria-labelledby="dlg-appr-h">
      <div class="dh" id="dlg-appr-h">Close requests waiting for approval (four-eyes)</div>
      <div class="db" id="a-body">Loading…</div>
      <div class="df"><button class="btn sec" data-close>Close</button></div>
    </dialog>

    <dialog id="dlg-help" aria-labelledby="dlg-help-h">
      <div class="dh" id="dlg-help-h">Keyboard shortcuts</div>
      <div class="db"><table class="mini">
        <tr><td><span class="kbd">j</span> / <span class="kbd">k</span></td><td>next / previous case</td></tr>
        <tr><td><span class="kbd">c</span></td><td>claim the selected case</td></tr>
        <tr><td><span class="kbd">x</span></td><td>close (with classification)</td></tr>
        <tr><td><span class="kbd">e</span></td><td>escalate to Tier 2</td></tr>
        <tr><td><span class="kbd">r</span></td><td>refresh</td></tr>
        <tr><td><span class="kbd">/</span></td><td>search</td></tr>
        <tr><td><span class="kbd">?</span></td><td>this help</td></tr>
        <tr><td><span class="kbd">Esc</span></td><td>close a dialog</td></tr>
      </table><div class="nag">Shortcuts are ignored while you are typing in a field.</div></div>
      <div class="df"><button class="btn sec" data-close>Close</button></div>
    </dialog>`;

  /* ── helpers ─────────────────────────────── */
  function toast(msg, bad){
    const t = $("toast");
    t.textContent = msg;
    t.className = bad ? "bad" : "";
    t.style.display = "block";
    clearTimeout(toast._t);
    toast._t = setTimeout(()=>{ t.style.display = "none"; }, 5000);
  }
  const actor = ()=>SOC.actor();
  const nowSrv = ()=>Date.now()/1000 + st.skew;
  function dur(s){
    s = Math.abs(s);
    if (s < 60) return Math.round(s) + "s";
    if (s < 3600) return Math.round(s/60) + "m";
    if (s < 86400) return (s/3600).toFixed(1) + "h";
    return (s/86400).toFixed(1) + "d";
  }
  function slaHtml(c, kind){
    const done = ["Closed","Escalated","PendingApproval"].includes(c.status);
    const due = kind === "ack" ? c.ack_due : c.triage_due;
    const stopped = done || (kind === "ack" && c.claimed_at);
    const label = kind === "ack" ? "Ack" : "Triage";
    if (stopped){
      const met = kind === "ack" ? c.ack_met : !c.triage_breached;
      return `<span class="sla stop" title="${label} SLA clock stopped">${label}: ${met ? "met" : "missed"}</span>`;
    }
    return `<span class="sla" data-due="${due}" data-start="${c.sla_start}" data-label="${label}"></span>`;
  }
  function tickSla(){
    const now = nowSrv();
    for (const el of document.querySelectorAll(".sla[data-due]")){
      const due = Number(el.dataset.due), start = Number(el.dataset.start);
      const left = due - now, total = Math.max(due - start, 1);
      el.textContent = `${el.dataset.label}: ${left >= 0 ? dur(left) + " left" : "breached " + dur(left) + " ago"}`;
      el.className = "sla " + (left < 0 ? "bad" : left / total < 0.25 ? "warn" : "ok");
    }
  }
  setInterval(tickSla, 1000);
  function chipStatus(s){ return `<span class="chip ${STATUS_CLS[s] || ""}">${esc(s === "PendingApproval" ? "Pending approval" : s)}</span>`; }
  function chipSev(s){ return `<span class="chip sev-${esc(s)}">${esc(s)}</span>`; }
  // In-flight guard (audit fix F3): the same request can't be sent again while it is still running,
  // so a double-click or a repeated key press does not write twice.
  const inFlight = new Set();
  let pendingButtons = [];
  async function post(url, body){
    if (inFlight.has(url)) throw Object.assign(new Error("Already working on it…"), {inFlight: true});
    inFlight.add(url);
    document.body.classList.add("busy");
    if (inFlight.size === 1){
      pendingButtons = [...document.querySelectorAll(".acts .btn, dialog .btn:not([data-close])")]
        .filter(button=>!button.disabled);
      pendingButtons.forEach(button=>button.disabled = true);
    }
    try {
      return await SOC.apiPOST(url, Object.assign({actor: actor()}, body || {}));
    } finally {
      inFlight.delete(url);
      if (!inFlight.size){
        document.body.classList.remove("busy");
        pendingButtons.forEach(button=>button.disabled = false);
        pendingButtons = [];
      }
    }
  }
  function fail(e){
    if (e && e.inFlight) return;          // a dropped double-click is not an error
    const d = e && e.data;
    let msg = (e && e.message) || "Action failed";
    if (d && d.missing) msg += ": " + d.missing.map(m=>m.label).join("; ");
    toast(msg, true);
  }

  /* ── actor selector + my shift ───────────── */
  SOC.analysts().then(list=>{
    st.analysts = list;
    const sel = $("actor");
    sel.innerHTML = list.map(a=>`<option value="${esc(a.id)}">${esc(a.name)} · ${esc(a.role)}</option>`).join("");
    sel.disabled = list.length === 1;
    if (!list.some(a=>a.id === actor()) && list.length) SOC.setActor(list[0].id);
    sel.value = actor();
    applyTier();
    sel.addEventListener("change", ()=>{ SOC.setActor(sel.value); applyTier(); refreshAll(); toast("Now acting as " + sel.value); });
  });
  function applyTier(){
    const me = st.analysts.find(a=>a.id === actor());
    st.tier = me ? SOC.tierOf(me.role) : 0;
    $("btn-approvals").hidden = st.tier < 2;

  }
  async function loadMe(){
    try {
      const m = await SOC.apiGET("/api/triage/me?hours=8&actor=" + encodeURIComponent(actor()));
      const mtta = m.mtta_seconds && m.mtta_seconds.median != null ? dur(m.mtta_seconds.median) : "—";
      $("me").innerHTML = [
        ["My open cases", m.open_owned], ["Claimed", m.claimed], ["Closed", m.closed],
        ["Close requests", m.close_requested], ["Escalated", m.escalated], ["My MTTA (median)", mtta],
        ...(m.tier >= 2 ? [["Approved / rejected", `${m.approved} / ${m.rejected}`]] : []),
      ].map(([k,v])=>`<span class="m"><b>${esc(v)}</b>${esc(k)}</span>`).join("")
        + `<span class="m" style="color:var(--muted)">last 8 h · ${esc(m.actor)} (Tier ${esc(m.tier)})</span>`;
    } catch(e){ /* optional strip */ }
  }

  /* ── queue ───────────────────────────────── */
  function queueUrl(){
    const p = new URLSearchParams({group: st.group, actor: actor(), offset: st.offset, limit: st.limit});
    if (st.status) p.set("status", st.status);
    if (st.severity) p.set("severity", st.severity);
    if (st.q) p.set("q", st.q);
    if (st.mine) p.set("mine", "1");
    return "/api/triage/queue?" + p.toString();
  }
  function renderCounts(q){
    const c = q.counts;
    const btn = (id, label, n, on) => `<button class="cnt ${on ? "on" : ""}" aria-pressed="${on}" data-cnt="${id}">${esc(label)}<b>${esc(n)}</b></button>`;
    $("counts").innerHTML = [
      btn("mine", "My queue", c.mine, st.mine),
      `<span class="cnt">Unassigned<b>${esc(c.unassigned)}</b></span>`,
      `<span class="cnt ${c.sla_breached ? "bad" : ""}">SLA breached<b>${esc(c.sla_breached)}</b></span>`,
      btn("pending", "Pending approval", c.pending_approval, st.status === "PendingApproval"),
      ...["Critical","High","Medium","Low"].filter(s=>c.by_severity[s]).map(s=>btn("sev:"+s, s, c.by_severity[s], st.severity === s)),
      `<span class="cnt" style="cursor:default">${esc(c.total)} cases · ${esc(c.alerts)} alerts</span>`,
    ].join("");
    $("n-approvals").textContent = c.pending_approval;
  }
  function rowHtml(c){
    const shared = c.source_flags && c.source_flags.shared;
    const mode = c.suggestion === "escalate" ? "Escalate suggested" : c.suggestion === "close" ? "Close suggested" : "Review needed";
    return `<div class="qrow ${c.key === st.selected ? "sel" : ""}" role="option" aria-selected="${c.key === st.selected}" data-case="${esc(c.key)}" tabindex="-1">
      <div class="qrow-top">${chipSev(c.priority)}<span class="t" title="${esc(c.label)}">${esc(c.label)}</span>${chipStatus(c.status)}</div>
      <div class="qrow-identity">${shared ? '<span class="warnip" title="Shared source IP">⚠ </span>' : ""}${esc(c.client)} · ${esc(c.members)} alert${c.members === 1 ? "" : "s"}</div>
      <div class="qrow-bottom"><span>Owner: ${esc(c.owner || "unassigned")}</span><span class="qrow-signal">${esc(mode)}</span>${slaHtml(c, c.owner ? "triage" : "ack")}</div>
    </div>`;
  }
  function renderQueue(q){
    if (!q || !Array.isArray(q.cases) || !Number.isSafeInteger(q.total) || q.total < 0 ||
        !q.cases.every(c=>c && typeof c.key === "string" && typeof c.label === "string"))
      throw new Error("Triage API returned an invalid queue");
    if (q.total > 0 && st.offset >= q.total){
      // cases left the queue (closed/escalated) and this page is now past the end: go to the last page
      st.offset = Math.floor((q.total - 1) / st.limit) * st.limit;
      setTimeout(refreshAll, 0);
      return;
    }
    st.queue = q;
    st.skew = q.now - Date.now()/1000;
    renderCounts(q);
    SOC.patchList($("qlist"), q.cases, c=>c.key, rowHtml,
      `<div class="empty">No cases match. ${st.status === "open" ? "Nothing open — good shift." : ""}</div>`);
    const page = Math.floor(st.offset / st.limit) + 1, pages = Math.max(Math.ceil(q.total / st.limit), 1);
    $("p-info").textContent = `Page ${page} of ${pages} · ${q.total} matching`;
    $("p-prev").disabled = st.offset <= 0;
    $("p-next").disabled = st.offset + st.limit >= q.total;
    tickSla();
    if (st.selected) loadCase(st.selected, true);
    loadMe();
  }
  let queueUpdated = null;
  const poller = SOC.pollJSON(queueUrl, renderQueue, 5000, error=>{
    const retry = $("queue-retry");
    $("queue-status").classList.toggle("bad", !!error);
    if (!error && document.activeElement === retry) $("qlist").focus();
    retry.hidden = !error;
    if (error){
      const message = st.queue && queueUpdated ? "Queue stale since " + queueUpdated.toLocaleTimeString() + ". Showing saved results." : "Could not load the queue.";
      if ($("queue-message").textContent !== message) $("queue-message").textContent = message;
      if (!st.queue) $("qlist").textContent = "";
    } else {
      queueUpdated = new Date();
      $("queue-message").textContent = "Updated " + queueUpdated.toLocaleTimeString();
    }
  });
  $("queue-retry").addEventListener("click", ()=>poller.refresh());
  function refreshAll(){ poller.refresh(); }

  $("f-group").value = st.group;
  $("f-status").value = st.status;
  $("f-sev").value = st.severity;
  $("f-group").addEventListener("change", e=>{ st.group = e.target.value; LS.set("tri_group", st.group); st.offset = 0; st.selected = null; showEmpty(); refreshAll(); });
  $("f-status").addEventListener("change", e=>{ st.status = e.target.value; LS.set("tri_status", st.status); st.offset = 0; refreshAll(); });
  $("f-sev").addEventListener("change", e=>{ st.severity = e.target.value; LS.set("tri_sev", st.severity); st.offset = 0; refreshAll(); });
  let qTimer = null;
  $("f-q").addEventListener("input", e=>{ clearTimeout(qTimer); qTimer = setTimeout(()=>{ st.q = e.target.value.trim(); st.offset = 0; refreshAll(); }, 250); });
  $("p-prev").addEventListener("click", ()=>{ st.offset = Math.max(0, st.offset - st.limit); refreshAll(); });
  $("p-next").addEventListener("click", ()=>{ st.offset += st.limit; refreshAll(); });
  $("counts").addEventListener("click", e=>{
    const b = e.target.closest("[data-cnt]"); if (!b) return;
    const k = b.dataset.cnt;
    if (k === "mine") st.mine = !st.mine;
    else if (k === "pending") st.status = st.status === "PendingApproval" ? "open" : "PendingApproval";
    else if (k.startsWith("sev:")) st.severity = st.severity === k.slice(4) ? "" : k.slice(4);
    $("f-status").value = st.status; $("f-sev").value = st.severity;
    LS.set("tri_status", st.status); LS.set("tri_sev", st.severity);
    st.offset = 0; refreshAll();
  });
  $("qlist").addEventListener("click", e=>{
    const r = e.target.closest("[data-case]"); if (r) select(r.dataset.case);
  });
  function select(key){
    if (st.selected !== key){
      st.view = null; st.changed = null;
      $("case").innerHTML = '<div class="empty" role="status">Loading case…</div>';
    }
    st.selected = key;
    for (const el of $("qlist").querySelectorAll(".qrow")){
      const on = el.dataset.case === key;
      el.classList.toggle("sel", on);
      el.setAttribute("aria-selected", on);
      if (on){ el.focus({preventScroll:true}); el.scrollIntoView({block:"nearest"}); }
    }
    loadCase(key, false);
  }
  function move(delta){
    const rows = Array.from($("qlist").querySelectorAll(".qrow"));
    if (!rows.length) return;
    let i = rows.findIndex(r=>r.dataset.case === st.selected);
    i = i < 0 ? 0 : Math.max(0, Math.min(rows.length - 1, i + delta));
    select(rows[i].dataset.case);
  }

  /* ── case pane ───────────────────────────── */
  function showEmpty(){ $("case").innerHTML = emptyCaseHtml; st.view = null; caseSig = ""; st.changed = null; }
  // History entries another analyst added to the open case since it was last shown (newest last).
  const histSig = h=>`${h.timestamp}|${h.action}|${h.actor}`;
  function othersChanges(prev, next){
    if (!prev || prev.case.key !== next.case.key) return [];
    const seen = new Set((prev.history || []).map(histSig));
    return (next.history || []).filter(h=>!seen.has(histSig(h)) && h.actor && h.actor !== actor());
  }
  let caseReq = 0;
  // The queue poll reloads the open case every 5 s. Re-render only when the case actually changed,
  // and keep keyboard focus and the last lookup result when it does (audit 2026-11-26, T1).
  let caseSig = "";
  function focusToken(){
    const a = document.activeElement;
    if (!a || !$("case").contains(a)) return null;
    for (const attr of ["data-act", "data-check", "data-goto", "data-enrich", "data-enrich-ip"])
      if (a.hasAttribute(attr)) return `[${attr}="${CSS.escape(a.getAttribute(attr))}"]`;
    return null;
  }
  async function loadCase(key, quiet){
    if (key !== st.selected) return;
    const my = ++caseReq;
    try {
      const v = await SOC.apiGET(`/api/triage/case/${encodeURIComponent(key)}?limit=50&actor=${encodeURIComponent(actor())}`);
      if (my !== caseReq || key !== st.selected) return;
      const sig = JSON.stringify(v);
      if (quiet && st.view && sig === caseSig){ st.view = v; return; }
      const scroll = $("case").scrollTop, focus = quiet ? focusToken() : null;
      const enrich = quiet && $("enrich-out") ? $("enrich-out").textContent : "";
      const theirs = quiet ? othersChanges(st.view, v) : [];
      if (!quiet) st.changed = null;
      else if (theirs.length){
        const last = theirs.reduce((a, b)=>String(a.timestamp) >= String(b.timestamp) ? a : b);
        st.changed = {count: theirs.length + (st.changed ? st.changed.count : 0), actor: last.actor, action: last.action, at: last.timestamp};
        toast(`${last.actor} updated this case: ${last.action}.`);
      }
      st.view = v; caseSig = sig;
      renderCase(v);
      if (quiet){
        $("case").scrollTop = scroll;
        if (enrich && $("enrich-out")) $("enrich-out").textContent = enrich;
        const el = focus && $("case").querySelector(focus);
        if (el) el.focus({preventScroll: true});
      }
    } catch(e){
      if (my !== caseReq || key !== st.selected) return;
      if (!quiet) $("case").innerHTML = `<div class="nag bad">Could not load the case: ${esc(e.message)}</div>`;
    }
  }
  function can(a){ return st.view && st.view.allowed_actions.includes(a); }
  function icon(item){
    if (item.kind === "manual") return item.checked ? ['yes', "✓"] : ['na', "○"];
    const r = item.auto && item.auto.result;
    if (r === null || r === undefined) return ['na', "–"];
    if (item.kind === "benign") return r ? ['ben', "✓"] : ['na', "✗"];
    if (item.kind === "caution") return r ? ['yes', "!"] : ['no', "✗"];
    return r ? ['yes', "✓"] : ['no', "✗"];
  }
  function renderCase(v){
    const c = v.case, ev = v.evidence, ml = v.ml, sg = v.suggestion;
    const kv = (k, val) => `<span class="k">${esc(k)}</span><span class="v">${val}</span>`;
    const fmtObj = o => Object.entries(o || {}).map(([k,n])=>`<span class="pill2">${esc(k)} ${esc(n)}</span>`).join("") || "—";
    const maxTl = Math.max(1, ...ev.timeline.map(t=>t.count));
    const score = s => s ? `${esc(s.max)} max · ${esc(s.mean)} mean (n=${esc(s.n)})` : "—";
    const pend = v.close_request && v.close_request.status === "pending" ? v.close_request : null;
    const missing = v.checklist.filter(item=>item.kind === "manual" && item.required && !item.checked);
    const indicatorIds = [...(sg.tunnel_indicators || []), ...(sg.benign_indicators || [])];
    const indicators = indicatorIds.map(id=>v.checklist.find(item=>item.id === id)).filter(Boolean);
    const assessment = sg.action === "escalate" ? "Escalation suggested" : sg.action === "close" ? "Closure suggested" : "Review required";
    $("case").innerHTML = `
      <header class="case-overview">
        <span class="case-key">Case ${esc(c.key)}</span>
        <h2>${esc(c.label)}</h2>
        <div class="case-facts">${chipSev(c.priority)} ${chipStatus(c.status)}
          <span class="pill2">${esc(c.client)}</span><span class="pill2">${esc(c.members)} alerts (${esc(c.open_members)} open)</span>
          <span class="pill2">Owner: ${esc(c.owner || "unassigned")}</span>
          ${slaHtml(c, "ack")} ${slaHtml(c, "triage")}
        </div>
      </header>
      ${st.changed ? `<div class="banner changed" role="status"><b>Case changed while you had it open.</b>
        ${esc(st.changed.actor)}: ${esc(st.changed.action)} at ${esc(SOC.fmtDate(st.changed.at))}${st.changed.count > 1 ? ` (+${esc(st.changed.count - 1)} more)` : ""}.
        Re-check the status and owner before you act. <button class="btn sec" data-act="ackchange" style="margin-left:6px">Got it</button></div>` : ""}
      <div class="case-layout">
        <div class="case-main">
          <div class="case-brief">
            <span class="eyebrow">Case brief</span>
            <p>${esc(c.members)} ${c.members === 1 ? "alert" : "alerts"} for ${esc(c.client)}. DNS evidence contains ${esc(ev.total_queries)} queries across ${esc(ev.distinct_names)} distinct names. Review the signals and confirm the affected endpoint before deciding.</p>
            ${c.incident_id ? `<a class="incident-context-link" href="/incidents?id=${encodeURIComponent(c.incident_id)}">View linked incident ${esc(c.incident_id)} ↗</a>` : ""}
            <div class="brief-facts"><span>Priority: <b>${esc(c.priority)}</b> from the highest member alert</span>
              <span>First seen: <b>${esc(SOC.fmtDate(c.first_seen_at))}</b></span>
              <span>Asset impact: <b>not recorded</b></span></div>
          </div>
          ${v.source.warning ? `<div class="banner"><span class="warnip">⚠ Shared source.</span> ${esc(v.source.warning)}</div>` : ""}
          ${pend ? `<div class="banner"><b>Close requested</b> by ${esc(pend.requested_by)} as <b>${esc(CLASS_LABELS[pend.classification] || pend.classification)}</b>: “${esc(pend.comment)}”
            ${can("approve") ? `<div style="margin-top:6px;display:flex;gap:6px"><button class="btn" data-act="approve">Approve and close</button><button class="btn sec" data-act="reject">Reject</button></div>`
              : `<div style="color:var(--muted);margin-top:4px">Waiting for a Tier 2 analyst other than the requester.</div>`}</div>` : ""}
          ${c.next_step ? `<div class="banner"><b>Next step:</b> ${esc(c.next_step)}</div>` : ""}
          <div class="assessment ${esc(sg.action)}" aria-label="Automated assessment">
            <span class="eyebrow">Automated assessment</span><strong>${esc(assessment)}</strong>
            <p>${esc(sg.text)}</p>
            <div class="assessment-signals">${indicators.length ? indicators.map(item=>`<span>${esc(item.label)}</span>`).join("") : '<span>No decisive signal yet</span>'}</div>
            <small>Based on the checks and ML data below. This is a suggestion; only an analyst can decide the outcome.</small>
          </div>
      <h3 class="case-section" id="case-evidence">Evidence <span style="color:var(--muted);font-weight:400;font-size:11.5px">· ${esc(ev.source)}</span></h3>
      <div class="kvtable">
        ${kv("Queries", `${esc(ev.total_queries)} total · ${esc(ev.distinct_names)} distinct names`)}
        ${kv("Busiest 5 min", `${esc(ev.max_5min_queries)} queries · ${esc(ev.max_5min_distinct)} distinct`)}
        ${kv("Query types", fmtObj(ev.query_types))}
        ${kv("Responses", fmtObj(ev.response_codes) + (ev.nxdomain_ratio != null ? ` NXDOMAIN ratio ${esc(ev.nxdomain_ratio)}` : ""))}
        ${kv("Name length", `longest label ${esc(ev.longest_label)} · max ${esc(ev.max_query_length ?? "—")} · mean ${esc(ev.mean_query_length ?? "—")}`)}
        ${kv("Encodings", fmtObj(ev.encodings) + (ev.hex_labels ? ` <span class="pill2">hex ${esc(ev.hex_labels)}</span>` : ""))}
        ${kv("Randomness", `high-entropy ${esc(ev.high_entropy)} · random subdomain ${esc(ev.random_subdomain)}`)}
        ${kv("Seen", `${esc(ev.first_seen || "—")} → ${esc(ev.last_seen || "—")}`)}
        ${kv("Rules", fmtObj(ev.rule_counts))}
        ${kv("ATT&CK", (ev.techniques || []).map(t=>`<span class="pill2">${esc(t)}</span>`).join("") || "—")}
        ${ev.zscores.max ? kv("Strongest Z-score", `${esc(ev.zscores.max.feature)} z=${esc(ev.zscores.max.z)} (value ${esc(ev.zscores.max.value)}, baseline ${esc(ev.zscores.max.baseline_mean)}) · ${esc(ev.zscores.count)} Z-score alerts`) : ""}
      </div>
      ${ev.timeline.length > 1 ? `<div style="margin-top:8px;color:var(--muted);font-size:11px">Queries per minute</div>
        <div class="tl" role="img" aria-label="Queries per minute">${ev.timeline.map(t=>`<span style="height:${Math.max(4, 100*t.count/maxTl).toFixed(0)}%" title="${esc(t.minute)}: ${esc(t.count)}"></span>`).join("")}</div>` : ""}
      <div style="margin-top:8px;color:var(--muted);font-size:11px">Longest names</div>
      <div class="samples">${ev.samples.map(s=>`<div>${esc(s)}</div>`).join("") || "—"}</div>

      <h3 class="case-section" id="case-checklist">DNS-tunnel checklist <span style="color:var(--muted);font-weight:400;font-size:11.5px">· ${esc(c.checklist_done)}/${esc(c.checklist_total)} done · ✓ indicator present, ✗ absent, – no data</span></h3>
      <div id="checklist">${v.checklist.map(item=>{
        const [cls, sym] = icon(item);
        const detail = item.kind === "manual"
          ? (item.checked ? `ticked by ${esc(item.by)} ${esc(SOC.fmtDate(item.at))}${item.note ? " · " + esc(item.note) : ""}` : "manual check")
          : esc((item.auto && item.auto.detail) || "");
        const box = item.kind === "manual"
          ? `<label><input type="checkbox" data-check="${esc(item.id)}" ${item.checked ? "checked" : ""} ${can("checklist") ? "" : "disabled"}> ${esc(item.label)}</label>${item.required ? '<span class="req">required</span>' : ""}`
          : esc(item.label) + (item.kind === "benign" ? ' <span style="color:var(--cyan);font-size:11px">(benign sign)</span>' : item.kind === "caution" ? ' <span style="color:var(--orange);font-size:11px">(caution)</span>' : "");
        return `<div class="chk"><span class="ic ${cls}" aria-hidden="true">${sym}</span><span>${box}</span><span class="d">${detail}</span></div>`;
      }).join("")}</div>

      <h3>ML: why it fired ${ml.demo ? '<span class="chip">synthetic demo scores</span>' : ""}</h3>
      <div class="kvtable">
        ${kv("Path A (Random Forest)", score(ml.score_a) + (ml.thresholds.path_a != null ? ` · threshold ${esc(ml.thresholds.path_a)}` : ""))}
        ${kv("Path B (anomaly)", score(ml.score_b))}
        ${kv("Fusion", score(ml.combined) + (ml.thresholds.fusion != null ? ` · threshold ${esc(Number(ml.thresholds.fusion).toFixed(3))}` : ""))}
        ${kv("Confidence", fmtObj(ml.confidence))}
        ${kv("Signatures", fmtObj(ml.signatures))}
      </div>
      ${ml.top_deviations.length ? `<table class="mini" style="margin-top:8px"><thead><tr><th>Feature</th><th>This case (mean)</th><th>Client baseline</th><th>z</th></tr></thead><tbody>
        ${ml.top_deviations.map(d=>`<tr><td>${esc(d.feature)}</td><td class="num">${esc(d.case_mean)}</td><td class="num">${esc(d.client_mean)}</td><td class="num">${esc(d.z)}</td></tr>`).join("")}</tbody></table>` : ""}
      <div style="color:var(--muted);font-size:11px;margin-top:4px">${esc(ml.deviation_note)}</div>

      <h3>Pivots</h3>
      <div><b style="font-size:12px">Other cases for ${esc(c.client)}</b>: ${v.pivots.host_cases.map(h=>`<span class="pill2 link" data-goto="${esc(h.key)}">${esc(h.label)} (${esc(h.members)})</span>`).join("") || "none"}</div>
      <div style="margin-top:6px"><b style="font-size:12px">Top domains in this case</b>: ${v.pivots.top_domains.map(d=>`<span class="pill2">${esc(d.apex)} (${esc(d.alerts)})</span>`).join("") || "—"}</div>
      ${v.pivots.domain_hosts ? `<div style="margin-top:6px"><b style="font-size:12px">Hosts querying ${esc(c.group)}</b>: ${v.pivots.domain_hosts.map(h=>`<span class="pill2">${esc(h.client)} (${esc(h.queries)})</span>`).join("")}</div>` : ""}
      ${v.top_apex ? `<div style="margin-top:6px"><span class="link" data-enrich="${esc(v.top_apex)}">Look up ${esc(v.top_apex)}</span> · <span class="link" data-enrich-ip="${esc(c.client)}">Look up ${esc(c.client)}</span> <span id="enrich-out" style="color:var(--muted);font-size:11.5px"></span></div>` : ""}

      <h3>Alerts in this case <span style="color:var(--muted);font-weight:400;font-size:11.5px">· showing ${esc(v.members.length)} of ${esc(v.members_total)}</span></h3>
      <table class="mini"><thead><tr><th>Severity</th><th>Rule</th><th>Domain</th><th>Status</th><th>Verdict</th><th>ML</th></tr></thead><tbody>
        ${v.members.map(m=>`<tr title="${esc(m.description)}"><td>${chipSev(m.severity)}</td><td>${esc(m.rule)}</td><td class="samples">${esc(m.domain)}</td>
          <td>${esc(m.status)}</td><td>${esc(m.verdict || "—")}</td><td class="num">${m.ml_combined_score != null ? esc(m.ml_combined_score.toFixed(3)) : "—"}</td></tr>`).join("")}
      </tbody></table>

      ${v.escalations.length ? `<h3>Escalations</h3>${v.escalations.map(e=>`<div class="nag" style="margin-bottom:6px"><b>${esc(SOC.fmtDate(e.ts))} by ${esc(e.actor)}</b>
        <div><b>Summary:</b> ${esc(e.summary)}</div><div><b>Hypothesis:</b> ${esc(e.hypothesis)}</div><div><b>Recommended:</b> ${esc(e.recommended_action)}</div></div>`).join("")}` : ""}
      <h3>History</h3>
      ${v.history.length ? v.history.map(h=>`<div style="font-size:11.5px;color:var(--muted);border-bottom:1px dashed #262b3d;padding:3px 0">
        <span class="num">${esc(SOC.fmtDate(h.timestamp))}</span> · <b style="color:#cfd4e2">${esc(h.action)}</b> by ${esc(h.actor)}${h.note ? " · " + esc(String(h.note).slice(0, 160)) : ""}</div>`).join("") : '<div class="nag">No case actions yet.</div>'}
      <div style="color:var(--dim);font-size:11px;margin-top:12px">${esc(v.guardrail_note)}</div>
        </div>
        <aside class="decision-rail" aria-label="Case decisions">
          <span class="eyebrow">Analyst decision</span><h3>Next action</h3>
          <div class="rail-owner">${c.owner ? `Owned by ${esc(c.owner)}` : "Unassigned case"} · ${esc(c.status)}</div>
          <div class="rail-progress"><b>Required checks</b>
            ${missing.length ? missing.map(item=>`<span>○ ${esc(item.label)}</span>`).join("") : '<span>✓ All required manual checks recorded</span>'}
          </div>
          <div class="acts">
            <button class="btn blue" data-act="claim" title="Assign this case to yourself" ${can("claim") ? "" : "disabled"}>Claim<span class="kbd">c</span></button>
            <button class="btn sec" data-act="release" title="Return this open case to the queue" ${can("release") ? "" : "disabled"}>Release</button>
            <button class="btn" data-act="close" title="Record a classification and reason" ${can("close") ? "" : "disabled"}>Close…<span class="kbd">x</span></button>
            <button class="btn dng" data-act="escalate" title="Send evidence and next steps to Tier 2" ${can("escalate") ? "" : "disabled"}>Escalate…<span class="kbd">e</span></button>
            ${c.incident_id ? `<a class="btn declare-incident" href="/incidents?id=${encodeURIComponent(c.incident_id)}">Open linked incident ↗</a>`
              : `<button class="btn declare-incident" data-act="declare" title="Create a linked incident from this investigation" ${can("declare") ? "" : "disabled"}>Declare incident ↗</button>`}
            ${v.members.some(m=>m.verdict) ? `<button class="btn sec rail-advanced" data-act="clearverdict" title="Withdraw the verdicts on the alerts shown below; they leave the training export">Clear verdicts</button>` : ""}
          </div>
          <a class="rail-jump" href="#case-checklist">Review required checks ↓</a>
          <p class="rail-help">Claim starts your investigation. Release returns unfinished work. Close with a reason, escalate to Tier 2, or declare an incident when the evidence meets incident criteria.</p>
        </aside>
      </div>`;
    tickSla();
  }

  $("case").addEventListener("click", async e=>{
    const a = e.target.closest("[data-act]");
    if (a && !a.disabled) return doAction(a.dataset.act);
    const g = e.target.closest("[data-goto]");
    if (g) return select(g.dataset.goto);
    const en = e.target.closest("[data-enrich],[data-enrich-ip]");
    if (en){
      const kind = en.dataset.enrich ? "domain" : "ip";
      const val = en.dataset.enrich || en.dataset.enrichIp;
      try {
        const r = await SOC.apiGET(`/api/enrich/${kind}/${encodeURIComponent(val)}`);
        const off = r.offline || {};
        const parts = kind === "domain"
          ? [off.internal ? "internal zone" : "public name", off.tranco ? `Tranco #${off.tranco.rank}` : (off.tranco_available ? "not in Tranco" : "Tranco not installed")]
          : [(off.flags || []).join(", ") || "public IP"];
        const on = r.online || {};
        parts.push(on.status === "ok" ? on.detail : `${on.provider}: ${on.status}`);
        $("enrich-out").textContent = "· " + parts.join(" · ");
      } catch(err){ $("enrich-out").textContent = "· lookup failed"; }
    }
  });
  $("case").addEventListener("change", async e=>{
    const cb = e.target.closest("[data-check]");
    if (!cb || !st.view) return;
    const key = st.view.case.key;
    try {
      await post(`/api/triage/case/${key}/checklist`, {item_id: cb.dataset.check, checked: cb.checked});
      if (key === st.selected) loadCase(key, true);
    } catch(err){ cb.checked = !cb.checked; fail(err); }
  });

  /* ── actions + dialogs ───────────────────── */
  for (const b of document.querySelectorAll("dialog [data-close]")){
    b.addEventListener("click", ()=>b.closest("dialog").close());
  }
  async function doAction(act){
    const v = st.view; if (!v) return;
    const key = v.case.key;
    if (act === "claim"){
      const takeover = v.case.owner && v.case.owner !== actor();
      if (takeover && !window.confirm(`${v.case.owner} owns this case. Take it over? They lose ownership and the takeover is recorded in the audit log.`)) return;
      try {
        await post(`/api/triage/case/${key}/claim`, v.case.owner && v.case.owner !== actor() ? {force: true} : {});
        toast("Claimed. Investigation started; review the evidence and checklist next.");
        refreshAll(); loadCase(key, true);
      } catch(e){ fail(e); }
    } else if (act === "ackchange"){
      st.changed = null; renderCase(v); $("qlist").focus();
    } else if (act === "declare"){
      $("d-title").value = `${v.case.label} on ${v.case.client}`;
      $("d-severity").value = v.case.priority;
      $("d-reason").value = ""; $("d-err").textContent = "";
      $("dlg-declare").showModal();
      $("d-reason").focus();
    } else if (act === "release"){
      $("r-next").value = v.case.next_step || "";
      $("dlg-release").showModal();
    } else if (act === "close"){
      // The classification is the training label for the next retraining, so the analyst must choose it;
      // a pre-selected default would leak the suggestion into the labels (audit 2026-11-26, T4).
      const hint = v.suggestion.action === "close" ? " (checks and ML suggest closing)" : "";
      $("c-class").innerHTML = `<option value="" disabled selected>Choose a classification…${esc(hint)}</option>` +
        v.close_classes.map(k=>`<option value="${esc(k)}">${esc(CLASS_LABELS[k] || k)}</option>`).join("");
      $("c-comment").value = ""; $("c-err").textContent = "";
      updateFpNote();
      prepareManualChecks("c-manual", v);
      $("dlg-close").showModal();
      $("c-class").focus();
    } else if (act === "escalate"){
      prepareManualChecks("e-manual", v);
      const ev = v.evidence;
      $("e-summary").value = `${v.case.label} on ${v.case.client}: ${v.case.members} alerts, priority ${v.case.priority}.`;
      $("e-evidence").value = [`${ev.total_queries} queries / ${ev.distinct_names} distinct names; busiest 5 min ${ev.max_5min_queries}`,
        `query types ${Object.entries(ev.query_types).map(([k,n])=>k+" "+n).join(", ")}`,
        `longest label ${ev.longest_label}; encodings ${Object.entries(ev.encodings).map(([k,n])=>k+" "+n).join(", ") || "none"}`,
        `ML fusion max ${v.ml.combined ? v.ml.combined.max : "n/a"}; techniques ${(ev.techniques||[]).join(", ") || "none"}`,
        `samples: ${ev.samples.slice(0,3).join(", ")}`].join("\n");
      $("e-checks").value = v.checklist.filter(i=>i.kind !== "manual" || i.checked).map(i=>{
        const r = i.kind === "manual" ? "done" : (i.auto.result === true ? "YES" : i.auto.result === false ? "no" : "n/a");
        return `${i.label}: ${r}${i.auto && i.auto.detail ? " (" + i.auto.detail + ")" : ""}`;
      }).join("\n");
      $("e-hyp").value = ""; $("e-rec").value = ""; $("e-err").textContent = "";
      $("dlg-esc").showModal();
      $("e-hyp").focus();
    } else if (act === "clearverdict"){
      const fps = v.members.filter(m=>m.verdict).map(m=>m.fp);
      if (!fps.length) return;
      if (!window.confirm(`Clear the verdict on ${fps.length} alert(s)? They will be removed from the training export.`)) return;
      try {
        const r = await post("/api/alerts/bulk", {fps, action: "clearverdict", payload: {}});
        toast(`Cleared ${r.succeeded} verdict(s)` + (r.failed ? `, ${r.failed} refused (see the alert for why)` : "") + ".", r.failed > 0);
        refreshAll(); loadCase(key, true);
      } catch(e){ fail(e); }
    } else if (act === "approve" || act === "reject"){
      const rid = v.close_request && v.close_request.id;
      if (!rid) return;
      try {
        await post(`/api/triage/requests/${rid}/${act}`, {});
        toast(act === "approve" ? "Approved: case closed." : "Rejected: the case stays open.");
        refreshAll(); loadCase(key, true);
      } catch(e){ fail(e); }
    }
  }
  function requiredManual(v){
    return v.checklist.filter(item=>item.kind === "manual" && item.required);
  }
  function prepareManualChecks(target, v){
    $(target).innerHTML = `<fieldset class="manual-confirm"><legend>Required verification</legend>
      <p>Confirm the checks you actually performed. Text in the decision form does not mark the case checklist.</p>
      ${requiredManual(v).map(item=>`<div class="manual-row">
        <label><input type="checkbox" data-manual="${esc(item.id)}" ${item.checked ? "checked" : ""}> ${esc(item.label)}</label>
        ${item.checked ? `<small>Recorded by ${esc(item.by || "an analyst")}</small>` : `<input type="text" data-manual-note="${esc(item.id)}" placeholder="Result or reference (optional)" maxlength="500">`}
      </div>`).join("")}</fieldset>`;
  }
  function unconfirmedManual(target){
    return [...$(target).querySelectorAll("[data-manual]")].filter(box=>!box.checked);
  }
  async function saveManualChecks(target, v){
    for (const item of requiredManual(v)){
      if (item.checked) continue;
      const note = $(target).querySelector(`[data-manual-note="${CSS.escape(item.id)}"]`);
      await post(`/api/triage/case/${v.case.key}/checklist`,
        {item_id: item.id, checked: true, note: note ? note.value.trim() : ""});
    }
  }
  function updateFpNote(){
    const v = st.view;
    $("c-fp-note").hidden = !(v && v.allowed_actions.includes("fp_needs_approval") && FP_CLASSES.includes($("c-class").value));
  }
  $("c-class").addEventListener("change", updateFpNote);
  $("c-submit").addEventListener("click", async ()=>{
    const v = st.view; if (!v) return;
    const comment = $("c-comment").value.trim();
    if (!$("c-class").value){ $("c-err").textContent = "Choose a classification."; $("c-class").focus(); return; }
    if (comment.length < 10){ $("c-err").textContent = "Write at least 10 characters explaining why."; return; }
    const unchecked = unconfirmedManual("c-manual");
    if (unchecked.length){ $("c-err").textContent = "Confirm both required checks before closing."; unchecked[0].focus(); return; }
    try {
      await saveManualChecks("c-manual", v);
      const r = await post(`/api/triage/case/${v.case.key}/close`, {classification: $("c-class").value, comment});
      $("dlg-close").close();
      toast(r.pending_approval ? "Close request sent to Tier 2 for approval." : `Closed ${r.members.ok} alerts.`);
      refreshAll(); loadCase(v.case.key, true);
    } catch(e){ $("c-err").textContent = e.message + (e.data && e.data.missing ? ": " + e.data.missing.map(m=>m.label).join("; ") : ""); }
  });
  $("e-submit").addEventListener("click", async ()=>{
    const v = st.view; if (!v) return;
    const body = {summary: $("e-summary").value, evidence: $("e-evidence").value, checks_done: $("e-checks").value,
                  hypothesis: $("e-hyp").value, recommended_action: $("e-rec").value};
    const empty = Object.entries(body).filter(([,x])=>x.trim().length < 3).map(([k])=>k);
    if (empty.length){ $("e-err").textContent = "Fill in: " + empty.join(", "); return; }
    const unchecked = unconfirmedManual("e-manual");
    if (unchecked.length){ $("e-err").textContent = "Confirm both required checks before escalating."; unchecked[0].focus(); return; }
    try {
      await saveManualChecks("e-manual", v);
      await post(`/api/triage/case/${v.case.key}/escalate`, body);
      $("dlg-esc").close();
      toast("Escalated to Tier 2. The case is back in the queue for Tier 2.");
      refreshAll(); loadCase(v.case.key, true);
    } catch(e){ $("e-err").textContent = e.message + (e.data && e.data.missing ? ": " + e.data.missing.map(m=>m.label).join("; ") : ""); }
  });
  $("d-submit").addEventListener("click", async ()=>{
    const v = st.view; if (!v) return;
    const title = $("d-title").value.trim(), reason = $("d-reason").value.trim();
    if (title.length < 3){ $("d-err").textContent = "Give the incident a specific title."; $("d-title").focus(); return; }
    if (reason.length < 10){ $("d-err").textContent = "Explain why this activity meets incident criteria (at least 10 characters)."; $("d-reason").focus(); return; }
    try {
      const r = await post(`/api/triage/case/${v.case.key}/declare`, {title, severity: $("d-severity").value, reason});
      $("dlg-declare").close();
      requestAnimationFrame(()=>{ window.location.href = `/incidents?id=${encodeURIComponent(r.record.id)}`; });
    } catch(e){ $("d-err").textContent = e.message; }
  });
  $("r-submit").addEventListener("click", async ()=>{
    const v = st.view; if (!v) return;
    try {
      await post(`/api/triage/case/${v.case.key}/release`, {next_step: $("r-next").value});
      $("dlg-release").close(); toast("Released."); refreshAll(); loadCase(v.case.key, true);
    } catch(e){ fail(e); }
  });

  /* handover + approvals */
  let lastHandover = null;
  $("btn-handover").addEventListener("click", async ()=>{
    $("h-body").textContent = "Loading…";
    $("dlg-handover").showModal();
    try {
      const h = lastHandover = await SOC.apiGET("/api/triage/handover?hours=8");
      const m = h.metrics;
      $("h-body").innerHTML = `
        <div>Generated ${esc(SOC.fmtDate(h.generated_at))} · last ${esc(h.window_hours)} h · pipeline ${esc(h.pipeline.status)}</div>
        <div>MTTA median ${esc(m.mtta_seconds.median != null ? dur(m.mtta_seconds.median) : "—")} · ack-SLA breaches ${esc(m.ack_sla_breached)} · open by severity ${esc(Object.entries(m.open_by_severity).map(([k,n])=>k+" "+n).join(", ") || "none")}</div>
        ${h.last_ack ? `<div class="nag">Last acknowledged by <b>${esc(h.last_ack.actor)}</b> at ${esc(SOC.fmtDate(h.last_ack.ts))}${h.last_ack.note ? ": " + esc(h.last_ack.note) : ""}</div>` : '<div class="nag">No handover acknowledged yet.</div>'}
        <b>Open cases (${esc(h.open_cases.length)})</b>
        <table class="mini"><thead><tr><th>Priority</th><th>Case</th><th>Status</th><th>Owner</th><th>Next step</th></tr></thead><tbody>
          ${h.open_cases.map(c=>`<tr><td>${chipSev(c.priority)}</td><td>${esc(c.label)}<br><span style="color:var(--muted)">${esc(c.client)} · ${esc(c.members)} alerts${c.triage_breached ? " · SLA breached" : ""}</span></td>
            <td>${esc(c.status)}</td><td>${esc(c.owner || "—")}</td><td>${esc(c.next_step || "—")}</td></tr>`).join("") || '<tr><td colspan="5">None.</td></tr>'}
        </tbody></table>
        <b>Waiting for Tier 2 approval (${esc(h.pending_close_requests.length)})</b>
        ${h.pending_close_requests.map(r=>`<div class="nag">${esc(r.label)} · ${esc(r.classification)} · by ${esc(r.requested_by)}</div>`).join("") || "<div>None.</div>"}
        <label>Note for the record (optional) <textarea id="h-note" placeholder="e.g. Took over the queue; will follow up on the escalated ML case."></textarea></label>`;
    } catch(e){ $("h-body").innerHTML = `<div class="nag bad">${esc(e.message)}</div>`; }
  });
  $("h-ack").addEventListener("click", async ()=>{
    try {
      await post("/api/triage/handover/ack", {note: ($("h-note") || {}).value || "", report_generated_at: lastHandover && lastHandover.generated_at});
      $("dlg-handover").close(); toast("Handover acknowledged and recorded in the audit log.");
    } catch(e){ fail(e); }
  });
  $("btn-approvals").addEventListener("click", async ()=>{
    $("a-body").textContent = "Loading…";
    $("dlg-approvals").showModal();
    try {
      const r = await SOC.apiGET("/api/triage/requests?status=pending");
      $("a-body").innerHTML = r.records.length ? r.records.map(x=>`<div class="nag" style="margin-bottom:8px">
          <b>${esc(x.label)}</b> (${esc(x.client)}, ${esc(x.priority)}, ${esc(x.member_fps.length)} alerts)<br>
          ${esc(CLASS_LABELS[x.classification] || x.classification)} · requested by ${esc(x.requested_by)} ${esc(SOC.fmtDate(x.requested_at))}<br>“${esc(x.comment)}”
          <div style="margin-top:6px;display:flex;gap:6px">
            <button class="btn sec" data-open="${esc(x.case_key)}">Open case</button>
            ${x.requested_by === actor() ? '<span style="color:var(--muted)">Your own request: another Tier 2 analyst must decide.</span>'
              : `<button class="btn" data-dec="approve" data-rid="${esc(x.id)}">Approve</button><button class="btn sec" data-dec="reject" data-rid="${esc(x.id)}">Reject</button>`}
          </div></div>`).join("") : "<div>No pending requests.</div>";
    } catch(e){ $("a-body").innerHTML = `<div class="nag bad">${esc(e.message)}</div>`; }
  });
  $("a-body").addEventListener("click", async e=>{
    const o = e.target.closest("[data-open]");
    if (o){ $("dlg-approvals").close(); return select(o.dataset.open); }
    const d = e.target.closest("[data-dec]");
    if (!d) return;
    try {
      await post(`/api/triage/requests/${d.dataset.rid}/${d.dataset.dec}`, {});
      toast(d.dataset.dec === "approve" ? "Approved." : "Rejected.");
      $("btn-approvals").click(); refreshAll();
    } catch(err){ fail(err); }
  });
  $("btn-help").addEventListener("click", ()=>$("dlg-help").showModal());

  /* ── keyboard ────────────────────────────── */
  document.addEventListener("keydown", e=>{
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    if (document.querySelector("dialog[open]")) return;
    const k = e.key;
    if (k === "j" || k === "ArrowDown"){ e.preventDefault(); move(1); }
    else if (k === "k" || k === "ArrowUp"){ e.preventDefault(); move(-1); }
    else if (k === "c" && can("claim")) doAction("claim");
    else if (k === "x" && can("close")) doAction("close");
    else if (k === "e" && can("escalate")) doAction("escalate");
    else if (k === "r") refreshAll();
    else if (k === "/"){ e.preventDefault(); $("f-q").focus(); }
    else if (k === "?") $("dlg-help").showModal();
  });

  // keep the top-bar pipeline pill live (cheap: /api/state answers 304 when nothing changed)
  SOC.pollState(()=>{}, 10000);
})();
