/* ──────────────────────────────────────────────────────────────
   Shared top-bar + sidebar + poll helpers for Week 6 pages.
   Usage:  put <div id="app-chrome"></div> at top of body and
           call SOC.mount({active: "events"}).
   ────────────────────────────────────────────────────────────── */
(function(global){
  "use strict";

  const NAV = [
    {href:"#", icon:"▦", label:"Dashboards", cls:"open", caret:"▾"},
    {href:"/soc", label:"Monitoring Overview", key:"soc", cls:"sub"},
    {href:"/usecases", label:"Monitoring Use Cases", key:"usecases", cls:"sub"},
    {href:"/", label:"Classic Dashboard", key:"classic", cls:"sub"},
    {href:"/triage", icon:"✚", label:"Triage (Tier 1)", key:"triage"},
    {href:"/alerts", icon:"⚠", label:"Alerts", key:"alerts"},
    {href:"/events", icon:"◉", label:"Event Explorer", key:"events"},
    {href:"/devices", icon:"🖳", label:"Sources & Collection", key:"devices"},
    {href:"/health", icon:"♥", label:"Pipeline Health", key:"health"},
    {href:"/incidents", icon:"▤", label:"Incidents", key:"incidents"},
    {href:"#", icon:"🔍", label:"Forensic Analysis"},
    {href:"#", icon:"≣", label:"Audit Logs"},
    {href:"#", icon:"⚙", label:"Settings", caret:"▸"},
  ];

  function esc(s){
    if (s === null || s === undefined) return "";
    return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  }

  function renderChrome(active){
    return `
<div class="topbar">
  <div class="logo"><span class="mark">◎</span> Capstone Project</div>
  <div class="topnav">
    <span>⠿ Services <span class="caret">▾</span></span>
    <span>☉ Support <span class="caret">▾</span></span>
  </div>
  <div class="right">
    <span class="pill" id="soc-health-pill"><span class="statusdot" id="soc-status-dot"></span><span id="soc-mode-label">…</span></span>
    <span class="select">English</span>
    <span class="select">Theme: Dark</span>
    <span class="bell">🔔</span>
    <span class="user">👤 <span id="soc-actor-label">soc-analyst@lab.local</span></span>
  </div>
</div>
<div class="wrap">
  <aside class="sidebar">
    <div class="sb-title">SOC AS-A-SERVICE</div>
    <nav class="nav">
      ${NAV.map(n=>{
        const isActive = n.key === active;
        const cls = [n.cls, isActive ? "active" : ""].filter(Boolean).join(" ");
        return `<a class="${esc(cls)}" href="${esc(n.href)}">${n.icon?`<span class="ic">${esc(n.icon)}</span> `:""}${esc(n.label)}${n.caret?` <span class="grp-caret">${esc(n.caret)}</span>`:""}</a>`;
      }).join("")}
    </nav>
    <div class="sb-ver">v1.0 — Capstone (Week 6)</div>
  </aside>
  <main class="main" id="soc-main"></main>
</div>`;
  }

  function fmtDate(iso){
    const d = iso ? new Date(iso) : new Date();
    if (isNaN(d.getTime())) return "—";
    const p = n => String(n).padStart(2,"0");
    return `${p(d.getMonth()+1)}/${p(d.getDate())}/${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

  function relTime(epochSec){
    if (!epochSec) return "—";
    const diff = Date.now()/1000 - epochSec;
    if (diff < 60) return Math.floor(diff) + "s ago";
    if (diff < 3600) return Math.floor(diff/60) + "m ago";
    if (diff < 86400) return Math.floor(diff/3600) + "h ago";
    return Math.floor(diff/86400) + "d ago";
  }

  // server.py rejects POSTs without these (CSRF defence; the custom header forces a CORS preflight)
  const POST_HEADERS = {"Content-Type":"application/json", "X-SOC-Request":"1"};

  async function apiGET(url){
    const r = await fetch(url, {cache:"no-store"});
    if (!r.ok) throw new Error("HTTP "+r.status);
    return r.json();
  }
  async function apiPOST(url, body){
    const r = await fetch(url, {method:"POST", cache:"no-store",
      headers:POST_HEADERS, body:JSON.stringify(body||{})});
    const data = await r.json().catch(()=>({}));
    if (!r.ok) throw Object.assign(new Error(data.error||("HTTP "+r.status)), {code:r.status, data});
    return data;
  }

  // Conditional GET of /api/state: resolves to null when the server answers 304 (nothing changed).
  async function fetchState(etagRef){
    const headers = etagRef && etagRef.etag ? {"If-None-Match": etagRef.etag} : {};
    const r = await fetch("/api/state", {cache:"no-store", headers});
    if (r.status === 304) return null;
    if (!r.ok) throw new Error("HTTP "+r.status);
    if (etagRef) etagRef.etag = r.headers.get("ETag");
    return r.json();
  }

  // GET /api/state polling helper; onUpdate(state) gets called when state.version changes.
  // Pauses while the tab is hidden and catches up as soon as it is visible again.
  function pollState(onUpdate, interval){
    let version = -1, alive = true, failed = 0, busy = false;
    const etagRef = {etag:null};
    async function tick(force){
      if (!alive || busy || (!force && document.hidden)) return;
      busy = true;
      try {
        if (force) etagRef.etag = null;
        const s = await fetchState(etagRef);
        failed = 0;
        if (s === null) return;
        updateChromeFromState(s);
        if (!force && s.version === version) return;
        version = s.version;
        try { onUpdate(s); } catch(e){ console.error(e); }
      } catch(e){
        failed++;
        if (failed >= 2) markDisconnected();
      } finally { busy = false; }
    }
    const onVis = ()=>{ if (!document.hidden) tick(false); };
    document.addEventListener("visibilitychange", onVis);
    tick(true);
    const t = setInterval(()=>tick(false), interval || 3000);
    return {stop: ()=>{ alive=false; clearInterval(t); document.removeEventListener("visibilitychange", onVis); },
            forceTick: ()=>tick(true)};
  }

  // Generic conditional-GET poller (ETag / 304, paused while hidden). urlFn() is re-read every tick.
  function pollJSON(urlFn, onUpdate, interval){
    let alive = true, busy = false, etag = null, lastUrl = null;
    async function tick(force){
      if (!alive || busy || (!force && document.hidden)) return;
      busy = true;
      try {
        const url = typeof urlFn === "function" ? urlFn() : urlFn;
        if (url !== lastUrl){ etag = null; lastUrl = url; }
        const r = await fetch(url, {cache:"no-store", headers: (!force && etag) ? {"If-None-Match": etag} : {}});
        if (r.status === 304) return;
        if (!r.ok) throw new Error("HTTP " + r.status);
        etag = r.headers.get("ETag");
        const data = await r.json();
        try { onUpdate(data); } catch(e){ console.error(e); }
      } catch(e){ /* keep polling */ }
      finally { busy = false; }
    }
    const onVis = ()=>{ if (!document.hidden) tick(false); };
    document.addEventListener("visibilitychange", onVis);
    tick(true);
    const t = setInterval(()=>tick(false), interval || 5000);
    return {stop: ()=>{ alive=false; clearInterval(t); document.removeEventListener("visibilitychange", onVis); },
            refresh: ()=>tick(true)};
  }

  // Analyst list (cached) + current actor helpers
  let analystsPromise = null;
  function analysts(){
    if (!analystsPromise) analystsPromise = apiGET("/api/analysts").then(r=>r.records||[]).catch(()=>[]);
    return analystsPromise;
  }
  function actor(){ try { return localStorage.getItem("soc_actor") || "analyst-1"; } catch(e){ return "analyst-1"; } }
  function setActor(a){ try { localStorage.setItem("soc_actor", a); } catch(e){} }
  function tierOf(role){ const m = /\d/.exec(String(role||"")); return m ? Number(m[0]) : 0; }

  // Keyed DOM patch: renderFn(item) returns the HTML of ONE element. Only rows whose HTML changed
  // are replaced, so scroll position, hover, focus and text selection survive a poll.
  function patchList(container, items, keyFn, renderFn, emptyHtml){
    if (!items.length){
      if (container.dataset.empty !== "1"){ container.innerHTML = emptyHtml || ""; container.dataset.empty = "1"; }
      return;
    }
    if (container.dataset.empty === "1"){ container.innerHTML = ""; delete container.dataset.empty; }
    const existing = new Map();
    for (const el of Array.from(container.children)){
      if (el.dataset && el.dataset.key !== undefined) existing.set(el.dataset.key, el);
      else el.remove();
    }
    const tpl = document.createElement("template");
    let cursor = container.firstElementChild;
    for (const item of items){
      const key = String(keyFn(item));
      const htmlStr = renderFn(item);
      let el = existing.get(key);
      if (!el || el._socHtml !== htmlStr){
        tpl.innerHTML = htmlStr.trim();
        const fresh = tpl.content.firstElementChild;
        fresh.dataset.key = key;
        fresh._socHtml = htmlStr;
        if (el){
          const wasCursor = el === cursor;
          el.replaceWith(fresh);
          if (wasCursor) cursor = fresh;
        }
        el = fresh;
      }
      existing.delete(key);
      if (el !== cursor) container.insertBefore(el, cursor);
      else cursor = cursor.nextElementSibling;
    }
    for (const el of existing.values()) el.remove();
  }

  function updateChromeFromState(s){
    const mode = document.getElementById("soc-mode-label");
    const dot = document.getElementById("soc-status-dot");
    const pill = document.getElementById("soc-health-pill");
    if (mode) mode.textContent = s.mode === "demo" ? "Demo" : "Live";
    if (dot) {
      const st = s.pipeline && s.pipeline.status;
      dot.className = "statusdot" + (st==="running" ? " running" : st==="error" ? " error" : "");
    }
    if (pill && s.health) {
      pill.classList.remove("warn","err");
      if (s.health.band === "Critical") pill.classList.add("err");
      else if (s.health.band === "Warning") pill.classList.add("warn");
      pill.title = (s.health.reasons||[]).join("; ");
    }
    const act = document.getElementById("soc-actor-label");
    if (act && !act.dataset.filled){
      act.dataset.filled = "1";
      analysts().then(list=>{
        const me = list.find(a=>a.id===actor());
        act.textContent = actor() + "@lab.local" + (me ? " · " + me.role : "");
      });
    }
  }
  function markDisconnected(){
    const dot = document.getElementById("soc-status-dot");
    const pill = document.getElementById("soc-health-pill");
    if (dot) dot.className = "statusdot error";
    if (pill) { pill.classList.add("err"); pill.title = "Dashboard server not reachable"; }
  }

  function mount(opts){
    const host = document.getElementById("app-chrome");
    if (!host) throw new Error("app-chrome container missing");
    host.outerHTML = renderChrome(opts && opts.active);
    return document.getElementById("soc-main");
  }

  global.SOC = {mount, pollState, pollJSON, fetchState, patchList, apiGET, apiPOST, fmtDate, relTime, esc, NAV,
                POST_HEADERS, analysts, actor, setActor, tierOf};
})(window);
