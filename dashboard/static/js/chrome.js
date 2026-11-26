/* ──────────────────────────────────────────────────────────────
   Shared top-bar + sidebar + poll helpers for Week 6 pages.
   Usage:  put <div id="app-chrome"></div> at top of body and
           call SOC.mount({active: "events"}).
   ────────────────────────────────────────────────────────────── */
(function(global){
  "use strict";

  const NAV = [
    {href:"/soc", label:"Monitoring overview", key:"soc"},
    {href:"/triage", label:"Triage", key:"triage"},
    {href:"/alerts", label:"Alerts", key:"alerts"},
    {href:"/events", label:"Event explorer", key:"events"},
    {href:"/incidents", label:"Incidents", key:"incidents"},
    {href:"/devices", label:"Sources & collection", key:"devices"},
    {href:"/health", label:"Pipeline health", key:"health"},
    {href:"/usecases", label:"Monitoring use cases", key:"usecases"},
    {href:"/training", label:"Model training", key:"training"},
    {href:"/", label:"Classic dashboard", key:"classic"},
  ];

  function esc(s){
    if (s === null || s === undefined) return "";
    return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  }

  function renderChrome(active){
    return `
<a class="soc-skip" href="#soc-main">Skip to content</a>
<header class="topbar">
  <button type="button" class="soc-menu" aria-expanded="false" aria-controls="soc-sidebar">Menu</button>
  <a class="logo" href="/soc"><span class="mark" aria-hidden="true">◎</span> DNS Operations</a>
  <div class="right">
    <span class="pill" id="soc-health-pill" role="status"><span class="statusdot connecting" id="soc-status-dot" aria-hidden="true"></span><span id="soc-mode-label">Connecting</span></span>
    <span class="soc-actor" id="soc-actor-label"></span>
  </div>
</header>
<div class="wrap">
  <aside class="sidebar" id="soc-sidebar">
    <nav class="nav" aria-label="SOC navigation">
      ${NAV.map(n=>{
        const current = n.key === active ? ' class="active" aria-current="page"' : "";
        return `<a href="${n.href}"${current}>${esc(n.label)}</a>`;
      }).join("")}
    </nav>
  </aside>
<main class="main" id="soc-main" tabindex="-1"></main>
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
    const state = await r.json();
    if (etagRef) etagRef.etag = r.headers.get("ETag");
    return state;
  }

  // GET /api/state polling helper; onUpdate(state) gets called when state.version changes.
  // Pauses while the tab is hidden and catches up as soon as it is visible again.
  function pollState(onUpdate, interval, onStatus = ()=>{}){
    let version = -1, alive = true, failed = 0, busy = false, queued = false, lastSuccess = null;
    const etagRef = {etag:null};
    async function tick(force){
      if (!alive || (!force && document.hidden)) return;
      if (busy){
        queued ||= force;
        return;
      }
      busy = true;
      try {
        if (force || failed >= 2) etagRef.etag = null;
        const s = await fetchState(etagRef);
        if (!alive) return;
        failed = 0;
        if (s === null){
          if (!lastSuccess) throw new Error("State cache unavailable after 304");
          lastSuccess = new Date();
          onStatus({lastSuccess, error:null});
          return;
        }
        updateChromeFromState(s);
        if (force || s.version !== version){
          await onUpdate(s);
          version = s.version;
        }
        lastSuccess = new Date();
        onStatus({lastSuccess, error:null});
      } catch(e){
        failed++;
        onStatus({lastSuccess, error:e});
        if (failed >= 2) markDisconnected();
      } finally {
        busy = false;
        if (queued){
          queued = false;
          tick(true);
        }
      }
    }
    const onVis = ()=>{ if (!document.hidden) tick(false); };
    document.addEventListener("visibilitychange", onVis);
    tick(true);
    const t = setInterval(()=>tick(false), interval || 3000);
    return {stop: ()=>{ alive=false; clearInterval(t); document.removeEventListener("visibilitychange", onVis); },
            forceTick: ()=>tick(true)};
  }

  // Generic conditional-GET poller (ETag / 304, paused while hidden). urlFn() is re-read every tick.
  function pollJSON(urlFn, onUpdate, interval, onStatus = ()=>{}){
    let alive = true, busy = false, queued = false, etag = null, lastUrl = null;
    const currentUrl = () => typeof urlFn === "function" ? urlFn() : urlFn;
    async function tick(force){
      if (!alive || (!force && document.hidden)) return;
      if (busy){
        queued ||= force;
        return;
      }
      busy = true;
      const url = currentUrl();
      try {
        if (url !== lastUrl){ etag = null; lastUrl = url; }
        const r = await fetch(url, {cache:"no-store", headers: (!force && etag) ? {"If-None-Match": etag} : {}});
        if (r.status !== 304){
          if (!r.ok) throw new Error("HTTP " + r.status);
          const data = await r.json();
          if (!alive || url !== currentUrl()) return;
          onUpdate(data);
          etag = r.headers.get("ETag");
        }
        if (alive && url === currentUrl()) onStatus(null);
      } catch(e){
        if (alive && url === currentUrl()) onStatus(e);
      } finally {
        busy = false;
        if (queued){
          queued = false;
          tick(true);
        }
      }
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
  let authenticatedActor = null;
  function analysts(){
    if (!analystsPromise) analystsPromise = apiGET("/api/analysts").then(r=>{
      const records = r.records || [];
      if (r.authenticated && records.length === 1) authenticatedActor = records[0].id;
      return records;
    }).catch(()=>[]);
    return analystsPromise;
  }
  function actor(){ if (authenticatedActor) return authenticatedActor; try { return localStorage.getItem("soc_actor") || "analyst-1"; } catch(e){ return "analyst-1"; } }
  function setActor(a){
    if (authenticatedActor) return;
    try { localStorage.setItem("soc_actor", a); } catch(e){}
    updateActorLabel();
  }
  function updateActorLabel(){
    const label = document.getElementById("soc-actor-label");
    if (!label) return;
    label.textContent = actor();
    analysts().then(list=>{
      const selected = list.find(a=>a.id===actor());
      if (selected) label.textContent = selected.name + " · " + selected.role;
    });
  }
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
    if (mode) {
      const status = s.pipeline?.status;
      const detail = status === "running" ? "Processing" : status === "error" ? "Pipeline error" : s.health?.band;
      const label = (s.mode === "demo" ? "Demo" : "Live") + (detail ? " · " + detail : "");
      if (mode.textContent !== label) mode.textContent = label;
    }
    if (dot) {
      const st = s.pipeline && s.pipeline.status;
      dot.className = "statusdot" + (st==="running" ? " running" : st==="error" ? " error" : "");
    }
    if (pill) {
      pill.classList.remove("warn","err");
      if (s.pipeline?.status === "error" || s.health?.band === "Critical") pill.classList.add("err");
      else if (s.health?.band === "Warning") pill.classList.add("warn");
      pill.title = (s.health?.reasons||[]).join("; ");
    }
  }
  function markDisconnected(){
    const dot = document.getElementById("soc-status-dot");
    const pill = document.getElementById("soc-health-pill");
    const mode = document.getElementById("soc-mode-label");
    if (mode) mode.textContent = "Disconnected";
    if (dot) dot.className = "statusdot error";
    if (pill) { pill.classList.add("err"); pill.title = "Dashboard server not reachable"; }
  }

  function mount(opts){
    const host = document.getElementById("app-chrome");
    if (!host) throw new Error("app-chrome container missing");
    const page = host.querySelector("main");
    document.body.classList.add("soc-shell");
    host.outerHTML = renderChrome(opts?.active);
    const main = document.getElementById("soc-main");
    if (page) main.append(...page.childNodes);
    updateActorLabel();
    const menu = document.querySelector(".soc-menu");
    const sidebar = document.getElementById("soc-sidebar");
    function setMenu(open){
      menu.setAttribute("aria-expanded", String(open));
      sidebar.classList.toggle("is-open", open);
    }
    menu.addEventListener("click", () => setMenu(menu.getAttribute("aria-expanded") === "false"));
    document.addEventListener("keydown", e => {
      if (e.key === "Escape" && sidebar.classList.contains("is-open") && menu.getClientRects().length){
        setMenu(false);
        menu.focus();
      }
    });
    return main;
  }

  global.SOC = {mount, pollState, pollJSON, fetchState, patchList, apiGET, apiPOST, fmtDate, relTime, esc, NAV,
                POST_HEADERS, analysts, actor, setActor, tierOf, updateChromeFromState, markDisconnected};
})(window);
