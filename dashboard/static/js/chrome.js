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

  async function apiGET(url){
    const r = await fetch(url, {cache:"no-store"});
    if (!r.ok) throw new Error("HTTP "+r.status);
    return r.json();
  }
  async function apiPOST(url, body){
    const r = await fetch(url, {method:"POST", cache:"no-store",
      headers:{"Content-Type":"application/json"}, body:JSON.stringify(body||{})});
    const data = await r.json().catch(()=>({}));
    if (!r.ok) throw Object.assign(new Error(data.error||("HTTP "+r.status)), {code:r.status, data});
    return data;
  }

  // GET /api/state polling helper; onUpdate(state) gets called when state.version changes
  function pollState(onUpdate, interval){
    let version = -1, alive = true, failed = 0;
    async function tick(force){
      try {
        const s = await apiGET("/api/state");
        failed = 0;
        updateChromeFromState(s);
        if (!force && s.version === version) return;
        version = s.version;
        try { onUpdate(s); } catch(e){ console.error(e); }
      } catch(e){
        failed++;
        if (failed >= 2) markDisconnected();
      }
    }
    tick(true);
    const t = setInterval(()=>tick(false), interval || 3000);
    return {stop: ()=>{ alive=false; clearInterval(t); }, forceTick: ()=>tick(true)};
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
    if (act) act.textContent = (localStorage.getItem("soc_actor") || "analyst-1") + "@lab.local";
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

  global.SOC = {mount, pollState, apiGET, apiPOST, fmtDate, relTime, esc, NAV};
})(window);
