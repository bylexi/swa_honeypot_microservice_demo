"""
dashboard.py — Live Web-Dashboard für den Honeypot
===================================================
Liest honeypot.log und zeigt ein interaktives Echtzeit-Dashboard.

Start:  python3 dashboard.py
Browser: http://127.0.0.1:8081
"""

import http.server
import json
import os
import sys
import threading
from collections import Counter, defaultdict
from datetime import datetime, timezone

LOG_FILE = os.getenv("HONEYPOT_LOG_FILE", "honeypot.log")
HOST = os.getenv("DASHBOARD_HOST", "127.0.0.1")
PORT = int(os.getenv("DASHBOARD_PORT", "8081"))

# ---------------------------------------------------------------------------
# Log-Parsing
# ---------------------------------------------------------------------------

def parse_log(logfile: str = LOG_FILE) -> list[dict]:
    entries = []
    try:
        with open(logfile, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("{"):
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except FileNotFoundError:
        pass
    return entries


def build_stats(entries: list[dict]) -> dict:
    if not entries:
        return {
            "total_requests": 0,
            "total_attacks": 0,
            "unique_ips": 0,
            "attack_types": {},
            "top_ips": [],
            "recent_attacks": [],
            "timeline": [],
        }

    ip_counter: Counter = Counter()
    attack_type_counter: Counter = Counter()
    attacks_by_ip: dict = defaultdict(int)
    recent_attacks: list[dict] = []
    timeline_buckets: dict = defaultdict(int)     # "HH:MM" → request count
    attack_timeline: dict = defaultdict(int)      # "HH:MM" → attack count

    for e in entries:
        ip = e.get("ip", "?")
        ip_counter[ip] += 1
        atypes = e.get("attack_types", [])

        # Timeline (minute buckets)
        ts_raw = e.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            bucket = ts.strftime("%H:%M")
            timeline_buckets[bucket] += 1
            if atypes:
                attack_timeline[bucket] += 1
        except ValueError:
            pass

        if atypes:
            for a in atypes:
                attack_type_counter[a] += 1
            attacks_by_ip[ip] += 1
            recent_attacks.append(e)

    # Build sorted timeline (last 30 buckets)
    all_buckets = sorted(set(list(timeline_buckets.keys()) + list(attack_timeline.keys())))
    timeline = [
        {
            "t": b,
            "requests": timeline_buckets[b],
            "attacks": attack_timeline[b],
        }
        for b in all_buckets[-30:]
    ]

    top_ips = [
        {
            "ip": ip,
            "requests": count,
            "attacks": attacks_by_ip[ip],
        }
        for ip, count in ip_counter.most_common(8)
    ]

    return {
        "total_requests": len(entries),
        "total_attacks": len(recent_attacks),
        "unique_ips": len(ip_counter),
        "attack_types": dict(attack_type_counter.most_common()),
        "top_ips": top_ips,
        "recent_attacks": recent_attacks[-25:][::-1],   # newest first
        "timeline": timeline,
        "log_file": LOG_FILE,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

HTML = r"""<!DOCTYPE html>
<html lang="de">
<head>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Honeypot Dashboard</title>
<style>
  /* ── Tokens ─────────────────────────────────────────────────────────── */
  :root {
    --bg:        #0b1220;
    --surface:   #111c2e;
    --surface2:  #172038;
    --border:    #1e3050;
    --cyan:      #38d9c0;
    --cyan-dim:  #1d7a6e;
    --red:       #f05a5a;
    --amber:     #f0a830;
    --blue:      #4a8cff;
    --muted:     #4a637a;
    --text:      #cfe0f0;
    --text-dim:  #6a8aaa;
    --mono:      'Courier New', Courier, monospace;
    --sans:      system-ui, -apple-system, sans-serif;
    --radius:    6px;
  }

  /* ── Reset ──────────────────────────────────────────────────────────── */
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { font-size: 15px; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    padding: 0 0 40px;
  }

  /* ── Header ─────────────────────────────────────────────────────────── */
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 28px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .logo-icon {
    width: 32px; height: 32px;
    background: var(--cyan);
    border-radius: 4px;
    display: grid;
    place-items: center;
    flex-shrink: 0;
  }

  .logo-icon svg { display: block; }

  .logo-text {
    display: flex;
    flex-direction: column;
    line-height: 1.2;
  }

  .logo-title {
    font-size: 1rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    color: #fff;
    text-transform: uppercase;
  }

  .logo-sub {
    font-size: 0.72rem;
    color: var(--text-dim);
    font-family: var(--mono);
    letter-spacing: 0.04em;
  }

  .header-right {
    display: flex;
    align-items: center;
    gap: 20px;
  }

  .live-badge {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 0.72rem;
    font-family: var(--mono);
    letter-spacing: 0.1em;
    color: var(--cyan);
    text-transform: uppercase;
  }

  .live-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--cyan);
    animation: pulse 2s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50%       { opacity: 0.4; transform: scale(0.85); }
  }

  .refresh-btn {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text-dim);
    padding: 6px 14px;
    border-radius: var(--radius);
    font-size: 0.78rem;
    font-family: var(--mono);
    cursor: pointer;
    transition: border-color .2s, color .2s;
    letter-spacing: 0.05em;
  }
  .refresh-btn:hover { border-color: var(--cyan); color: var(--cyan); }

  .logfile-tag {
    font-size: 0.72rem;
    font-family: var(--mono);
    color: var(--muted);
    display: none;
  }
  @media (min-width: 700px) { .logfile-tag { display: block; } }

  /* ── Main Grid ───────────────────────────────────────────────────────── */
  main {
    max-width: 1280px;
    margin: 0 auto;
    padding: 24px 28px 0;
    display: grid;
    gap: 20px;
  }

  /* ── KPI Row ─────────────────────────────────────────────────────────── */
  .kpi-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
  }
  @media (max-width: 700px) { .kpi-row { grid-template-columns: repeat(2, 1fr); } }

  .kpi {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px 22px;
    position: relative;
    overflow: hidden;
  }

  .kpi::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--accent, var(--cyan));
  }

  .kpi-label {
    font-size: 0.68rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--text-dim);
    margin-bottom: 10px;
  }

  .kpi-value {
    font-size: 2.1rem;
    font-family: var(--mono);
    font-weight: 700;
    color: var(--accent, var(--cyan));
    line-height: 1;
  }

  .kpi-sub {
    margin-top: 6px;
    font-size: 0.72rem;
    color: var(--text-dim);
    font-family: var(--mono);
  }

  /* ── Mid Row ─────────────────────────────────────────────────────────── */
  .mid-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
  }
  @media (max-width: 900px) { .mid-row { grid-template-columns: 1fr; } }

  /* ── Cards ───────────────────────────────────────────────────────────── */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }

  .card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 18px;
    border-bottom: 1px solid var(--border);
    background: var(--surface2);
  }

  .card-title {
    font-size: 0.72rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-dim);
    font-weight: 600;
  }

  .card-badge {
    font-size: 0.66rem;
    font-family: var(--mono);
    padding: 2px 8px;
    border-radius: 3px;
    background: var(--border);
    color: var(--text-dim);
  }

  .card-body { padding: 18px; }

  /* ── Attack Type Bars ────────────────────────────────────────────────── */
  .atk-bar-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 12px;
  }
  .atk-bar-row:last-child { margin-bottom: 0; }

  .atk-label {
    width: 140px;
    font-size: 0.78rem;
    font-family: var(--mono);
    color: var(--text);
    flex-shrink: 0;
  }

  .atk-bar-wrap {
    flex: 1;
    height: 8px;
    background: var(--border);
    border-radius: 4px;
    overflow: hidden;
  }

  .atk-bar-fill {
    height: 100%;
    border-radius: 4px;
    background: var(--fill-color, var(--cyan));
    transition: width 0.6s cubic-bezier(.4,0,.2,1);
  }

  .atk-count {
    font-size: 0.78rem;
    font-family: var(--mono);
    color: var(--text-dim);
    width: 28px;
    text-align: right;
    flex-shrink: 0;
  }

  /* ── IP Table ────────────────────────────────────────────────────────── */
  .ip-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
    font-family: var(--mono);
  }

  .ip-table th {
    text-align: left;
    color: var(--text-dim);
    font-size: 0.66rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 0 8px 10px;
    border-bottom: 1px solid var(--border);
    font-weight: 500;
  }

  .ip-table td {
    padding: 8px 8px;
    border-bottom: 1px solid var(--border);
    color: var(--text);
    vertical-align: middle;
  }

  .ip-table tr:last-child td { border-bottom: none; }
  .ip-table tr:hover td { background: var(--surface2); }

  .ip-tag {
    font-size: 0.7rem;
    padding: 2px 6px;
    border-radius: 3px;
    background: rgba(240, 90, 90, 0.15);
    color: var(--red);
    border: 1px solid rgba(240, 90, 90, 0.25);
  }

  .ip-tag.clean {
    background: rgba(56, 217, 192, 0.1);
    color: var(--cyan);
    border-color: rgba(56, 217, 192, 0.2);
  }

  /* ── Timeline Chart ──────────────────────────────────────────────────── */
  #timeline-chart {
    width: 100%;
    height: 120px;
    display: block;
  }

  /* ── Log Feed ────────────────────────────────────────────────────────── */
  .log-feed {
    font-family: var(--mono);
    font-size: 0.76rem;
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .log-entry {
    display: grid;
    grid-template-columns: 54px 100px 42px 1fr 80px;
    gap: 0 10px;
    padding: 8px 18px;
    border-bottom: 1px solid var(--border);
    align-items: start;
    transition: background 0.15s;
    animation: flashin 0.5s ease;
  }

  @keyframes flashin {
    from { background: rgba(56, 217, 192, 0.12); }
    to   { background: transparent; }
  }

  .log-entry:hover { background: var(--surface2); }
  .log-entry:last-child { border-bottom: none; }

  .log-entry .ts    { color: var(--muted); }
  .log-entry .ip    { color: var(--blue); }
  .log-entry .meth  { color: var(--text-dim); }
  .log-entry .path  { color: var(--text); word-break: break-all; }
  .log-entry .types { text-align: right; }

  .type-pill {
    display: inline-block;
    font-size: 0.62rem;
    padding: 2px 5px;
    border-radius: 3px;
    margin: 1px;
    white-space: nowrap;
  }

  .pill-sql   { background: rgba(240,90,90,.18); color: var(--red); }
  .pill-xss   { background: rgba(240,168,48,.18); color: var(--amber); }
  .pill-path  { background: rgba(74,140,255,.18); color: var(--blue); }
  .pill-brute { background: rgba(200,90,200,.18); color: #d07ad0; }
  .pill-cmd   { background: rgba(200,200,80,.18); color: #c8c84a; }
  .pill-other { background: rgba(100,150,200,.18); color: var(--text-dim); }

  /* ── Empty State ─────────────────────────────────────────────────────── */
  .empty {
    text-align: center;
    padding: 40px 20px;
    color: var(--text-dim);
    font-size: 0.85rem;
  }
  .empty code {
    display: inline-block;
    margin-top: 10px;
    padding: 4px 10px;
    background: var(--surface2);
    border-radius: 4px;
    color: var(--cyan);
    font-family: var(--mono);
    font-size: 0.8rem;
  }

  /* ── Footer ──────────────────────────────────────────────────────────── */
  footer {
    text-align: center;
    font-size: 0.68rem;
    font-family: var(--mono);
    color: var(--muted);
    margin-top: 28px;
    letter-spacing: 0.06em;
  }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">
      <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
        <path d="M9 1L2 5v8l7 4 7-4V5L9 1z" stroke="#0b1220" stroke-width="1.5" fill="none"/>
        <circle cx="9" cy="9" r="2.5" fill="#0b1220"/>
        <path d="M9 6.5V4M9 14v-2.5M4 9H1.5M16.5 9H14" stroke="#0b1220" stroke-width="1.2" stroke-linecap="round"/>
      </svg>
    </div>
    <div class="logo-text">
      <span class="logo-title">Honeypot</span>
      <span class="logo-sub">Security Dashboard</span>
    </div>
  </div>
  <div class="header-right">
    <span class="logfile-tag" id="logfile-tag">—</span>
    <div class="live-badge">
      <div class="live-dot"></div>
      Live
    </div>
    <button class="refresh-btn" onclick="fetchData()">↺ Refresh</button>
  </div>
</header>

<main>
  
  <!-- KPIs -->
  <div class="kpi-row">
    <div class="kpi" style="--accent: var(--cyan)">
      <div class="kpi-label">Requests gesamt</div>
      <div class="kpi-value" id="kpi-requests">—</div>
      <div class="kpi-sub" id="kpi-req-sub">&nbsp;</div>
    </div>
    <div class="kpi" style="--accent: var(--red)">
      <div class="kpi-label">Erkannte Angriffe</div>
      <div class="kpi-value" id="kpi-attacks">—</div>
      <div class="kpi-sub" id="kpi-atk-sub">&nbsp;</div>
    </div>
    <div class="kpi" style="--accent: var(--blue)">
      <div class="kpi-label">Unique IPs</div>
      <div class="kpi-value" id="kpi-ips">—</div>
      <div class="kpi-sub">&nbsp;</div>
    </div>
    <div class="kpi" style="--accent: var(--amber)">
      <div class="kpi-label">Häufigster Angriff</div>
      <div class="kpi-value" id="kpi-top-type" style="font-size:1rem;padding-top:6px">—</div>
      <div class="kpi-sub" id="kpi-top-count">&nbsp;</div>
    </div>
  </div>

  <div class="card" style="grid-column: 1 / -1;">
    <div class="card-header">
    <span class="card-title">Live Angriffs-Karte</span>
    <span class="card-badge">Geo-IP Tracking</span>
    </div>
    <div id="map" style="height: 350px; width: 100%;"></div>
  </div>

  <!-- Timeline -->
  <div class="card">
    <div class="card-header">
      <span class="card-title">Aktivitäts-Verlauf</span>
      <span class="card-badge" id="timeline-range">letzte 30 Minuten</span>
    </div>
    <div class="card-body" style="padding: 14px 18px;">
      <svg id="timeline-chart"></svg>
    </div>
  </div>

  <!-- Mid row -->
  <div class="mid-row">

    <!-- Attack types -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Angriffstypen</span>
        <span class="card-badge" id="atk-total-badge">0 erkannt</span>
      </div>
      <div class="card-body" id="atk-bars">
        <div class="empty">Noch keine Angriffe.<br><code>python3 attacker_sim.py</code></div>
      </div>
    </div>

    <!-- Top IPs -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Top IPs</span>
        <span class="card-badge" id="ip-count-badge">0 IPs</span>
      </div>
      <div class="card-body" style="padding:0" id="ip-table-wrap">
        <div class="empty" style="padding:30px">Keine Requests.<br><code>python3 attacker_sim.py</code></div>
      </div>
    </div>

  </div>

  <!-- Live feed -->
  <div class="card">
    <div class="card-header">
      <span class="card-title">Letzte Angriffe</span>
      <span class="card-badge">Live Feed</span>
    </div>
    <div id="log-feed-wrap">
      <div class="empty" style="padding:40px">
        Keine Angriffe erkannt.<br>
        <code>python3 attacker_sim.py</code>
      </div>
    </div>
  </div>

</main>

<footer id="footer-ts">Letzte Aktualisierung: —</footer>

<script>
// Karte initialisieren (Zentriert auf Europa/Welt)
const map = L.map('map').setView([20, 0], 2);

// Dark-Mode Karten-Tiles laden (CartoDB)
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
  attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
  subdomains: 'abcd',
  maxZoom: 20
}).addTo(map);

// Layer für die Marker, damit wir sie bei jedem Refresh löschen können
const markerLayer = L.layerGroup().addTo(map);

function renderMap(d) {
  markerLayer.clearLayers(); 

  const dataToDraw = d.recent_requests || d.recent_attacks || [];
  
  if (dataToDraw.length > 0) {
      console.log("Details des ersten Eintrags:", dataToDraw[0]);
  }
  
  let drawnCount = 0;

  dataToDraw.forEach(atk => {
    // Wir prüfen nur noch, ob 'geo' da ist und ob lat/lon nicht null sind
    if (atk.geo && atk.geo.lat != null && atk.geo.lon != null) {
      
      const isAttack = (atk.attack_types && atk.attack_types.length > 0);
      const color = isAttack ? '#f05a5a' : '#38d9c0';
      const typeText = isAttack ? atk.attack_types.join(', ') : 'Normale Anfrage';
      
      L.circleMarker([atk.geo.lat, atk.geo.lon], {
        radius: 8,
        fillColor: color,
        color: color,
        weight: 2,
        opacity: 0.9,
        fillOpacity: 0.6
      })
      .bindPopup(`<b>IP:</b> ${atk.ip}<br><b>Land:</b> ${atk.geo.country || 'Unbekannt'}<br><b>Typ:</b> ${typeText}`)
      .addTo(markerLayer);

      drawnCount++;
    }
  });

  console.log(`Es wurden ${drawnCount} Marker auf der Karte platziert.`);
}

const PILL = {
  sql_injection:   'pill-sql',
  xss:             'pill-xss',
  path_traversal:  'pill-path',
  login_bruteforce:'pill-brute',
  command_injection:'pill-cmd',
};

const ATK_COLORS = {
  sql_injection:   '#f05a5a',
  xss:             '#f0a830',
  path_traversal:  '#4a8cff',
  login_bruteforce:'#d07ad0',
  command_injection:'#c8c84a',
};

function pillClass(t) { return PILL[t] || 'pill-other'; }
function fmtTime(ts) {
  try { return ts.slice(11, 19); } catch { return ts; }
}

// ── KPIs ──────────────────────────────────────────────────────────────────
function renderKPIs(d) {
  document.getElementById('kpi-requests').textContent = d.total_requests;
  document.getElementById('kpi-attacks').textContent  = d.total_attacks;
  document.getElementById('kpi-ips').textContent      = d.unique_ips;

  const pct = d.total_requests
    ? Math.round(100 * d.total_attacks / d.total_requests) : 0;
  document.getElementById('kpi-atk-sub').textContent = `${pct}% aller Requests`;
  document.getElementById('kpi-req-sub').textContent =
    d.log_file ? `aus ${d.log_file}` : '';

  document.getElementById('logfile-tag').textContent =
    d.log_file ? `log: ${d.log_file}` : '';

  const types = Object.entries(d.attack_types || {});
  if (types.length) {
    const [topName, topCnt] = types[0];
    document.getElementById('kpi-top-type').textContent =
      topName.replace('_', ' ');
    document.getElementById('kpi-top-count').textContent = `${topCnt}× erkannt`;
  } else {
    document.getElementById('kpi-top-type').textContent = '—';
    document.getElementById('kpi-top-count').textContent = '';
  }
}

// ── Attack Type Bars ───────────────────────────────────────────────────────
function renderAtkBars(d) {
  const wrap  = document.getElementById('atk-bars');
  const badge = document.getElementById('atk-total-badge');
  const types = Object.entries(d.attack_types || {});
  const total = Object.values(d.attack_types || {}).reduce((a,b)=>a+b,0);
  badge.textContent = `${total} erkannt`;

  if (!types.length) {
    wrap.innerHTML =
      '<div class="empty">Keine Angriffe.<br><code>python3 attacker_sim.py</code></div>';
    return;
  }

  const max = types[0][1] || 1;
  wrap.innerHTML = types.map(([name, cnt]) => {
    const pct   = Math.round(100 * cnt / max);
    const color = ATK_COLORS[name] || '#6a8aaa';
    const label = name.replace(/_/g, ' ');
    return `<div class="atk-bar-row">
      <span class="atk-label">${label}</span>
      <div class="atk-bar-wrap">
        <div class="atk-bar-fill" style="width:${pct}%;--fill-color:${color}"></div>
      </div>
      <span class="atk-count">${cnt}</span>
    </div>`;
  }).join('');
}

// ── IP Table ───────────────────────────────────────────────────────────────
function renderIPTable(d) {
  const wrap  = document.getElementById('ip-table-wrap');
  const badge = document.getElementById('ip-count-badge');
  badge.textContent = `${d.unique_ips} IPs`;

  if (!d.top_ips || !d.top_ips.length) {
    wrap.innerHTML =
      '<div class="empty" style="padding:30px">Keine Requests.<br><code>python3 attacker_sim.py</code></div>';
    return;
  }

  const rows = d.top_ips.map(r => {
    const tag = r.attacks > 0
      ? `<span class="ip-tag">${r.attacks} Angriffe</span>`
      : `<span class="ip-tag clean">clean</span>`;
    return `<tr>
      <td class="ip">${r.ip}</td>
      <td>${r.requests}</td>
      <td>${tag}</td>
    </tr>`;
  }).join('');

  wrap.innerHTML = `<table class="ip-table">
    <thead><tr>
      <th>IP-Adresse</th><th>Requests</th><th>Status</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

// ── Timeline SVG ───────────────────────────────────────────────────────────
function renderTimeline(d) {
  const svg   = document.getElementById('timeline-chart');
  const W     = svg.parentElement.clientWidth - 36;
  const H     = 110;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.setAttribute('width', W);
  svg.setAttribute('height', H);

  const tl = d.timeline || [];
  if (!tl.length) {
    svg.innerHTML =
      `<text x="${W/2}" y="${H/2}" text-anchor="middle"
        fill="#4a637a" font-size="12" font-family="monospace">
        Keine Daten vorhanden</text>`;
    return;
  }

  const range  = document.getElementById('timeline-range');
  range.textContent = `${tl.length} Minuten`;

  const maxReq = Math.max(...tl.map(b => b.requests), 1);
  const maxAtk = Math.max(...tl.map(b => b.attacks), 1);
  const n      = tl.length;
  const pad    = 8;
  const uw     = (W - pad * 2) / n;   // unit width

  // grid lines
  const gridLines = [0.25, 0.5, 0.75, 1].map(f => {
    const y = H - pad - f * (H - pad * 2);
    return `<line x1="${pad}" y1="${y}" x2="${W - pad}" y2="${y}"
      stroke="#1e3050" stroke-width="1" stroke-dasharray="3,4"/>`;
  }).join('');

  // requests area
  const reqPts = tl.map((b, i) => {
    const x = pad + i * uw + uw / 2;
    const y = H - pad - (b.requests / maxReq) * (H - pad * 2);
    return `${x},${y}`;
  }).join(' ');

  const firstX = pad + uw / 2;
  const lastX  = pad + (n - 1) * uw + uw / 2;
  const reqArea = `M ${firstX} ${H - pad} L ${reqPts.split(' ').map((p,i) =>
    i === 0 ? p : p).join(' L ')} L ${lastX} ${H - pad} Z`;

  // attacks line
  const atkLine = tl.map((b, i) => {
    const x = pad + i * uw + uw / 2;
    const y = H - pad - (b.attacks / (maxAtk || 1)) * (H - pad * 2);
    return `${i === 0 ? 'M' : 'L'} ${x} ${y}`;
  }).join(' ');

  // time labels (show ~6 evenly spaced)
  const step = Math.max(1, Math.floor(n / 6));
  const labels = tl.filter((_, i) => i % step === 0 || i === n - 1)
    .map((b, i, arr) => {
      const origIdx = tl.indexOf(b);
      const x = pad + origIdx * uw + uw / 2;
      return `<text x="${x}" y="${H - 1}" text-anchor="middle"
        fill="#4a637a" font-size="9" font-family="monospace">${b.t}</text>`;
    }).join('');

  svg.innerHTML = `
    <defs>
      <linearGradient id="req-grad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#38d9c0" stop-opacity="0.25"/>
        <stop offset="100%" stop-color="#38d9c0" stop-opacity="0.02"/>
      </linearGradient>
    </defs>
    ${gridLines}
    <path d="${reqArea}" fill="url(#req-grad)" stroke="none"/>
    <polyline points="${reqPts}" fill="none" stroke="#38d9c0"
      stroke-width="1.5" stroke-linejoin="round"/>
    <path d="${atkLine}" fill="none" stroke="#f05a5a"
      stroke-width="1.5" stroke-linejoin="round" stroke-dasharray="4,3"/>
    ${labels}
    <circle cx="12" cy="10" r="4" fill="#38d9c0" opacity="0.7"/>
    <text x="20" y="14" fill="#6a8aaa" font-size="9" font-family="monospace">Requests</text>
    <circle cx="74" cy="10" r="4" fill="#f05a5a" opacity="0.7"/>
    <text x="82" y="14" fill="#6a8aaa" font-size="9" font-family="monospace">Angriffe</text>
  `;
}

// ── Log Feed ───────────────────────────────────────────────────────────────
function renderFeed(d) {
  const wrap = document.getElementById('log-feed-wrap');
  const attacks = d.recent_attacks || [];

  if (!attacks.length) {
    wrap.innerHTML =
      '<div class="empty" style="padding:40px">Keine Angriffe erkannt.<br><code>python3 attacker_sim.py</code></div>';
    return;
  }

  const rows = attacks.map(e => {
    const types = (e.attack_types || []).map(t =>
      `<span class="type-pill ${pillClass(t)}">${t.replace(/_/g,' ')}</span>`
    ).join('');
    const path = (e.path || '').length > 55
      ? e.path.slice(0, 55) + '…' : (e.path || '—');
    return `<div class="log-entry">
      <span class="ts">${fmtTime(e.timestamp)}</span>
      <span class="ip">${e.ip || '?'}</span>
      <span class="meth">${e.method || ''}</span>
      <span class="path" title="${e.path || ''}">${path}</span>
      <span class="types">${types}</span>
    </div>`;
  }).join('');

  wrap.innerHTML = `<div class="log-feed">${rows}</div>`;
}

// ── Fetch & Render ─────────────────────────────────────────────────────────
async function fetchData() {
  try {
    const res  = await fetch('/api/data?t=' + Date.now()); 
    const data = await res.json();
    renderKPIs(data);
    renderAtkBars(data);
    renderIPTable(data);
    renderTimeline(data);
    renderFeed(data);
    renderMap(data); // Karte updaten
    document.getElementById('footer-ts').textContent =
      'Letzte Aktualisierung: ' + new Date().toLocaleTimeString('de-AT');
  } catch (err) {
    console.error('Fetch error:', err);
  }
}

// Initial + auto-refresh every 5 s
fetchData();
setInterval(fetchData, 5000);
window.addEventListener('resize', () => {
  fetch('/api/data').then(r => r.json()).then(renderTimeline);
});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class DashboardHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # suppress default access log

    def do_GET(self):
        # Schneidet alles ab dem '?' ab (ignoriert also den t=... Parameter)
        clean_path = self.path.split('?')[0]

        if clean_path == "/" or clean_path == "/index.html":
            self._serve_html()
        elif clean_path == "/api/data":
            self._serve_json()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")

    def _serve_html(self):
        body = HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_json(self):
        entries = parse_log(LOG_FILE)
        stats   = build_stats(entries)
        body    = json.dumps(stats, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def run():
    if not os.path.exists(LOG_FILE):
        print(f"  [HINWEIS] Log-Datei '{LOG_FILE}' nicht gefunden.")
        print( "            Starte zuerst honeypot.py — das Dashboard läuft trotzdem.")
        print()

    server = http.server.ThreadingHTTPServer((HOST, PORT), DashboardHandler)
    print(f"""
╔══════════════════════════════════════════╗
║   Honeypot Dashboard gestartet           ║
╠══════════════════════════════════════════╣
║   URL:      http://{HOST}:{PORT}         ║
║   Log-File: {LOG_FILE:<32}║
║   Refresh:  alle 5 Sekunden              ║
╚══════════════════════════════════════════╝

Strg+C zum Beenden.
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard gestoppt.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        LOG_FILE = sys.argv[1]
    run()
