const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

async function loadDashboard() {
  let data;
  try {
    data = await api('/api/dashboard');
  } catch (e) {
    const banner = document.getElementById('conn-banner');
    if (banner) {
      banner.style.display = 'block';
      banner.innerHTML = `Backend unreachable. Start it with <code>uvicorn backend.main:app --port 8000</code>, then open this page via <code>http://127.0.0.1:8000</code> (not as a file).`;
    }
    return;
  }
  const banner = document.getElementById('conn-banner');
  if (banner) banner.style.display = 'none';
  const c = data.counts || {};
  const stats = data.stats || { by_severity: {}, days: { events: [0, 0, 0, 0, 0, 0, 0], honey: [0, 0, 0, 0, 0, 0, 0] } };
  const total = c.events ?? 0;
  const sev = stats.by_severity || {};
  const high = (sev.high ?? 0) + (sev.critical ?? 0);
  const active = data.active || [];
  setNum('hero-num', total);
  const threat = data.threat || 'None';
  const ht = document.getElementById('hero-threat');
  if (ht) ht.innerHTML = threat === 'None' ? '' : `<span class="badge ${threat.toLowerCase()}">${esc(threat)}</span>`;
  set('hero-range', `${c.active_sessions ?? 0} active sessions · Mon–Sun`);
  renderChart(stats.days || { events: [0, 0, 0, 0, 0, 0, 0], honey: [0, 0, 0, 0, 0, 0, 0] });
  renderThreat(total, high, active.length, c.honeytokens_triggered ?? 0, sev);
  renderDetect(total, high, sev, c.honeytokens_triggered ?? 0);
  renderSessCard(active, total, c.honeytokens_triggered ?? 0);
  renderHoney(total, c.honeytokens_triggered ?? 0, c.sessions_with_events ?? 0);
  renderProgression(data.progression || []);
  renderFeed(data.recent_commands || []);
  renderRecent(data.recent_events || []);
  renderSessions(active);
}
function set(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }
function setNum(id, v) { const el = document.getElementById(id); if (el) el.textContent = Number(v || 0).toLocaleString('en-US'); }
function smooth(pts) {
  if (pts.length < 2) return pts.length ? `M${pts[0][0]},${pts[0][1]}` : '';
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[Math.max(0, i - 1)], p1 = pts[i], p2 = pts[i + 1], p3 = pts[Math.min(pts.length - 1, i + 2)];
    const c1x = p1[0] + (p2[0] - p0[0]) / 6, c1y = p1[1] + (p2[1] - p0[1]) / 6;
    const c2x = p2[0] - (p3[0] - p1[0]) / 6, c2y = p2[1] - (p3[1] - p1[1]) / 6;
    d += `C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2[0]},${p2[1]}`;
  }
  return d;
}
function renderChart(days) {
  const box = document.getElementById('chart');
  if (!box) return;
  const ev = days.events || [0, 0, 0, 0, 0, 0, 0];
  const hn = days.honey || [0, 0, 0, 0, 0, 0, 0];
  if (!ev.concat(hn).some((v) => v > 0)) {
    box.innerHTML = `<div class="empty"><h4>No activity yet</h4><p>Attack telemetry will chart here by weekday.</p></div>`;
    return;
  }
  const W = 1440, H = 148, max = Math.max(...ev, ...hn, 4);
  // Hand-tuned rhythm: very small / medium / very big bands in 3 shades.
  const FRACS = [0.07, 0.18, 0.10, 0.20, 0.13, 0.14, 0.18];
  const SHADES = ['#C9B8F7', '#E4D9FC', '#A98FF2', '#E4D9FC',
                  '#C9B8F7', '#A98FF2', '#E4D9FC'];
  const edges = [0];
  FRACS.forEach((f) => edges.push(edges[edges.length - 1] + f));
  const BX = (i) => edges[i] * W;
  const BWX = (i) => (edges[i + 1] - edges[i]) * W;
  const CX = (i) => ((edges[i] + edges[i + 1]) / 2) * W;
  const Y = (v) => 110 - (v / max) * 92;
  const bands = ev.map((_, i) => `<rect x="${BX(i).toFixed(1)}" y="0" width="${(BWX(i) + 1).toFixed(1)}" height="148" fill="${SHADES[i]}" opacity=".6"/>`).join('');
  const labels = DAYS.map((d, i) => `<text class="day-label" x="${CX(i)}" y="128" text-anchor="middle" font-size="14">${d}</text>`).join('');
  const evPts = [[0, Y(ev[0])], ...ev.map((v, i) => [CX(i), Y(v)]), [W, Y(ev[6])]];
  const hnPts = [[0, Y(hn[0])], ...hn.map((v, i) => [CX(i), Y(v)]), [W, Y(hn[6])]];
  box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">${bands}
    <path d="${smooth(evPts)}" fill="none" stroke="#141419" stroke-width="3"/>
    <path d="${smooth(hnPts)}" fill="none" stroke="#8B7CF6" stroke-width="2" opacity=".85"/>
    ${labels}</svg>`;
}
function renderThreat(total, high, sessions, honey, sev) {
  const f = total ? high / total : 0;
  const arc = Math.PI * 84;
  const g = document.getElementById('gauge');
  if (g) g.innerHTML = `<svg width="210" height="126" viewBox="0 0 210 126">
    <path d="M21,107 A84,84 0 0 1 189,107" fill="none" stroke="#33333E" stroke-width="12" stroke-linecap="round"/>
    <path d="M21,107 A84,84 0 0 1 189,107" fill="none" stroke="#C9B8F7" stroke-width="12" stroke-linecap="round" stroke-dasharray="${(f * arc).toFixed(1)} ${arc.toFixed(1)}"/></svg>`;
  setNum('gauge-num', total);
  const order = ['critical', 'high', 'medium', 'low'];
  const peak = Math.max(...order.map((s) => sev[s] ?? 0), 1);
  const rows = order.map((s) => {
    const n = sev[s] ?? 0;
    return `<div class="sev-row"><span>${s}</span><div class="barcode"><i style="width:${Math.round((n / peak) * 100)}%"></i></div><b>${n}</b></div>`;
  }).join('');
  const cols = document.getElementById('threat-cols');
  if (cols) cols.innerHTML = `
    <div><b>${sessions}</b><span>Sessions</span></div>
    <div><b>${total ? Math.round(f * 100) + '%' : '—'}</b><span>High</span></div>
    <div><b>${honey}</b><span>Honey</span></div>${rows}`;
}
function renderDetect(total, high, sev, honey) {
  const pct = total ? Math.round((high / total) * 100) : 0;
  set('detect-big', total ? pct + '%' : '0%');
  const bar = document.getElementById('detect-bar');
  if (bar) bar.style.width = pct + '%';
  const cols = document.getElementById('detect-cols');
  if (cols) cols.innerHTML = `
    <div><b>${high}</b><span>High</span></div>
    <div><b>${total}</b><span>Total</span></div>
    <div><b>${honey}</b><span>Honey</span></div>`;
}
function renderSessCard(active, total, honey) {
  setNum('sess-big', active.length);
  const withEv = active.filter((s) => (s.commands ?? 0) > 0).length;
  const bar = document.getElementById('sess-bar');
  if (bar) bar.style.width = (active.length ? Math.round((withEv / active.length) * 100) : 0) + '%';
  const cmds = active.reduce((a, s) => a + (s.commands ?? 0), 0);
  const cols = document.getElementById('sess-cols');
  if (cols) cols.innerHTML = `
    <div><b>${cmds}</b><span>Commands</span></div>
    <div><b>${total}</b><span>Events</span></div>
    <div><b>${honey}</b><span>Honey</span></div>`;
}
function renderHoney(total, honey, sessEv) {
  setNum('honey-big', honey);
  const bar = document.getElementById('honey-bar');
  if (bar) bar.style.width = (total ? Math.round((honey / total) * 100) : 0) + '%';
  const cols = document.getElementById('honey-cols');
  if (cols) cols.innerHTML = `
    <div><b>${honey}</b><span>Touched</span></div>
    <div><b>${sessEv}</b><span>Sessions</span></div>
    <div><b>${total ? Math.round((honey / total) * 100) + '%' : '—'}</b><span>Share</span></div>`;
}
function renderProgression(prog) {
  const box = document.getElementById('progression');
  if (!box) return;
  if (!prog.length) {
    box.innerHTML = `<p class="meta">No stages observed yet.</p>`;
    return;
  }
  box.innerHTML = prog.map((p) => `
    <div class="stage ${p.reached ? 'reached' : ''}">
      <span class="node">${p.reached ? '✓' : '·'}</span>
      <span>${esc(p.stage)}${p.evidence_count ? ` <span class="meta">(${p.evidence_count})</span>` : ''}</span>
    </div>`).join('');
}
function renderFeed(commands) {
  const box = document.getElementById('attack-feed');
  if (!box) return;
  if (!commands.length) {
    box.innerHTML = `<div class="empty"><h4>No attacks observed yet</h4><p>Commands typed in <code>/terminal.html</code> appear here live.</p></div>`;
    return;
  }
  box.innerHTML = commands.map((c) => `
    <div class="event-row"><time>${fmtTime(c.ts)}</time>
      <div><code>${esc(c.command || '')}</code>
      <div class="meta">${esc(c.session_id || '')}${(c.events || []).length ? ` → ${(c.events || []).map((e) => `<span class="badge low">${esc(e)}</span>`).join(' ')}` : ' → <span class="meta">no rule fired</span>'}</div></div>
    </div>`).join('');
}
function renderRecent(events) {
  const box = document.getElementById('recent');
  if (!box) return;
  if (!events.length) {
    box.innerHTML = `<div class="empty"><h4>No security events yet</h4><p>Interact with the deception environment to generate telemetry.</p></div>`;
    return;
  }
  box.innerHTML = events.map((e) => `
    <div class="event-row">
      <span class="badge ${esc(e.severity || 'low')}">${esc(e.severity || '')}</span>
      <div><div>${esc(e.type || '')} <span class="meta">· ${esc(e.session_id || '')} · ${fmtTime(e.timestamp)}</span></div>
      <code>${esc(e.command || '')}</code></div>
    </div>`).join('');
}
function renderSessions(sessions) {
  const box = document.getElementById('sessions');
  if (!box) return;
  if (!sessions.length) {
    box.innerHTML = `<div class="empty"><h4>No active sessions</h4><p>The deception environment is ready for interaction.</p><p class="meta">Interact via the terminal at <code>/terminal.html</code>.</p></div>`;
    return;
  }
  box.innerHTML = sessions.map((s) => `
    <div class="event-row"><div><strong>${esc(s.session_id)}</strong>
    <div class="meta">${s.commands ?? 0} commands · ${esc(s.status || '')} · stage: ${esc(s.stage || '—')} · threat: ${esc(s.threat || 'None')}</div>
    ${(s.interests && Object.keys(s.interests).length) ? `<div class="meta">interests: ${esc(Object.entries(s.interests).map(([k, v]) => `${k}×${v}`).join(', '))}</div>` : ''}</div></div>`).join('');
}
document.addEventListener('DOMContentLoaded', () => {
  loadDashboard();
  const wsProto = location.protocol === 'https:' ? 'wss' : 'ws';
  try {
    const ws = new WebSocket(`${wsProto}://${location.host}/ws/dashboard`);
    ws.onmessage = (m) => {
      try {
        const msg = JSON.parse(m.data);
        if (msg.kind === 'event_batch' || msg.kind === 'session_reset' || msg.kind === 'session_created') loadDashboard();
      } catch {}
    };
  } catch {}
  setInterval(loadDashboard, 5000);
});
