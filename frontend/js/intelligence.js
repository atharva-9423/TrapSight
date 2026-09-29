async function pickLatestActiveSid() {
  try {
    const d = await api('/api/sessions');
    const act = (d.sessions || []).filter((s) => s.status === 'active')
      .sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
    return act.length ? act[0].session_id : '';
  } catch { return ''; }
}
async function loadIntel() {
  // Follow the action: always show the newest active session so the page
  // tracks live attacks (terminal, demo scripts) instead of a stale id.
  const sid = await pickLatestActiveSid();
  const box = document.getElementById('intel');
  if (!sid) {
    box.innerHTML = `<div class="empty"><h4>No session selected</h4><p>Interact via the terminal — intelligence is generated only from real interaction.</p></div>`;
    document.getElementById('intel-sid').textContent = '—';
    return;
  }
  store.sid = sid;
  document.getElementById('intel-sid').textContent = sid;
  let intel;
  try { intel = await api(`/api/sessions/${sid}/intelligence`); }
  catch { box.innerHTML = `<div class="empty"><h4>Session not found</h4><p>It may have been cleared. Start a new session.</p></div>`; return; }
  const ai = intel.ai_analysis || {};
  box.innerHTML = `
    <div class="metrics">
      <div class="card"><h3>Commands</h3><div class="metric">${intel.session.commands}</div><div class="meta">${esc(sid)}</div></div>
      <div class="card"><h3>Events</h3><div class="metric">${intel.session.event_count}</div><div class="meta">behavioral detections</div></div>
      <div class="card"><h3>Duration</h3><div class="metric">${Math.round(intel.session.duration_sec)}<span style="font-size:20px">s</span></div><div class="meta">session length</div></div>
      <div class="card dark"><h3>Threat</h3><div style="margin:10px 0"><span class="badge ${esc((intel.threat || 'none').toLowerCase())}">${esc(intel.threat)}</span></div><div class="meta">${esc(intel.actor.label)} · ${intel.actor.confidence}% confidence</div></div>
    </div>
    <div class="bento4" style="margin-top:12px">
      <div class="card sp2 rs2"><h3>Behavioral profile</h3>
        <p style="font-size:16px;margin:6px 0"><strong>${esc(intel.actor.label)}</strong></p>
        <p class="meta">Observed: ${intel.actor.behaviors.length ? esc(intel.actor.behaviors.join(', ')) : 'no staged behavior yet'}</p>
        <div class="barcode"><i style="width:${intel.actor.confidence}%"></i></div>
        <p class="meta">${intel.actor.confidence}% confidence</p>
        <h3 style="margin-top:14px">Attack progression</h3>
        ${intel.progression.map((p) => `<div class="stage ${p.reached ? 'reached' : ''}"><span class="node">${p.reached ? '✓' : '·'}</span><span>${esc(p.stage)}${p.evidence_count ? ` <span class="meta">(${p.evidence_count})</span>` : ''}</span></div>`).join('')}
      </div>
      <div class="card sp2"><h3>Behavioral assessment</h3>
        <dl class="kv">
          <dt>Behavior</dt><dd>${esc(ai.behavior || '—')}</dd>
          <dt>Confidence</dt><dd>${esc(ai.confidence ?? '—')}</dd>
          <dt>Hypothesis</dt><dd>${esc(ai.intent_hypothesis || '—')}</dd>
          <dt>Severity</dt><dd>${esc(ai.severity || '—')}</dd>
        </dl>
        <p class="meta">Evidence</p>
        <ul>${(ai.evidence || []).map((e) => `<li><code>${esc(e)}</code></li>`).join('') || '<li>—</li>'}</ul>
        <p>${esc(ai.recommended_action || '')}</p>
      </div>
      <div class="card sp2"><h3>MITRE ATT&amp;CK</h3>${intel.mitre.length ? `<table class="clean"><tr><th>ID</th><th>Technique</th></tr>${intel.mitre.map((m) => `<tr><td>${esc(m.id)}</td><td>${esc(m.name)}</td></tr>`).join('')}</table>` : '<div class="empty"><h4>No techniques mapped</h4><p>Mappings appear only when a behavioral rule fires with evidence.</p></div>'}</div>
      <div class="card"><h3>Interests</h3>
        ${intel.interests && Object.keys(intel.interests).length
          ? `<dl class="kv">${Object.entries(intel.interests).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>`
          : '<div class="empty"><h4>None yet</h4></div>'}</div>
      <div class="card"><h3>Replica</h3>
        <dl class="kv">
          <dt>Source</dt><dd>${esc((intel.decoy_manifest || {}).source || '—')}</dd>
          <dt>Files</dt><dd>${((intel.decoy_manifest || {}).files || []).length}</dd>
        </dl>
        <p class="meta">${esc((intel.decoy_manifest || {}).note || '')}</p></div>
      <div class="card sp2"><h3>Deception actions</h3>${(intel.deception_actions || []).length ? intel.deception_actions.map((d) => `<div class="event-row"><div><strong>${esc(d.action)}</strong> → <code>${esc(d.target || '')}</code><div class="meta">${fmtTime(d.timestamp)} · ${esc(d.reason || '')}</div></div></div>`).join('') : '<div class="empty"><h4>No deception deployed</h4><p>Decoys appear here once suspicious behavior is observed.</p></div>'}</div>
      <div class="card sp2"><h3>Indicators</h3>${intel.indicators.length ? `<table class="clean"><tr><th>Type</th><th>Value</th></tr>${intel.indicators.slice(0, 50).map((i) => `<tr><td>${esc(i.type)}</td><td><code>${esc(i.value)}</code></td></tr>`).join('')}</table>` : '<div class="empty"><h4>No indicators collected</h4></div>'}</div>
      <div class="card sp2"><h3>Honeytokens</h3>${intel.honeytokens.length ? intel.honeytokens.map((h) => `<div class="event-row"><span class="badge high">high</span><div>${esc(h.type)}<div class="meta">${fmtTime(h.timestamp)} · ${esc(h.command || '')}</div></div></div>`).join('') : '<div class="empty"><h4>No honeytoken access</h4></div>'}</div>
    </div>`;
}
document.addEventListener('DOMContentLoaded', () => {
  loadIntel();
  setInterval(loadIntel, 3000);
});
