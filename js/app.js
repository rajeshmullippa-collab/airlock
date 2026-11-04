import { ClockedClient, ReplayClient } from './clocked.js';
import { runAirlock, auditReport, ROUTE_LABEL } from './airlock.js';
import { SAMPLES } from './samples.js';

const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const pct = p => (p == null || isNaN(p)) ? '–' : `${Math.round(p * 100)}%`;

const state = { sample: SAMPLES[0], run: null, mode: null };
const keyEl = $('#key'), policyEl = $('#policy'), contentEl = $('#content');
keyEl.value = sessionStorage.getItem('airlock_key') || '';
keyEl.addEventListener('input', () => sessionStorage.setItem('airlock_key', keyEl.value.trim()));

function loadSample(s) {
  state.sample = s;
  policyEl.value = s.policy;
  contentEl.value = s.text;
  document.querySelectorAll('#samples .chip').forEach(c => c.classList.toggle('on', c.dataset.id === s.id));
  updateCount();
}
function updateCount() { $('#count').textContent = `(${contentEl.value.length.toLocaleString()} characters)`; }
contentEl.addEventListener('input', () => { updateCount(); document.querySelectorAll('#samples .chip').forEach(c => c.classList.remove('on')); });

$('#samples').innerHTML = SAMPLES.map(s => `<button class="chip" role="listitem" data-id="${s.id}" title="${esc(s.blurb)}">${esc(s.title)}</button>`).join('')
  + '<button class="chip" data-id="__clear" title="Start from an empty box">Your own text</button>';
$('#samples').addEventListener('click', e => {
  const b = e.target.closest('.chip'); if (!b) return;
  if (b.dataset.id === '__clear') { contentEl.value = ''; policyEl.value = ''; updateCount(); document.querySelectorAll('#samples .chip').forEach(c => c.classList.toggle('on', c === b)); contentEl.focus(); return; }
  loadSample(SAMPLES.find(s => s.id === b.dataset.id));
});

// ---------- step strip ----------
function resetSteps() { document.querySelectorAll('.st').forEach(el => { el.className = 'st'; const sm = el.querySelector('small'); if (sm) sm.remove(); }); }
const inspectState = { total: 0, done: 0, err: 0 };
function onEvent(ev) {
  let key = ev.step.startsWith('inspect') ? 'inspect' : ev.step;
  const el = document.querySelector(`.st[data-s="${key}"]`);
  if (!el) return;
  if (key === 'inspect' && ev.step !== 'inspect') {
    if (ev.status === 'running') inspectState.total++;
    if (ev.status === 'done') inspectState.done++;
    if (ev.status === 'error') inspectState.err++;
    const finished = inspectState.done + inspectState.err === inspectState.total;
    el.className = 'st ' + (inspectState.err ? 'error' : finished ? 'done' : 'running');
    setSmall(el, `${inspectState.done + inspectState.err}/${inspectState.total}`);
    return;
  }
  el.className = 'st ' + ev.status;
  if (ev.status === 'skipped') setSmall(el, 'no scripts');
}
function setSmall(el, t) { let sm = el.querySelector('small'); if (!sm) { sm = document.createElement('small'); el.appendChild(sm); } sm.textContent = t; }

// ---------- run ----------
async function go(mode) {
  const text = contentEl.value;
  if (!text.trim()) { showError('Paste some content first.'); return; }
  let client;
  if (mode === 'live') {
    const key = keyEl.value.trim();
    if (!key) { showError('Paste a Clocked API key to run live, or use "Replay recorded run" on a sample.'); keyEl.focus(); return; }
    client = new ClockedClient({ apiKey: key });
  } else {
    const s = state.sample && SAMPLES.find(x => x.id === state.sample.id);
    const sid = document.querySelector('#samples .chip.on')?.dataset.id;
    const sample = SAMPLES.find(x => x.id === sid) || s || SAMPLES[0];
    loadSample(sample);
    let fx;
    try { fx = await (await fetch(`demo/${sample.id}.json`, { cache: 'no-store' })).json(); }
    catch { showError('The recorded run for this sample is missing.'); return; }
    client = new ReplayClient(fx);
    state.fixture = fx;
  }
  state.mode = mode;
  setBusy(true); resetSteps(); Object.assign(inspectState, { total: 0, done: 0, err: 0 });
  $('#results').innerHTML = '';
  $('#verdict').className = 'verdict idle';
  $('#verdict').innerHTML = `<div class="v-title">Checking…</div><div class="v-sub">${mode === 'live' ? 'Calling Clocked' : 'Replaying the recorded Clocked responses'}.</div>`;
  try {
    const run = await runAirlock(client, { text: contentEl.value, policy: policyEl.value }, onEvent);
    state.run = run;
    render(run);
  } catch (e) {
    showError(e.message || String(e));
  } finally { setBusy(false); }
}
function setBusy(b) { $('#runLive').disabled = b; $('#runDemo').disabled = b; }
function showError(msg) { $('#verdict').className = 'verdict err'; $('#verdict').innerHTML = `<div class="v-title">Could not run</div><div class="v-sub">${esc(msg)}</div>`; }
$('#runLive').onclick = () => go('live');
$('#runDemo').onclick = () => go('replay');

// ---------- rendering ----------
function highlight(text, spans) {
  const ss = spans.filter(s => s.end > s.start && s.start >= 0 && s.end <= text.length).sort((a, b) => a.start - b.start);
  let out = '', pos = 0;
  for (const s of ss) {
    if (s.start < pos) continue;
    out += esc(text.slice(pos, s.start)) + `<mark class="${s.cls}" title="${esc(s.title || '')}">${esc(text.slice(s.start, s.end))}</mark>`;
    pos = s.end;
  }
  return out + esc(text.slice(pos));
}
const bar = (p, cls = '') => `<div class="bar ${cls}"><span style="width:${Math.max(1, Math.round((p || 0) * 100))}%"></span></div>`;
const riskCls = p => p >= 0.5 ? 'bad' : p >= 0.3 ? 'warn' : 'ok';
const tag = (flag) => ({
  injection: '<span class="tag bad">Injection</span>', malicious: '<span class="tag bad">Malicious</span>', suspicious: '<span class="tag warn">Suspicious</span>',
  uncertain: '<span class="tag warn">Uncertain → person</span>', clear: '<span class="tag ok">Clear</span>', error: '<span class="tag bad">Failed</span>',
}[flag] || '');

function render(run) {
  const v = $('#verdict');
  v.className = 'verdict ' + run.route;
  const asks = run.steps.decide?.answers?.asks?.selected || [];
  v.innerHTML = `<div class="v-title">${esc(ROUTE_LABEL[run.route])}${state.mode === 'replay' ? '<span class="replay-badge">RECORDED RUN</span>' : ''}</div>
    <ul>${run.reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>
    <div class="v-meta">${state.mode === 'replay' ? `Real Clocked responses recorded ${esc((state.fixture?.recorded_at || '').slice(0, 10))}` : 'Live'} · ${run.credits ? `${run.credits} Clocked credits · ` : ''}${Object.keys(run.steps).length} calls${asks.length ? ` · asks: ${asks.map(a => a.replace('_', ' ')).join(', ')}` : ''}</div>`;

  const parts = [];
  // What the agent gets
  parts.push(`<div class="card"><div class="card-h"><h3>What your agent gets</h3>${run.safeCopy != null ? `<span class="tag ${run.route === 'block' ? 'bad' : run.route === 'human_review' ? 'warn' : 'info'}">${run.route === 'block' ? 'Do not send' : run.route === 'human_review' ? 'After a person approves' : 'Safe copy'}</span>` : '<span class="tag bad">Withheld</span>'}</div><div class="card-b">
    ${run.safeCopy != null ? `<div class="textview" id="safeView">${markPlaceholders(run.safeCopy)}</div>
    <div class="safe-actions"><button class="ghost small" id="copySafe">Copy safe copy</button><button class="ghost small" id="dlAudit">Download audit report (no personal data)</button></div>`
      : '<p>No safe copy: Protect did not answer, so the text is held back (fail closed).</p>'}
  </div></div>`);

  // Guard
  const g = run.steps.guard;
  if (g) {
    const inj = (g.evidence || []).map(e => ({ start: e.start, end: e.end, cls: 'inj', title: 'Flagged by Guard' }));
    const cats = Object.entries(g.categories || {}).sort((a, b) => b[1] - a[1]).slice(0, 4);
    parts.push(`<div class="card"><div class="card-h"><h3>Guard</h3><span class="ep">/injection</span>${tag(run.guardFlag)}</div><div class="card-b">
      <div class="kv"><div>Injection<b>${pct(g.injection)}</b></div><div>Category<b>${esc(g.category || '–')}</b></div><div>Severity<b>${esc(g.severity || '–')}</b></div></div>
      ${bar(g.injection, riskCls(g.injection))}
      <div class="probs">${cats.map(([k, p]) => `<span>${esc(k)}</span>${bar(p)}<span>${pct(p)}</span>`).join('')}</div>
      ${(g.evidence || []).length ? `<ul class="ev">${g.evidence.map(e => `<li>“${esc(e.quote)}” <span class="muted">chars ${e.start}–${e.end}</span></li>`).join('')}</ul>` : '<p class="muted" style="font-size:13px">No passages flagged.</p>'}
      ${inj.length ? `<details><summary style="font-size:13px;cursor:pointer;margin-top:6px">Show in the original text</summary><div class="textview">${highlight(run.text, inj)}</div></details>` : ''}
    </div></div>`);
  } else parts.push(errCard('Guard', '/injection', run.errors.guard));

  // Inspect
  if (!run.scripts.length) parts.push(`<div class="card"><div class="card-h"><h3>Inspect</h3><span class="ep">/script</span><span class="tag mute">Not needed</span></div><div class="card-b"><p class="muted" style="margin:0;font-size:13px">No code blocks or command lines found, so Inspect was not called.</p></div></div>`);
  for (const sc of run.scripts) {
    const r = sc.result;
    if (!r) { parts.push(errCard('Inspect', '/script', run.errors[sc.id])); continue; }
    const marks = (r.evidence || []).map(e => {
      let s = e.start, en = e.end;
      if (!(sc.code.slice(s, en) === e.line)) { const at = sc.code.indexOf(e.line); if (at >= 0) { s = at; en = at + e.line.length; } }
      return { start: s, end: en, cls: 'scr', title: 'Behind the risk judgment' };
    });
    const withheld = ['malicious', 'suspicious'].includes(sc.flag);
    parts.push(`<div class="card"><div class="card-h"><h3>Inspect</h3><span class="ep">/script · ${sc.blocks.length} block${sc.blocks.length > 1 ? 's' : ''}</span>${tag(sc.flag)}</div><div class="card-b">
      <div class="kv"><div>Malicious<b>${pct(r.malicious)}</b></div><div>Suspicious<b>${pct(r.suspicious)}</b></div><div>Behaviour<b>${esc(r.category || '–')}</b></div><div>Severity<b>${esc(r.severity || '–')}</b></div></div>
      ${bar(r.malicious, riskCls(r.malicious))}
      <div class="textview">${highlight(sc.code, marks)}</div>
      <p class="muted" style="font-size:12.5px;margin:6px 0 0">${withheld ? 'Withheld from the agent.' : 'Left in place.'} Inspect reads the script as text; nothing was executed.</p>
    </div></div>`);
  }

  // Protect
  const p = run.steps.protect;
  if (p) {
    const spans = (p.entities || []).map(e => ({ start: e.start, end: e.end, cls: 'pii', title: e.type }));
    const counts = Object.entries(p.counts || {});
    parts.push(`<div class="card"><div class="card-h"><h3>Protect</h3><span class="ep">/pii</span>${counts.length ? `<span class="tag info">${run.piiCount} masked</span>` : '<span class="tag ok">None found</span>'}</div><div class="card-b">
      <div class="pills">${counts.map(([k, n]) => `<span class="pill pii">${esc(k)} × ${n}</span>`).join('') || '<span class="pill">no personal data or secrets</span>'}</div>
      <details><summary style="font-size:13px;cursor:pointer">Show detected values</summary><div class="textview">${highlight(run.quarantined, spans)}</div></details>
    </div></div>`);
  } else parts.push(errCard('Protect', '/pii', run.errors.protect));

  // Decide
  const d = run.steps.decide;
  if (d && d.answers) {
    const r = d.answers.route || {}, a = d.answers.asks || {};
    const rp = Object.entries(r.probabilities || {});
    parts.push(`<div class="card"><div class="card-h"><h3>Decide</h3><span class="ep">/decide</span><span class="tag ${r.choice === 'block' ? 'bad' : r.choice === 'human_review' ? 'warn' : 'info'}">${esc(ROUTE_LABEL[r.choice] || r.choice || '–')}</span></div><div class="card-b">
      <div class="probs">${rp.map(([k, v]) => `<span>${esc(ROUTE_LABEL[k] || k)}</span>${bar(v, k === 'block' ? 'bad' : k === 'human_review' ? 'warn' : '')}<span>${pct(v)}</span>`).join('')}</div>
      <p style="font-size:13px;margin:10px 0 4px"><b>What the text asks for</b> <span class="muted">(independent probabilities)</span></p>
      <div class="pills">${Object.entries(a.probabilities || {}).sort((x, y) => y[1] - x[1]).map(([k, v]) => `<span class="pill ${(a.selected || []).includes(k) ? 'on' : ''}">${esc(k.replace('_', ' '))} ${pct(v)}</span>`).join('')}</div>
      <p class="muted" style="font-size:12.5px;margin:6px 0 0">Final route = the stricter of Decide's answer and Airlock's policy floors.</p>
    </div></div>`);
  } else parts.push(errCard('Decide', '/decide', run.errors.decide));

  $('#results').innerHTML = parts.join('');
  const cs = $('#copySafe'); if (cs) cs.onclick = async () => { await navigator.clipboard.writeText(run.safeCopy); cs.textContent = 'Copied'; setTimeout(() => cs.textContent = 'Copy safe copy', 1500); };
  const da = $('#dlAudit'); if (da) da.onclick = () => {
    const rep = auditReport(run, { mode: state.mode, sample: document.querySelector('#samples .chip.on')?.dataset.id || 'custom' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(rep, null, 2)], { type: 'application/json' }));
    a.download = `airlock-audit-${Date.now()}.json`; a.click();
  };
}
function markPlaceholders(t) {
  return esc(t).replace(/&lt;[A-Z_]+&gt;/g, m => `<mark class="ph">${m}</mark>`).replace(/\[(instruction removed|script withheld)[^\]]*\]/g, m => `<mark class="rm">${m}</mark>`);
}
function errCard(name, ep, err) {
  return `<div class="card"><div class="card-h"><h3>${name}</h3><span class="ep">${ep}</span><span class="tag bad">Failed</span></div><div class="card-b"><p style="margin:0;font-size:13px">${esc(err?.message || 'No answer')}. Airlock treats a missing check as a reason to hold the text for a person.</p></div></div>`;
}

loadSample(SAMPLES[0]);
const qs = new URLSearchParams(location.search);
if (qs.get('sample')) { const s = SAMPLES.find(x => x.id === qs.get('sample')); if (s) loadSample(s); }
if (qs.get('autoplay') === '1') go('replay');
