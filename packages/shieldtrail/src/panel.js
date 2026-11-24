/*
 * ShieldTrail dev panel. Served by the dev server (shieldtrail/node, NODE_ENV=development) at
 * http://127.0.0.1:4320/panel.js. Add it to your app's layout:
 *   <script src="http://127.0.0.1:4320/panel.js" async></script>
 * A small shield appears in the corner of a page only when agent activity happened since the page
 * was requested, or when a step waits for your approval. The same script, with data-full, is the
 * full dashboard at http://127.0.0.1:4320/.
 * Plain browser JavaScript, no dependencies; everything renders in a Shadow DOM and data is only
 * ever inserted as text, never as HTML.
 */
(() => {
  const script = document.currentScript;
  if (!script || window.__shieldtrailPanel) return;
  window.__shieldtrailPanel = true;

  const API = new URL(script.src).origin;
  const FULL = script.hasAttribute('data-full');
  // everything since this page was requested, server rendering included (same machine, same clock)
  const SINCE = FULL ? 0 : Math.floor(performance.timeOrigin);
  const POLL_MS = 1500;

  const C = {
    bg: '#12141f', card: '#191c2b', line: '#2a2e44', text: '#e9e9f2', muted: '#9b9db3',
    ok: '#22c55e', alert: '#eab308', would: '#f59e0b', block: '#ef4444', ask: '#a78bfa', accent: '#2dd4bf',
  };
  const ACTION = {
    allow: { color: C.ok, label: 'allowed' },
    alert: { color: C.alert, label: 'alert' },
    would_block: { color: C.would, label: 'would block' },
    block: { color: C.block, label: 'BLOCKED' },
    ask: { color: C.ask, label: 'waiting' },
  };
  const EDGE = { sequence: '#5b5f7a', taint: C.block, data: C.would, rule: C.ask };
  const VERDICT = { active: 'works', shadowed: 'never decides', unused: 'no match yet' };

  const CSS = `
  :host { all: initial; }
  * { box-sizing: border-box; }
  .root { font: 13px/1.45 ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif; color: ${C.text}; }
  button { font: inherit; color: inherit; cursor: pointer; }
  a { color: ${C.accent}; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .badge { position: fixed; right: 18px; bottom: 18px; z-index: 2147483646; width: 44px; height: 44px; border-radius: 50%;
    border: 2px solid var(--c); background: ${C.bg}; display: grid; place-items: center; box-shadow: 0 6px 24px rgba(0,0,0,.35); }
  .badge svg { width: 22px; height: 22px; }
  .badge .n { position: absolute; top: -6px; right: -6px; min-width: 20px; height: 20px; padding: 0 5px; border-radius: 10px;
    background: var(--c); color: #0b0c12; font-weight: 700; font-size: 11px; display: grid; place-items: center; }
  .pulse { animation: pulse 1.2s ease-in-out infinite; }
  @keyframes pulse { 50% { box-shadow: 0 0 0 8px rgba(167,139,250,.25); } }
  @media (prefers-reduced-motion: reduce) { .pulse { animation: none; } }
  .card { position: fixed; right: 18px; bottom: 72px; z-index: 2147483647; width: min(470px, calc(100vw - 24px));
    max-height: min(72vh, 640px); display: flex; flex-direction: column; background: ${C.bg}; border: 1px solid ${C.line};
    border-radius: 14px; box-shadow: 0 18px 60px rgba(0,0,0,.5); overflow: hidden; }
  .full { position: fixed; inset: 0; display: flex; flex-direction: column; background: ${C.bg}; }
  .head { display: flex; align-items: center; gap: 8px; padding: 10px 12px; border-bottom: 1px solid ${C.line}; }
  .head .chip { flex: none; }
  .brand { font-weight: 700; display: flex; align-items: center; gap: 6px; flex: none; }
  .brand svg { width: 16px; height: 16px; }
  .chip { display: inline-block; padding: 1px 7px; border-radius: 999px; font-size: 11px; font-weight: 600; border: 1px solid currentColor; white-space: nowrap; }
  .tabs { display: flex; gap: 2px; margin-left: auto; overflow-x: auto; scrollbar-width: none; }
  .tab { background: none; border: 0; padding: 4px 8px; border-radius: 7px; color: ${C.muted}; white-space: nowrap; }
  .tab[aria-selected="true"] { background: ${C.card}; color: ${C.text}; }
  .x { background: none; border: 0; color: ${C.muted}; font-size: 18px; line-height: 1; padding: 0 4px; }
  .body { overflow: auto; padding: 10px 12px; flex: 1; scrollbar-width: thin; }
  .foot { display: flex; gap: 10px; align-items: center; padding: 8px 12px; border-top: 1px solid ${C.line}; font-size: 12px; flex-wrap: wrap; }
  .foot .stop { margin-left: auto; }
  .btn { background: ${C.card}; border: 1px solid ${C.line}; border-radius: 8px; padding: 4px 10px; }
  .btn.danger { border-color: ${C.block}; color: ${C.block}; }
  .btn.go { border-color: ${C.ok}; color: ${C.ok}; }
  .muted { color: ${C.muted}; }
  .empty { color: ${C.muted}; padding: 18px 4px; text-align: center; }
  .banner { margin: 0 0 10px; padding: 8px 10px; border-radius: 9px; border: 1px solid ${C.block}; color: ${C.block}; display: flex; gap: 8px; align-items: center; }
  .task { border: 1px solid ${C.line}; border-radius: 11px; margin-bottom: 10px; background: ${C.card}; }
  .task > .t { display: flex; gap: 8px; align-items: center; padding: 8px 10px; border-bottom: 1px solid ${C.line}; }
  .task > .t b { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .task > .t .chip { margin-left: auto; }
  .step { display: grid; grid-template-columns: 92px 1fr; gap: 2px 8px; padding: 6px 10px; border-bottom: 1px solid rgba(42,46,68,.6); }
  .step:last-child { border-bottom: 0; }
  .step .what { overflow-wrap: anywhere; }
  .step .why { grid-column: 2; color: ${C.muted}; font-size: 12px; }
  .ask { border: 1px solid ${C.ask}; border-radius: 11px; padding: 10px; margin-bottom: 10px; background: ${C.card}; }
  .ask .acts { display: flex; gap: 8px; margin-top: 8px; }
  pre { margin: 6px 0 0; padding: 6px 8px; background: #0b0c14; border-radius: 7px; white-space: pre-wrap; overflow-wrap: anywhere; font: 11px/1.4 ui-monospace, Menlo, monospace; color: ${C.muted}; max-height: 120px; overflow: auto; }
  .rule { border-bottom: 1px solid ${C.line}; padding: 8px 0; display: grid; grid-template-columns: 1fr auto; gap: 2px 10px; align-items: center; }
  .rule .d { grid-column: 1; color: ${C.muted}; font-size: 12px; }
  .seg { display: inline-flex; border: 1px solid ${C.line}; border-radius: 8px; overflow: hidden; grid-row: span 2; }
  .seg button { background: none; border: 0; padding: 3px 9px; color: ${C.muted}; font-size: 12px; }
  .seg button[aria-pressed="true"] { background: ${C.card}; color: ${C.text}; font-weight: 600; }
  details { padding: 6px 10px 8px; }
  summary { color: ${C.muted}; cursor: pointer; font-size: 12px; }
  ol { margin: 6px 0 0; padding-left: 18px; }
  .split { display: grid; grid-template-columns: 300px 1fr; gap: 0; flex: 1; min-height: 0; }
  .list { border-right: 1px solid ${C.line}; overflow: auto; }
  .item { display: block; width: 100%; text-align: left; background: none; border: 0; border-bottom: 1px solid ${C.line}; padding: 9px 12px; }
  .item[aria-current="true"] { background: ${C.card}; }
  .item small { display: block; color: ${C.muted}; }
  .detail { overflow: auto; padding: 14px 18px; }
  .legend { display: flex; gap: 12px; flex-wrap: wrap; font-size: 11px; color: ${C.muted}; margin: 4px 0 10px; }
  .legend i { display: inline-block; width: 14px; height: 3px; vertical-align: middle; margin-right: 4px; }
  @media (max-width: 720px) { .split { grid-template-columns: 1fr; } .list { max-height: 30vh; border-right: 0; border-bottom: 1px solid ${C.line}; } }
  `;

  const SHIELD = (color) => svg('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: color, 'stroke-width': '2', 'stroke-linejoin': 'round' },
    svg('path', { d: 'M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z' }),
    svg('path', { d: 'M9 12l2 2 4-4' }));

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'style') el.style.cssText = v;
      else el.setAttribute(k, v === true ? '' : String(v));
    }
    for (const kid of kids.flat(Infinity)) if (kid !== undefined && kid !== null && kid !== false) el.append(kid instanceof Node ? kid : String(kid));
    return el;
  }
  function svg(tag, attrs, ...kids) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'style') el.style.cssText = v; // CSSOM, so a strict CSP on the host page does not block it
      else el.setAttribute(k, String(v));
    }
    for (const kid of kids.flat(Infinity)) if (kid) el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    return el;
  }
  const chip = (text, color) => h('span', { class: 'chip', style: `color:${color}` }, text);
  const cut = (s, n) => (s.length > n ? `${s.slice(0, n)}…` : s);

  const state = { page: null, policy: null, open: FULL, tab: 'page', selected: null, offline: false, sig: '', openStories: new Set() };

  async function api(path, body) {
    const res = await fetch(API + path, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    if (!res.ok) throw new Error(`${res.status} ${(await res.json().catch(() => ({}))).error || ''}`);
    return res.json();
  }

  const steps = (chain) => chain.events.filter((e) => e.kind !== 'task');
  const verdictOf = (chain) => {
    if (chain.blocked) return ACTION.block;
    if (chain.wouldBlock) return ACTION.would;
    if (chain.events.some((e) => e.decision && e.decision.action === 'alert')) return ACTION.alert;
    return ACTION.allow;
  };
  ACTION.would = ACTION.would_block;

  function counts() {
    const p = state.page;
    const events = p ? p.chains.flatMap((c) => c.events) : [];
    const n = (a) => events.filter((e) => e.decision && e.decision.action === a).length;
    return { events: events.length, blocked: n('block'), would: n('would_block'), alerts: n('alert'), pending: p ? p.pending.length : 0, halted: p && p.halted };
  }

  // ---------- views ----------
  function stepRow(e, chain) {
    const node = chain.nodes.find((n) => n.id === e.id);
    const a = ACTION[(e.decision && e.decision.action) || 'allow'] || ACTION.allow;
    const why = [];
    if (e.decision && e.decision.ruleId) why.push(`${e.decision.ruleId}: ${e.decision.reason}`);
    for (const f of e.findings.slice(0, 2)) if (!why.some((w) => w.includes(f.message))) why.push(f.message);
    return h('div', { class: 'step' },
      chip(a.label, a.color),
      h('span', { class: 'what' }, node ? node.title : `${e.kind} ${e.target}`),
      why.length ? h('span', { class: 'why' }, cut(why.join(' · '), 300)) : null);
  }

  function taskCard(chain) {
    const v = verdictOf(chain);
    const story = h('details', { open: state.openStories.has(chain.traceId), ontoggle: (ev) => (ev.target.open ? state.openStories.add(chain.traceId) : state.openStories.delete(chain.traceId)) },
      h('summary', {}, 'What happened, in words'),
      h('ol', {}, chain.narrative.map((l) => h('li', {}, l))));
    return h('div', { class: 'task' },
      h('div', { class: 't' }, h('b', {}, `${chain.actor} — ${chain.task || 'task'}`), chip(v.label, v.color)),
      steps(chain).map((e) => stepRow(e, chain)),
      chain.narrative.length ? story : null);
  }

  function approvals() {
    const list = state.page ? state.page.pending : [];
    if (!list.length) return h('div', { class: 'empty' }, 'Nothing waits for you. Rules with action "ask" put steps here in enforce mode.');
    return list.map((p) => {
      const args = p.event.data && (p.event.data.args || p.event.data.body);
      const answer = (approved) => async (ev) => {
        ev.target.disabled = true;
        await api(`/v1/pending/${encodeURIComponent(p.id)}`, { approved }).catch(() => {});
        poll();
      };
      return h('div', { class: 'ask' },
        h('div', {}, chip('waiting for you', C.ask), ' ', h('b', {}, `${p.event.actor}: ${p.event.kind === 'http' ? 'request to' : 'tool'} ${p.event.target}`)),
        h('div', { class: 'muted', style: 'margin-top:4px' }, `${p.ruleId}: ${p.reason}`),
        args ? h('pre', {}, cut(String(args), 600)) : null,
        h('div', { class: 'acts' },
          h('button', { class: 'btn go', onclick: answer(true) }, 'Allow once'),
          h('button', { class: 'btn danger', onclick: answer(false) }, 'Deny')));
    });
  }

  function rules() {
    if (!state.policy) return h('div', { class: 'empty' }, 'Loading rules…');
    return [
      h('p', { class: 'muted', style: 'margin:0 0 6px' }, 'Watch = record what would be blocked. Block = stop it. Saved to shieldtrail.policy.json.'),
      state.policy.rules.map((r) => {
        const stops = r.action === 'block' || r.action === 'ask';
        const set = (mode) => async () => {
          await api('/v1/policy/rule', { id: r.id, mode }).catch((err) => alert(`ShieldTrail: ${err.message}`));
          loadPolicy();
        };
        const audit = r.audit;
        const note = audit && audit.verdict === 'shadowed' ? `never decides: "${audit.shadowedBy}" matches first` : audit ? `${VERDICT[audit.verdict]}${audit.decided ? ` · decided ${audit.decided}×` : ''}` : '';
        return h('div', { class: 'rule' },
          h('b', {}, r.id, ' ', chip(r.action, r.action === 'block' ? C.block : r.action === 'ask' ? C.ask : C.alert)),
          stops
            ? h('div', { class: 'seg', role: 'group', 'aria-label': `Mode of ${r.id}` },
                [['off', 'Off'], ['shadow', 'Watch'], ['enforce', 'Block']].map(([m, label]) => h('button', { 'aria-pressed': String(r.mode === m), onclick: set(m) }, label)))
            : h('span', { class: 'muted', style: 'grid-row: span 2' }, 'records only'),
          h('span', { class: 'd' }, [r.description, note].filter(Boolean).join(' — ')));
      }),
    ];
  }

  function graph(chain) {
    const nodes = chain.nodes;
    const idx = new Map(nodes.map((n, i) => [n.id, i]));
    const W = 560, BOX = 380, X = 20, H = 46, GAP = 26, top = (i) => 10 + i * (H + GAP);
    const ev = new Map(chain.events.map((e) => [e.id, e]));
    const s = svg('svg', { viewBox: `0 0 ${W} ${top(nodes.length) + 4}`, width: '100%', style: `max-width:${W}px`, role: 'img', 'aria-label': 'Attack chain graph' },
      svg('defs', {}, Object.entries(EDGE).map(([k, c]) => svg('marker', { id: `a-${k}`, viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '7', markerHeight: '7', orient: 'auto-start-reverse' }, svg('path', { d: 'M0 0L10 5L0 10z', fill: c })))));
    let lane = 0;
    for (const e of chain.edges) {
      const a = idx.get(e.source), b = idx.get(e.target);
      if (a === undefined || b === undefined) continue;
      if (e.type === 'sequence' && b === a + 1) {
        s.append(svg('line', { x1: X + BOX / 2, y1: top(a) + H, x2: X + BOX / 2, y2: top(b) - 2, stroke: EDGE.sequence, 'stroke-width': 1.5, 'marker-end': 'url(#a-sequence)' }));
      } else {
        const off = 24 + (lane++ % 5) * 16;
        const side = e.type === 'sequence' ? X : X + BOX;
        const dir = e.type === 'sequence' ? -1 : 1;
        const y1 = top(a) + H / 2, y2 = top(b) + H / 2;
        s.append(svg('path', { d: `M${side} ${y1} C${side + dir * off} ${y1} ${side + dir * off} ${y2} ${side + dir * 3} ${y2}`, fill: 'none', stroke: EDGE[e.type], 'stroke-width': 2, 'stroke-dasharray': e.type === 'sequence' ? '4 3' : '', 'marker-end': `url(#a-${e.type})` }));
      }
    }
    nodes.forEach((n, i) => {
      const d = ev.get(n.id) && ev.get(n.id).decision;
      const a = ACTION[(d && d.action) || 'allow'] || ACTION.allow;
      const color = n.kind === 'task' ? C.accent : a.color;
      s.append(svg('g', {},
        svg('rect', { x: X, y: top(i), width: BOX, height: H, rx: 10, fill: C.card, stroke: color, 'stroke-width': n.labels.length || n.kind === 'task' ? 2 : 1 }),
        svg('text', { x: X + 12, y: top(i) + 19, fill: C.text, 'font-size': 13, 'font-weight': 600 }, cut(n.title, 46)),
        svg('text', { x: X + 12, y: top(i) + 36, fill: C.muted, 'font-size': 11 }, cut([n.kind, ...n.labels].join(' · '), 58)),
        n.kind === 'task' ? null : svg('text', { x: X + BOX - 10, y: top(i) + 19, fill: a.color, 'font-size': 11, 'font-weight': 700, 'text-anchor': 'end' }, a.label)));
    });
    return s;
  }

  function pageTab() {
    const chains = state.page ? [...state.page.chains].sort((a, b) => b.startedAt - a.startedAt) : [];
    if (!chains.length) return h('div', { class: 'empty' }, FULL ? 'No agent activity recorded yet.' : 'No agent activity on this page yet.');
    if (!FULL) return chains.map(taskCard);
    const sel = chains.find((c) => c.traceId === state.selected) || chains[0];
    return h('div', { class: 'split' },
      h('div', { class: 'list' }, chains.map((c) => {
        const v = verdictOf(c);
        return h('button', { class: 'item', 'aria-current': String(c === sel), onclick: () => { state.selected = c.traceId; render(true); } },
          h('b', {}, `${c.actor} — ${cut(c.task || 'task', 40)} `), chip(v.label, v.color),
          h('small', {}, `${new Date(c.startedAt).toLocaleTimeString()} · ${steps(c).length} step${steps(c).length === 1 ? '' : 's'}`));
      })),
      h('div', { class: 'detail' },
        h('h2', { style: 'margin:0 0 4px;font-size:17px' }, `${sel.actor} — ${sel.task || 'task'}`),
        h('div', { class: 'legend' }, Object.entries({ sequence: 'next step', taint: 'injected instructions flow', data: 'sensitive data flows', rule: 'cause matched by a rule' }).map(([k, l]) => h('span', {}, h('i', { style: `background:${EDGE[k]}` }), l))),
        graph(sel),
        h('h3', { style: 'font-size:14px;margin:16px 0 6px' }, 'What happened'),
        h('ol', {}, sel.narrative.map((l) => h('li', {}, l))),
        h('h3', { style: 'font-size:14px;margin:16px 0 6px' }, 'Steps'),
        h('div', { class: 'task' }, steps(sel).map((e) => stepRow(e, sel)))));
  }

  // ---------- frame ----------
  const host = h('div', { id: 'shieldtrail-devtools' });
  const shadow = host.attachShadow({ mode: 'open' });
  // a constructed stylesheet is not subject to the host page's style-src CSP
  try {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(CSS);
    shadow.adoptedStyleSheets = [sheet];
  } catch {
    shadow.append(h('style', {}, CSS));
  }
  const root = h('div', { class: 'root' });
  shadow.append(root);

  function render(force) {
    const c = counts();
    const visible = FULL || c.events > 0 || c.pending > 0 || c.halted;
    const scroll = root.querySelector('.body') && root.querySelector('.body').scrollTop;
    root.replaceChildren();
    if (!visible) return;
    const color = c.pending ? C.ask : c.halted || c.blocked ? C.block : c.would ? C.would : c.alerts ? C.alert : C.ok;
    const num = c.pending || c.blocked + c.would + c.alerts;
    if (!FULL) {
      root.append(h('button', {
        class: `badge${c.pending ? ' pulse' : ''}`, style: `--c:${color}`, 'aria-expanded': String(state.open),
        'aria-label': `ShieldTrail: ${c.pending ? `${c.pending} step(s) wait for your approval` : num ? `${num} security event(s) on this page` : 'no issue on this page'}`,
        onclick: () => { state.open = !state.open; if (state.open && state.tab === 'rules') loadPolicy(); render(true); },
      }, SHIELD(color), num ? h('span', { class: 'n' }, num > 99 ? '99+' : num) : null));
      if (!state.open) return;
    }
    const mode = state.page ? state.page.mode : '…';
    const tab = (id, label) => h('button', { class: 'tab', role: 'tab', 'aria-selected': String(state.tab === id), onclick: () => { state.tab = id; if (id === 'rules') loadPolicy(); render(true); } }, label);
    const body = h('div', { class: 'body' },
      c.halted ? h('div', { class: 'banner' }, `All agents are stopped: ${c.halted}`) : null,
      state.offline ? h('div', { class: 'banner' }, `Cannot reach the ShieldTrail dev server at ${API}. Is the app running in development?`) : null,
      state.tab === 'page' ? pageTab() : state.tab === 'ask' ? approvals() : rules());
    const killSwitch = h('button', {
      class: `btn stop ${c.halted ? 'go' : 'danger'}`,
      onclick: async () => {
        if (!c.halted && !confirm('Stop every tool call and outbound request of every agent?')) return;
        await api(c.halted ? '/v1/resume' : '/v1/halt', {}).catch(() => {});
        poll();
      },
    }, c.halted ? 'Resume agents' : 'Stop all agents');
    root.append(h('div', { class: FULL ? 'full' : 'card', role: FULL ? 'main' : 'dialog', 'aria-label': 'ShieldTrail' },
      h('div', { class: 'head' },
        h('span', { class: 'brand' }, SHIELD(C.accent), 'ShieldTrail'),
        chip(mode === 'enforce' ? 'blocking' : mode === 'shadow' ? 'watching' : mode, mode === 'enforce' ? C.block : C.accent),
        h('div', { class: 'tabs', role: 'tablist' }, tab('page', FULL ? 'Tasks' : 'Page'), tab('ask', `Approvals${c.pending ? ` (${c.pending})` : ''}`), tab('rules', 'Rules')),
        FULL ? null : h('button', { class: 'x', 'aria-label': 'Close', onclick: () => { state.open = false; render(true); } }, '×')),
      body,
      h('div', { class: 'foot' },
        FULL ? null : h('a', { href: `${API}/`, target: '_blank', rel: 'noopener' }, 'Full dashboard ↗'),
        h('a', { href: `${API}/v1/report.html`, target: '_blank', rel: 'noopener' }, 'HTML report ↗'),
        killSwitch)));
    if (scroll && !force) root.querySelector('.body').scrollTop = scroll;
  }

  async function loadPolicy() {
    try {
      state.policy = await api('/v1/policy');
    } catch {
      state.policy = null;
    }
    render(true);
  }

  async function poll() {
    try {
      const page = await api(`/v1/page?since=${SINCE}`);
      state.offline = false;
      const sig = JSON.stringify([page.chains.map((c) => [c.traceId, c.events.length, c.events.map((e) => e.decision && e.decision.action).join()]), page.pending.map((p) => p.id), page.halted, page.mode]);
      state.page = page;
      if (sig !== state.sig) {
        state.sig = sig;
        render(false);
      }
    } catch {
      if (!state.offline) {
        state.offline = true;
        render(false);
      }
    }
  }

  const mount = () => {
    document.body.append(host);
    poll();
    setInterval(poll, POLL_MS);
  };
  if (document.body) mount();
  else document.addEventListener('DOMContentLoaded', mount);
})();
