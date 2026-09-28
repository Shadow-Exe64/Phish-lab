/* Phish Lab — UI layer. All analysis lives in analyzer.js. Message text is only ever
 * inserted with textContent / text nodes, never innerHTML, because it is hostile input. */
(function () {
  'use strict';

  const P = window.PhishCore;
  const SAMPLES = window.PhishSamples;
  const QUIZ = window.PhishQuiz;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const STORE = 'phishlab.v1';

  /* ---------------------------------------------------------------- helpers */
  function h(tag, attrs, ...children) {
    const n = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      if (k === 'class') n.className = attrs[k];
      else if (k === 'text') n.textContent = attrs[k];
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), attrs[k]);
      else if (attrs[k] !== false && attrs[k] != null) n.setAttribute(k, attrs[k]);
    }
    children.flat().forEach((c) => { if (c != null && c !== false) n.append(c.nodeType ? c : document.createTextNode(String(c))); });
    return n;
  }
  const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); return n; };

  function toast(msg) {
    const el = h('div', { class: 'toast', text: msg });
    $('#toasts').appendChild(el); setTimeout(() => el.remove(), 2200);
  }
  async function copyText(text, msg) {
    try { await navigator.clipboard.writeText(text); } catch (e) {
      const ta = h('textarea', { style: 'position:fixed;opacity:0' }); ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); } catch (err) { /* ignore */ } ta.remove();
    }
    toast(msg || 'Copied');
  }
  function loadStore() { try { return JSON.parse(localStorage.getItem(STORE) || '{}'); } catch (e) { return {}; } }
  function saveStore(patch) { try { localStorage.setItem(STORE, JSON.stringify({ ...loadStore(), ...patch })); } catch (e) { /* ignore */ } }

  /* ------------------------------------------------------------------ theme */
  const current = () => document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  $('#theme-toggle').addEventListener('click', () => {
    const next = current() === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('phishlab.theme', next); } catch (e) { /* ignore */ }
  });

  /* ------------------------------------------------------------------- tabs */
  function makeTabs(buttons, onShow, attr) {
    buttons.forEach((b, i) => {
      b.addEventListener('click', () => onShow(b.dataset[attr]));
      b.addEventListener('keydown', (e) => {
        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
        const nb = buttons[(i + (e.key === 'ArrowRight' ? 1 : buttons.length - 1)) % buttons.length];
        onShow(nb.dataset[attr], true);
      });
    });
    return (name, focus) => buttons.forEach((b) => {
      const on = b.dataset[attr] === name; b.setAttribute('aria-selected', String(on)); b.tabIndex = on ? 0 : -1; if (on && focus) b.focus();
    });
  }
  const mainTabs = $$('.topbar .tab');
  const markMain = makeTabs(mainTabs, (n, f) => showMain(n, f), 'tab');
  function showMain(name, focus) {
    if (!['analyze', 'train', 'playbook'].includes(name)) name = 'analyze';
    markMain(name, focus);
    ['analyze', 'train', 'playbook'].forEach((id) => { $('#' + id).hidden = id !== name; });
    if (location.hash.slice(1) !== name) history.replaceState(null, '', '#' + name);
    window.scrollTo({ top: 0 });
  }
  window.addEventListener('hashchange', () => showMain(location.hash.slice(1)));

  const rtabs = $$('.rtabs .tab');
  const markR = makeTabs(rtabs, (n, f) => showR(n, f), 'rtab');
  function showR(name, focus) {
    markR(name, focus);
    ['flags', 'evidence', 'links', 'report'].forEach((id) => { $('#rp-' + id).hidden = id !== name; });
  }

  /* ---------------------------------------------------------------- samples */
  const sel = $('#sample');
  ['Phishing', 'Borderline', 'Legitimate'].forEach((g) => {
    const og = h('optgroup', { label: g === 'Legitimate' ? 'Legitimate (should be safe)' : g });
    SAMPLES.filter((s) => s.group === g).forEach((s) => og.appendChild(h('option', { value: s.id, text: s.title })));
    sel.appendChild(og);
  });
  sel.addEventListener('change', () => {
    const s = SAMPLES.find((x) => x.id === sel.value);
    if (!s) return;
    $('#msg').value = s.text; runAnalysis();
  });

  /* ---------------------------------------------------------------- analyse */
  let last = null;
  const VERDICT_TEXT = { safe: 'Safe', suspicious: 'Suspicious', malicious: 'Malicious' };

  function runAnalysis() {
    const text = $('#msg').value;
    if (!text.trim()) { toast('Paste a message first'); $('#msg').focus(); return; }
    last = P.analyze(text);
    render(last);
  }
  $('#btn-analyze').addEventListener('click', runAnalysis);
  $('#btn-clear').addEventListener('click', () => {
    $('#msg').value = ''; sel.value = ''; $('#result').hidden = true; $('#empty').hidden = false; last = null; $('#msg').focus();
  });
  $('#msg').addEventListener('keydown', (e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runAnalysis(); });

  function render(r) {
    $('#empty').hidden = true; $('#result').hidden = false;
    const v = $('#verdict'); v.className = 'verdict ' + r.verdict;
    $('#v-title').textContent = VERDICT_TEXT[r.verdict];
    $('#v-summary').textContent = r.summary;
    $('#v-score').textContent = r.score;
    $('#v-meter').setAttribute('aria-label', `Risk score ${r.score} out of 100`);
    $('#v-fill').style.width = '0%'; requestAnimationFrame(() => { $('#v-fill').style.width = r.score + '%'; });
    $('#v-action').textContent = r.action;
    renderNext(r); renderFlags(r); renderEvidence(r); renderLinks(r); renderReport(r);
    $('#c-flags').textContent = r.findings.length; $('#c-links').textContent = r.urls.length;
    showR('flags');
    if (window.innerWidth < 1000) $('#verdict').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function renderNext(r) {
    const box = clear($('#next'));
    const steps = {
      safe: [['Pause', 'No strong signals, but still ask: was I expecting this?'], ['Verify', 'If anything feels off, confirm through a channel you already trust.'], ['Report', 'Nothing to report. Close the ticket.']],
      suspicious: [['Pause', 'Do not click links or open attachments yet.'], ['Verify', 'Contact the apparent sender by phone using a directory number, not one from the message.'], ['Report', 'Warn the recipient and send the message to your security team using the report button.']],
      malicious: [['Pause', 'Stop. Do not click, reply, scan or call anything in this message.'], ['Verify', 'If you already interacted, change the affected passwords now and tell the security team.'], ['Report', 'Report it, block the listed domains, and escalate. Do not just delete it.']],
    }[r.verdict];
    box.append(h('h2', { text: 'What to do now' }),
      h('ol', { class: 'pvr' }, steps.map(([t, d], i) => h('li', null, h('b', { text: `${i + 1} ${t}` }), h('span', { text: d })))));
    if (r.blockList.length) {
      box.append(h('div', { class: 'block-list' }, h('strong', { text: 'Block:' }), r.blockList.map((d) => h('code', { text: d })),
        h('button', { class: 'btn btn-sm', type: 'button', text: 'Copy list', onclick: () => copyText(r.blockList.join('\n'), 'Domain list copied') })));
    }
  }

  const SEV_LABEL = { high: 'High', medium: 'Medium', low: 'Low' };
  const SEV_BADGE = { high: 'bad', medium: 'warn', low: 'info' };

  function senderCard(r) {
    const H = r.headers;
    if (!H.from && !H.subject && !Object.keys(H.auth).length) return null;
    const dl = h('dl', { class: 'kv' });
    const row = (k, v) => { if (v) { dl.append(h('dt', { text: k }), h('dd', { text: v })); } };
    if (H.from) { row('From name', H.from.name || '(none)'); row('From address', H.from.addr); row('Sending domain', H.from.registrable); }
    if (H.reply) row('Reply-To', H.reply.addr);
    if (H.returnPath) row('Return-Path', H.returnPath.addr);
    row('Subject', H.subject);
    const auth = h('div', { class: 'auth' });
    ['spf', 'dkim', 'dmarc'].forEach((k) => {
      const val = H.auth[k];
      const cls = !val ? '' : ['pass'].includes(val) ? 'ok' : ['fail', 'softfail', 'permerror'].includes(val) ? 'bad' : 'warn';
      auth.append(h('span', { class: 'badge ' + cls, text: `${k.toUpperCase()}: ${val || 'not in text'}` }));
    });
    return h('div', { class: 'card sender-card' }, h('h3', { text: 'Sender check' }), dl, auth,
      h('p', { class: 'hint', text: 'Always compare the address after the @ with who the message claims to be. The friendly name can say anything.' }));
  }

  function renderFlags(r) {
    const p = clear($('#rp-flags'));
    const sc = senderCard(r); if (sc) p.append(sc);
    if (!r.findings.length) {
      p.append(h('div', { class: 'card none' }, h('h3', { text: 'No red flags detected' }), h('p', { class: 'muted', text: 'Rule-based checks found nothing. That is reassuring but not proof: if the request is unexpected, verify it another way.' })));
      return;
    }
    r.findings.forEach((f) => {
      p.append(h('article', { class: 'flag sev-' + f.severity },
        h('div', { class: 'flag-head' }, h('h3', { text: f.title }),
          h('span', { class: 'badge ' + SEV_BADGE[f.severity], text: SEV_LABEL[f.severity] }),
          h('span', { class: 'badge', text: P.CATEGORIES[f.category] || f.category }),
          h('span', { class: 'pts', text: '+' + f.points })),
        h('p', { class: 'why' }, h('strong', { text: 'Why it is unsafe: ' }), f.why),
        f.evidence && f.evidence.length ? h('div', { class: 'evi' }, f.evidence.map((e) => h('code', { text: e }))) : null));
    });
  }

  function renderEvidence(r) {
    const p = clear($('#rp-evidence'));
    const view = h('div', { class: 'msg-view', tabindex: '0', role: 'region', 'aria-label': 'Message with red flags highlighted' });
    let pos = 0;
    r.highlights.forEach((hl) => {
      if (hl.start > pos) view.append(document.createTextNode(r.raw.slice(pos, hl.start)));
      const m = h('mark', { class: 'hl hl-' + hl.cat, title: hl.label, tabindex: '0' });
      m.textContent = r.raw.slice(hl.start, hl.end); view.append(m); pos = hl.end;
    });
    view.append(document.createTextNode(r.raw.slice(pos)));
    const cats = Array.from(new Set(r.highlights.map((x) => x.cat)));
    const legend = h('div', { class: 'legend' }, cats.length ? cats.map((c) => h('span', { class: 'hl-' + c }, h('i'), P.CATEGORIES[c])) : h('span', { text: 'Nothing highlighted.' }));
    p.append(h('p', { class: 'muted small', style: 'margin:0', text: 'Each highlight marks text that triggered a rule. Hover or focus a highlight to see why.' }), legend, view);
  }

  function renderLinks(r) {
    const p = clear($('#rp-links'));
    if (!r.urls.length) { p.append(h('div', { class: 'card none' }, h('h3', { text: 'No links found' }), h('p', { class: 'muted', text: 'Messages without links can still be dangerous. Callback scams use only a phone number.' }))); return; }
    p.append(h('p', { class: 'read-hint', text: 'Read every address from right to left. The last name before the first “/” decides who owns the site; anything in front of it is decoration. Links are defanged and never opened.' }));
    r.urls.forEach((u) => {
      const line = h('div', { class: 'domain-line' });
      if (u.parts && u.parts.registrable) {
        let path = '';
        try { const uu = new URL(/^[a-z]+:\/\//i.test(u.raw) ? u.raw.replace(/^hxxp/i, 'http') : 'http://' + u.raw); path = (uu.pathname + uu.search).replace(/\.$/, ''); if (path === '/') path = ''; } catch (e) { /* ignore */ }
        const dfg = (s) => s.replace(/\./g, '[.]');
        if (u.parts.sub) line.append(h('span', { class: 'dom-pre', text: dfg(u.parts.sub) + '[.]' }));
        line.append(h('span', { class: 'dom-root', text: dfg(u.parts.registrable) }));
        if (path) line.append(h('span', { class: 'dom-path', text: path.length > 70 ? path.slice(0, 70) + '…' : path }));
      } else line.append(document.createTextNode(u.display));
      const badge = { bad: ['bad', 'High risk'], warn: ['warn', 'Caution'], ok: ['ok', 'No issues found'] }[u.risk];
      p.append(h('article', { class: 'link-card ' + u.risk },
        h('div', { class: 'row' }, h('span', { class: 'badge ' + badge[0], text: badge[1] }), u.owner ? h('span', { class: 'owner', text: `Belongs to ${u.owner.name}` }) : null,
          h('span', { class: 'spacer' }), h('button', { class: 'btn btn-sm', type: 'button', text: 'Copy defanged', onclick: () => copyText(u.display, 'Defanged link copied') })),
        line,
        u.linkText ? h('p', { class: 'muted small', style: 'margin:0' }, 'Link text shown to the reader: ', h('code', { text: u.linkText })) : null,
        u.reasons.length ? h('ul', { class: 'reasons' }, u.reasons.map((x) => h('li', { text: x.text }))) : h('p', { class: 'muted small', style: 'margin:0', text: 'No suspicious patterns found in this address. Still confirm it matches what you expect.' })));
    });
  }

  function buildReport(r) {
    const L = [];
    L.push('PHISHING TRIAGE REPORT', `Generated: ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`, '');
    L.push(`Verdict: ${VERDICT_TEXT[r.verdict].toUpperCase()} (risk score ${r.score}/100)`, `Recommended action: ${r.action}`, `Summary: ${r.summary}`, '');
    const H = r.headers;
    if (H.from) { L.push('SENDER', `  From: ${H.from.name ? H.from.name + ' ' : ''}<${H.from.addr}>`); if (H.reply) L.push(`  Reply-To: ${H.reply.addr}`); if (H.returnPath) L.push(`  Return-Path: ${H.returnPath.addr}`); if (H.subject) L.push(`  Subject: ${H.subject}`); const a = Object.keys(H.auth).map((k) => `${k.toUpperCase()}=${H.auth[k]}`).join(' '); if (a) L.push(`  Authentication: ${a}`); L.push(''); }
    L.push(`RED FLAGS (${r.findings.length})`);
    if (!r.findings.length) L.push('  None detected.');
    r.findings.forEach((f, i) => { L.push(`${i + 1}. [${f.severity.toUpperCase()}] ${f.title} (+${f.points})`, `   Why: ${f.why}`); if (f.evidence && f.evidence.length) L.push(`   Evidence: ${f.evidence.join(' | ')}`); });
    L.push('', `LINKS (${r.urls.length})`);
    if (!r.urls.length) L.push('  None found.');
    r.urls.forEach((u) => L.push(`  - ${u.display}  [${u.risk}]${u.reasons.length ? ' ' + u.reasons.map((x) => x.text).join('; ') : ''}`));
    if (r.blockList.length) L.push('', 'DOMAINS TO BLOCK', ...r.blockList.map((d) => '  - ' + d.replace(/\./g, '[.]')));
    L.push('', 'NEXT STEPS', '  1. Pause: do not interact with the message.', '  2. Verify: confirm through a second, known channel.', '  3. Report: send to the security team; do not just delete.', '',
      'Note: automated rule-based analysis. Treat as decision support, not proof. The original message text is not included in this report.');
    return L.join('\n');
  }

  function renderReport(r) {
    const p = clear($('#rp-report'));
    const text = buildReport(r);
    p.append(h('div', { class: 'row no-print' },
      h('button', { class: 'btn btn-primary', type: 'button', text: 'Copy report', onclick: () => copyText(text, 'Report copied') }),
      h('button', { class: 'btn', type: 'button', text: 'Print / Save as PDF', onclick: () => { showR('report'); setTimeout(() => window.print(), 50); } }),
      h('button', { class: 'btn', type: 'button', text: 'Download .txt', onclick: () => {
        const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' })), download: 'phishing-triage-report.txt' });
        document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      } })),
      h('div', { class: 'card report' }, h('pre', { text })));
  }

  /* ------------------------------------------------------------------ quiz */
  const quiz = { order: [], i: 0, score: 0, answers: [], phase: 'start', peeked: { sender: false, links: {} }, best: loadStore().best || null };
  const quizRoot = $('#quiz');

  function shuffle(a) {
    const arr = a.slice(); const buf = new Uint32Array(arr.length); crypto.getRandomValues(buf);
    for (let i = arr.length - 1; i > 0; i--) { const j = buf[i] % (i + 1); [arr[i], arr[j]] = [arr[j], arr[i]]; }
    return arr;
  }
  function startQuiz() { quiz.order = shuffle(QUIZ); quiz.i = 0; quiz.score = 0; quiz.answers = []; quiz.phase = 'play'; resetPeek(); renderQuiz(); }
  function resetPeek() { quiz.peeked = { sender: false, links: {} }; }

  function renderQuiz() {
    clear(quizRoot);
    if (quiz.phase === 'start') {
      quizRoot.append(h('div', { class: 'card' }, h('h2', { text: 'Ready?' }),
        h('p', { class: 'muted', text: `${QUIZ.length} messages. For each one you decide: legitimate or phishing. Tip: the address and the link destination are hidden until you choose to inspect them, just like in a real inbox.` }),
        quiz.best != null ? h('p', { html: null }, `Your best score: `, h('strong', { text: `${quiz.best}/${QUIZ.length}` })) : null,
        h('button', { class: 'btn btn-primary', type: 'button', text: 'Start training', onclick: startQuiz })));
      return;
    }
    if (quiz.phase === 'done') return renderFinal();
    const q = quiz.order[quiz.i];
    const answered = quiz.phase === 'feedback';
    quizRoot.append(h('div', { class: 'quiz-bar' }, h('strong', { text: `Message ${quiz.i + 1} of ${quiz.order.length}` }),
      h('div', { class: 'progress', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': String(quiz.order.length), 'aria-valuenow': String(quiz.i) }, h('i', { style: `width:${(quiz.i / quiz.order.length) * 100}%` })),
      h('span', { class: 'badge info', text: `Score ${quiz.score}` })));

    const from = h('div', { class: 'mail-from' }, h('strong', { text: q.name }));
    if (quiz.peeked.sender || answered) from.append(h('code', { text: q.addr })); else from.append(h('button', { class: 'btn btn-sm', type: 'button', text: 'Show address', onclick: () => { quiz.peeked.sender = true; renderQuiz(); } }));
    const links = q.links.length ? h('div', { class: 'mail-links' }, q.links.map((l, idx) => {
      const open = quiz.peeked.links[idx] || answered;
      return h('div', null,
        h('button', { class: 'fake-link', type: 'button', 'aria-expanded': String(!!open), text: l.text, title: 'Inspect where this link goes', onclick: () => { quiz.peeked.links[idx] = !quiz.peeked.links[idx]; renderQuiz(); } }),
        open ? h('div', { class: 'dest', text: 'Goes to: ' + P.defang(l.href) }) : null);
    })) : null;
    quizRoot.append(h('article', { class: 'mail' },
      h('div', { class: 'mail-head' }, h('span', { class: 'mail-chan', text: q.channel }), from, h('div', { class: 'mail-subj', text: q.subject })),
      h('div', { class: 'mail-body', text: q.body }), links));

    if (!answered) {
      quizRoot.append(h('div', { class: 'choices' },
        h('button', { class: 'btn', type: 'button', text: 'Looks legitimate', onclick: () => answer(false) }),
        h('button', { class: 'btn btn-danger', type: 'button', text: 'It is phishing', onclick: () => answer(true) })));
    } else {
      const a = quiz.answers[quiz.answers.length - 1];
      const fb = h('div', { class: 'feedback ' + (a.correct ? 'right' : 'wrong'), role: 'status' },
        h('h3', { text: a.correct ? 'Correct' : 'Not quite' }),
        h('p', { text: `This one is ${q.phish ? 'phishing' : 'legitimate'}. ${q.why}` }),
        q.flags.length ? h('div', null, h('strong', { text: 'Red flags to notice:' }), h('ul', null, q.flags.map((f) => h('li', { text: f })))) : h('p', { class: 'muted', text: 'No red flags: it is fine to trust this one. Good analysts avoid crying wolf.' }),
        !a.correct && !a.inspected ? h('p', { class: 'muted small', text: 'You did not inspect the address or links this time. Try that first next round.' }) : null,
        h('button', { class: 'btn btn-primary', type: 'button', text: quiz.i + 1 < quiz.order.length ? 'Next message' : 'See results', onclick: () => { quiz.i++; resetPeek(); quiz.phase = quiz.i < quiz.order.length ? 'play' : 'done'; renderQuiz(); } }));
      quizRoot.append(fb);
      fb.querySelector('button').focus();
    }
  }

  function answer(saysPhish) {
    const q = quiz.order[quiz.i]; const correct = saysPhish === q.phish;
    if (correct) quiz.score++;
    quiz.answers.push({ id: q.id, correct, inspected: quiz.peeked.sender || Object.values(quiz.peeked.links).some(Boolean) });
    quiz.phase = 'feedback'; renderQuiz();
  }

  function renderFinal() {
    const n = quiz.order.length; const pct = Math.round((quiz.score / n) * 100);
    if (quiz.best == null || quiz.score > quiz.best) { quiz.best = quiz.score; saveStore({ best: quiz.best }); }
    const rating = pct === 100 ? 'Perfect: a genuine human firewall.' : pct >= 80 ? 'Strong. You catch most of what gets through.' : pct >= 60 ? 'Decent, but some attacks are slipping past you.' : 'Keep practising: read the red flags below and try again.';
    const missed = quiz.answers.filter((a) => !a.correct).map((a) => QUIZ.find((q) => q.id === a.id));
    quizRoot.append(h('div', { class: 'card final' }, h('div', { class: 'big', text: `${quiz.score}/${n}` }), h('h2', { text: rating }),
      h('p', { class: 'muted', style: 'margin-inline:auto', text: `Best score: ${quiz.best}/${n}` }),
      h('button', { class: 'btn btn-primary', type: 'button', text: 'Play again', onclick: startQuiz }),
      missed.length ? h('div', { class: 'missed' }, h('h3', { text: 'Review what you missed' }), missed.map((q) => h('div', { class: 'card' }, h('strong', { text: `${q.subject} (${q.phish ? 'phishing' : 'legitimate'})` }), h('p', { class: 'muted', style: 'margin:.3rem 0 0', text: q.why })))) : null));
  }

  /* ---------------------------------------------------------- playbook list */
  const saved = loadStore().triage || {};
  $$('#triage-list input').forEach((cb) => {
    cb.checked = !!saved[cb.dataset.t];
    cb.addEventListener('change', () => { const s = loadStore().triage || {}; s[cb.dataset.t] = cb.checked; saveStore({ triage: s }); });
  });

  /* ------------------------------------------------------------------ init */
  renderQuiz();
  showMain(location.hash.slice(1));
})();
