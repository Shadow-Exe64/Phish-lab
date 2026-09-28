'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const P = require('../assets/js/analyzer.js');
const SAMPLES = require('../assets/js/samples.js');

test('every sample gets the expected verdict', () => {
  for (const s of SAMPLES) {
    const r = P.analyze(s.text);
    assert.equal(r.verdict, s.expect, `${s.id}: got ${r.verdict} (score ${r.score}) -> ${r.findings.map((f) => f.id + ':' + f.points).join(', ')}`);
  }
});

test('legitimate samples never reach the suspicious band', () => {
  for (const s of SAMPLES.filter((x) => x.group === 'Legitimate')) {
    assert.ok(P.analyze(s.text).score < 20, s.id);
  }
});

test('splitHost handles multi-part suffixes', () => {
  assert.equal(P.splitHost('www.bbc.co.uk').registrable, 'bbc.co.uk');
  assert.equal(P.splitHost('a.b.example.com').registrable, 'example.com');
  assert.equal(P.splitHost('www.decodelabs.tech.login-update.com').registrable, 'login-update.com');
});

test('typosquat, combosquat, subdomain and nested traps', () => {
  const codes = (h) => P.analyzeDomain(h, h).reasons.map((r) => r.code);
  assert.ok(codes('paypa1.com').includes('typo'));
  assert.ok(codes('rnicrosoft.com').includes('typo'));
  assert.ok(codes('paypal-secure-login.com').includes('combo'));
  assert.ok(codes('paypal.com.evil-site.net').includes('subdomain'));
  assert.ok(codes('www.mycompany.com.login-update.net').includes('nested'));
  assert.ok(codes('xn--pypal-4ve.com').includes('homoglyph'));
  assert.ok(codes('192.168.4.9').includes('ip'));
});

test('real brand domains produce no reasons', () => {
  for (const h of ['www.paypal.com', 'accounts.google.com', 'login.microsoftonline.com', 'docs.python.org', 'www.bbc.co.uk']) {
    assert.deepEqual(P.analyzeDomain(h, h).reasons, [], h);
  }
});

test('no false positives on ordinary words that contain a brand-ish string', () => {
  const codes = (h) => P.analyzeDomain(h, h).reasons.map((r) => r.code);
  assert.ok(!codes('pineapple.com').includes('combo'));
  assert.ok(!codes('zoomer.com').includes('combo'));
  assert.ok(!codes('amazonia.com').includes('combo'));
});

test('link text mismatch inside HTML is caught', () => {
  const r = P.analyze('<a href="https://evil-site.net/x">https://www.paypal.com/login</a>');
  assert.ok(r.findings.some((f) => f.id === 'link-mismatch'));
});

test('negation is respected ("no immediate action")', () => {
  const r = P.analyze('Hi, this is not urgent and no immediate action is needed.');
  assert.ok(!r.findings.some((f) => f.id === 'urgency'));
});

test('emails and attachment names are not mistaken for links', () => {
  const r = P.analyze('Contact me at sarah@company.com and see Report.pdf');
  assert.equal(r.urls.length, 0);
});

test('double extension and script links', () => {
  assert.ok(P.analyze('Open photo.jpg.exe now').findings.some((f) => f.id === 'attach-double'));
  assert.ok(P.analyze('<a href="javascript:alert(1)">click</a>').urls.some((u) => u.reasons.some((r) => r.code === 'jsdata')));
});

test('userinfo trick and shorteners', () => {
  const r = P.analyze('Go to https://www.paypal.com@evil.example.net/login or https://bit.ly/3abc');
  assert.ok(r.findings.some((f) => f.id === 'link-userinfo'));
  assert.ok(r.findings.some((f) => f.id === 'link-shortener'));
});

test('defang and empty input', () => {
  assert.equal(P.defang('https://a.com/x'), 'hxxps://a[.]com/x');
  const r = P.analyze('');
  assert.equal(r.score, 0); assert.equal(r.verdict, 'safe'); assert.equal(r.action, 'Close');
});

test('highlights never overlap and stay in range', () => {
  for (const s of SAMPLES) {
    const r = P.analyze(s.text);
    let prev = 0;
    for (const h of r.highlights) { assert.ok(h.start >= prev && h.end > h.start && h.end <= s.text.length); prev = h.end; }
  }
});

test('words inside email addresses and URLs are not treated as language', () => {
  const r = P.analyze('From: Sam <ceo.urgent@example.org>\nSubject: Hello\n\nSee you at lunch https://example.org/urgent-verify-account');
  assert.ok(!r.findings.some((f) => f.id === 'urgency' || f.id === 'credential'));
});
