/*!
 * Phish Lab — analysis engine (pure logic, no DOM, no network).
 * Works in the browser (window.PhishCore) and in Node (require).
 *
 * It never opens, fetches or resolves a link. It only reads the text you give it
 * and applies transparent, explainable rules. Every rule returns evidence and a
 * plain-language reason, so the verdict can always be justified.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.PhishCore = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ------------------------------------------------------------ reference data */
  const BRANDS = [
    { name: 'Microsoft', key: 'microsoft', domains: ['microsoft.com', 'office.com', 'live.com', 'outlook.com', 'microsoftonline.com', 'office365.com', 'sharepoint.com', 'windows.com', 'azure.com', 'xbox.com', 'msn.com', 'bing.com'] },
    { name: 'Google', key: 'google', domains: ['google.com', 'gmail.com', 'googlemail.com', 'youtube.com', 'gstatic.com', 'googleapis.com', 'goo.gl', 'google.co.uk', 'google.co.in'] },
    { name: 'Apple', key: 'apple', domains: ['apple.com', 'icloud.com'] },
    { name: 'Amazon', key: 'amazon', domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'amazon.ca', 'amzn.to', 'amazon.com.au'] },
    { name: 'PayPal', key: 'paypal', domains: ['paypal.com', 'paypal.me'] },
    { name: 'Meta / Facebook', key: 'facebook', domains: ['facebook.com', 'fb.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'messenger.com'] },
    { name: 'LinkedIn', key: 'linkedin', domains: ['linkedin.com', 'lnkd.in'] },
    { name: 'Netflix', key: 'netflix', domains: ['netflix.com'] },
    { name: 'Dropbox', key: 'dropbox', domains: ['dropbox.com'] },
    { name: 'DocuSign', key: 'docusign', domains: ['docusign.com', 'docusign.net'] },
    { name: 'Zoom', key: 'zoom', domains: ['zoom.us', 'zoom.com'] },
    { name: 'OpenAI', key: 'openai', domains: ['openai.com', 'chatgpt.com'] },
    { name: 'ChatGPT', key: 'chatgpt', domains: ['openai.com', 'chatgpt.com'] },
    { name: 'GitHub', key: 'github', domains: ['github.com', 'githubusercontent.com'] },
    { name: 'Adobe', key: 'adobe', domains: ['adobe.com'] },
    { name: 'Slack', key: 'slack', domains: ['slack.com'] },
    { name: 'DHL', key: 'dhl', domains: ['dhl.com', 'dhl.de'] },
    { name: 'FedEx', key: 'fedex', domains: ['fedex.com'] },
    { name: 'UPS', key: 'ups', domains: ['ups.com'] },
    { name: 'USPS', key: 'usps', domains: ['usps.com'] },
    { name: 'Chase', key: 'chase', domains: ['chase.com'] },
    { name: 'Wells Fargo', key: 'wellsfargo', domains: ['wellsfargo.com'] },
    { name: 'Bank of America', key: 'bankofamerica', domains: ['bankofamerica.com'] },
    { name: 'HDFC Bank', key: 'hdfcbank', domains: ['hdfcbank.com'] },
    { name: 'ICICI Bank', key: 'icicibank', domains: ['icicibank.com'] },
    { name: 'State Bank of India', key: 'sbi', domains: ['sbi.co.in', 'onlinesbi.sbi', 'sbi.bank.in'] },
    { name: 'Paytm', key: 'paytm', domains: ['paytm.com'] },
    { name: 'Meezan Bank', key: 'meezanbank', domains: ['meezanbank.com'] },
    { name: 'JazzCash', key: 'jazzcash', domains: ['jazzcash.com.pk'] },
    { name: 'Easypaisa', key: 'easypaisa', domains: ['easypaisa.com.pk'] },
    { name: 'IRS', key: 'irs', domains: ['irs.gov'] },
  ];

  const FREEMAIL = new Set(['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'live.com', 'aol.com', 'proton.me', 'protonmail.com', 'icloud.com', 'gmx.com', 'mail.com', 'yandex.com', 'zoho.com', 'yahoo.co.in', 'rediffmail.com']);
  const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bl.ink', 't.ly', 'v.gd']);
  const RISKY_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'click', 'support', 'icu', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'rest', 'country', 'gdn', 'loan', 'men', 'bid', 'link', 'live', 'cam', 'monster', 'sbs', 'cyou']);
  const MULTI_SUFFIX = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.in', 'net.in', 'org.in', 'gov.in', 'co.jp', 'com.br', 'com.pk', 'org.pk', 'edu.pk', 'gov.pk', 'co.za', 'com.mx', 'com.tr', 'com.cn', 'com.sg', 'co.nz', 'com.ng', 'co.ke', 'com.eg', 'com.sa', 'com.ar', 'com.co', 'com.bd',
    'github.io', 'web.app', 'firebaseapp.com', 'pages.dev', 'netlify.app', 'herokuapp.com', 'blogspot.com', 'weebly.com', 'wixsite.com', 'vercel.app', 'workers.dev', 'onrender.com', 'glitch.me']);
  const FREE_HOSTS = new Set(['github.io', 'web.app', 'firebaseapp.com', 'pages.dev', 'netlify.app', 'herokuapp.com', 'blogspot.com', 'weebly.com', 'wixsite.com', 'vercel.app', 'workers.dev', 'onrender.com', 'glitch.me']);
  const SECURITY_WORDS = ['login', 'signin', 'secure', 'security', 'verify', 'verification', 'account', 'update', 'support', 'billing', 'auth', 'recover', 'recovery', 'unlock', 'confirm', 'service', 'helpdesk', 'password', 'wallet', 'alert', 'portal', 'online', 'customer', 'pay', 'payment'];
  const NESTED_TLD = 'com|net|org|edu|gov|io|co|tech|info|biz|app|dev|in|uk|us|pk';
  const BARE_TLDS = 'com|net|org|info|biz|top|xyz|click|link|site|online|support|icu|co|io|me|cc|tk|ml|ga|cf|gq|live|shop|store|app|dev|tech|in|pk|us|uk|ru|cn|gov|edu';

  const CATEGORIES = {
    sender: 'Sender', link: 'Link', urgency: 'Urgency', threat: 'Fear / threat', reward: 'Reward / greed',
    authority: 'Authority', credential: 'Credential request', secrecy: 'Secrecy / bypass', payment: 'Payment / BEC',
    attachment: 'Attachment', callback: 'Callback / phone', qr: 'QR code', other: 'Other',
  };

  /* ------------------------------------------------------------------ helpers */
  const uniq = (arr) => Array.from(new Set(arr));
  const severityFor = (pts) => (pts >= 30 ? 'high' : pts >= 15 ? 'medium' : 'low');

  function defang(url) {
    return String(url).replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
  }

  function levenshtein(a, b) {
    const m = a.length; const n = b.length;
    if (!m) return n; if (!n) return m;
    let prev = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
      const cur = [i];
      for (let j = 1; j <= n; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[n];
  }

  /** Split a hostname into subdomain / registrable name / suffix. Small built-in suffix list. */
  function splitHost(hostname) {
    const host = String(hostname).toLowerCase().replace(/\.$/, '');
    const labels = host.split('.');
    if (labels.length < 2) return { host, sub: '', name: host, suffix: '', registrable: host };
    const lastTwo = labels.slice(-2).join('.');
    const suffixLen = MULTI_SUFFIX.has(lastTwo) ? 2 : 1;
    const suffix = labels.slice(-suffixLen).join('.');
    const name = labels[labels.length - suffixLen - 1] || '';
    const sub = labels.slice(0, Math.max(0, labels.length - suffixLen - 1)).join('.');
    return { host, sub, name, suffix, registrable: name ? name + '.' + suffix : suffix };
  }

  function isIp(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[[0-9a-f:]+\]$/i.test(host) || /^0x[0-9a-f]+$/i.test(host) || /^\d{8,10}$/.test(host);
  }

  function deleet(label, oneAs) {
    return label.replace(/0/g, 'o').replace(/1/g, oneAs).replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's')
      .replace(/7/g, 't').replace(/8/g, 'b').replace(/rn/g, 'm').replace(/vv/g, 'w');
  }

  /** Which brand (if any) owns this registrable domain? */
  function ownerOf(registrable) {
    return BRANDS.find((b) => b.domains.includes(registrable)) || null;
  }

  /** Does this domain imitate a known brand? Returns { kind, brand } or null. */
  function brandImitation(parts) {
    if (ownerOf(parts.registrable)) return null;
    const label = parts.name;
    for (const b of BRANDS) {
      const key = b.key;
      // 1. look-alike spellings: paypa1, micr0soft, rn for m …
      if (label !== key && (deleet(label, 'l') === key || deleet(label, 'i') === key)) return { kind: 'typo', brand: b };
      // 2. one or two edits away (long brand names only, to avoid false positives)
      if (key.length >= 6) {
        const d = levenshtein(label, key);
        if (d >= 1 && d <= (key.length >= 9 ? 2 : 1) && Math.abs(label.length - key.length) <= 2) return { kind: 'typo', brand: b };
      }
      // 3. brand + security words: paypal-secure, google-account-recovery
      const tokens = label.split('-');
      if (label !== key) {
        if (tokens.includes(key) && tokens.length > 1) return { kind: 'combo', brand: b };
        if (key.length >= 6 && label.includes(key)) {
          const rest = label.replace(key, '');
          if (SECURITY_WORDS.some((w) => rest.includes(w))) return { kind: 'combo', brand: b };
        }
      }
      // 4. brand buried in the sub-domain: paypal.com.evil.net
      if (parts.sub) {
        const subTokens = parts.sub.split(/[.\-]/);
        if (subTokens.includes(key) || (key.length >= 6 && parts.sub.includes(key))) return { kind: 'subdomain', brand: b };
      }
    }
    return null;
  }

  const R = (code, points, text) => ({ code, points, text });

  /** Analyse a hostname. `rawHost` keeps original characters for homoglyph checks. */
  function analyzeDomain(host, rawHost) {
    const reasons = [];
    const parts = splitHost(host);
    const owner = ownerOf(parts.registrable);
    if (isIp(host)) {
      reasons.push(R('ip', 40, 'Uses a raw IP address instead of a domain name'));
      return { parts, reasons, owner };
    }
    if (host.includes('xn--') || /[^\x00-\x7f]/.test(rawHost || '')) {
      reasons.push(R('homoglyph', 50, 'Contains punycode or non-Latin look-alike characters that can imitate a real brand'));
    }
    if (SHORTENERS.has(parts.registrable)) reasons.push(R('shortener', 15, 'URL shortener hides the real destination'));
    const imit = brandImitation(parts);
    if (imit) {
      const map = {
        typo: [50, `Look-alike spelling of ${imit.brand.name} (typosquatting)`],
        combo: [40, `Adds security-style words to the ${imit.brand.name} name (combosquatting)`],
        subdomain: [45, `Puts "${imit.brand.key}" in the sub-domain, but the real domain is ${parts.registrable}`],
      };
      reasons.push(R(imit.kind, map[imit.kind][0], map[imit.kind][1]));
    } else if (!owner && parts.sub && new RegExp('(^|\\.)[a-z0-9-]{2,}\\.(' + NESTED_TLD + ')$').test(parts.sub)) {
      reasons.push(R('nested', 45, `Sub-domain trap: "${parts.sub}" looks like a real site, but the true domain is ${parts.registrable}`));
    }
    if (RISKY_TLDS.has(parts.suffix.split('.').pop())) reasons.push(R('tld', 12, `Uses the .${parts.suffix.split('.').pop()} ending, which is frequently abused`));
    if (FREE_HOSTS.has(parts.suffix)) reasons.push(R('freehost', 10, 'Hosted on a free public hosting platform, not an organisation\'s own domain'));
    if ((parts.name.match(/-/g) || []).length >= 3) reasons.push(R('hyphens', 8, 'Domain name contains many hyphens'));
    if (parts.sub && parts.sub.split('.').length >= 4) reasons.push(R('depth', 8, 'Unusually deep chain of sub-domains'));
    return { parts, reasons, owner };
  }

  /* --------------------------------------------------------------- URL parsing */
  function normalizeUrlText(raw) {
    return raw.replace(/^hxxp/i, 'http').replace(/\[\.\]|\(\.\)/g, '.').replace(/[)\]}>.,;:!?'"]+$/, '');
  }

  function extractUrlMatches(text) {
    const found = [];
    const overlaps = (s, e) => found.some((f) => s < f.end && e > f.start);
    const add = (m, hasScheme) => {
      const s = m.index; const e = s + m[0].length;
      if (overlaps(s, e)) return;
      const trimmed = m[0].replace(/[)\]}>.,;:!?'"]+$/, '');
      found.push({ start: s, end: s + trimmed.length, raw: trimmed, hasScheme });
    };
    let m;
    const reScheme = /\b(?:https?|hxxps?|ftp):\/\/[^\s<>"'`]+/gi;
    while ((m = reScheme.exec(text))) add(m, true);
    const reWww = /\bwww\.[^\s<>"'`]+/gi;
    while ((m = reWww.exec(text))) if (!/[\w@.-]/.test(text[m.index - 1] || ' ') || text[m.index - 1] === '/') add(m, false);
    const reBare = new RegExp('\\b[a-z0-9][a-z0-9-]*(?:\\.[a-z0-9-]+)*\\.(?:' + BARE_TLDS + ')\\b(?:\\/[^\\s<>"\'`]*)?', 'gi');
    while ((m = reBare.exec(text))) {
      const prev = text[m.index - 1] || ' ';
      const next = text[m.index + m[0].length] || ' ';
      if (/[\w@.\-\/]/.test(prev) || next === '@') continue;
      add(m, false);
    }
    return found.sort((a, b) => a.start - b.start);
  }

  function extractAnchors(text) {
    const out = [];
    let m;
    const reHtml = /<a\b[^>]*?href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>([\s\S]*?)<\/a>/gi;
    while ((m = reHtml.exec(text))) out.push({ href: m[1], text: m[2].replace(/<[^>]*>/g, '').trim() });
    const reMd = /\[([^\]]{1,120})\]\(((?:https?|hxxps?):[^)\s]+)\)/gi;
    while ((m = reMd.exec(text))) out.push({ href: m[2], text: m[1].trim() });
    return out;
  }

  function analyzeUrl(rawUrl, hasScheme, linkText) {
    const norm = normalizeUrlText(rawUrl);
    const info = { raw: rawUrl, display: defang(norm), linkText: linkText || '', reasons: [], parts: null, owner: null, host: '' };
    if (/^(javascript|data|vbscript):/i.test(norm)) {
      info.reasons.push(R('jsdata', 50, 'Uses a script or data link instead of a web address'));
      info.risk = 'bad';
      return info;
    }
    let url;
    try { url = new URL(/^[a-z]+:\/\//i.test(norm) ? norm : 'http://' + norm); } catch (e) {
      info.reasons.push(R('malformed', 5, 'Malformed URL'));
      info.risk = 'warn';
      return info;
    }
    const rawHostMatch = /^[a-z]+:\/\/([^\/?#]*)/i.exec(/^[a-z]+:\/\//i.test(norm) ? norm : 'http://' + norm);
    const rawHost = rawHostMatch ? rawHostMatch[1] : url.hostname;
    const host = url.hostname;
    info.host = host;
    const dom = analyzeDomain(host, rawHost);
    info.parts = dom.parts; info.owner = dom.owner; info.reasons.push(...dom.reasons);
    if (url.username || url.password) info.reasons.push(R('userinfo', 35, 'Contains "@" before the host, so the visible name is not where the link goes'));
    if (hasScheme && url.protocol === 'http:' && !/^(localhost|127\.)/.test(host)) info.reasons.push(R('http', 8, 'Not encrypted (http, not https)'));
    if (!dom.owner && /(login|log-in|signin|sign-in|verify|secure|password|recover|unlock|auth|account)/i.test(url.pathname + url.search)) {
      info.reasons.push(R('loginpath', 8, 'Login-style path on a domain you have no reason to trust'));
    }
    if ((norm.match(/%[0-9a-f]{2}/gi) || []).length >= 5) info.reasons.push(R('encoded', 6, 'Heavily encoded characters in the address'));
    if (linkText) {
      const m = /((?:[a-z0-9-]+\.)+[a-z]{2,})/i.exec(linkText.replace(/^https?:\/\//i, ''));
      if (m) {
        const shown = splitHost(m[1].toLowerCase()).registrable;
        if (shown && shown !== dom.parts.registrable) info.reasons.push(R('mismatch', 45, `Link text shows ${shown} but the link actually goes to ${dom.parts.registrable}`));
      }
    }
    const total = info.reasons.reduce((s, r) => s + r.points, 0);
    info.risk = total >= 30 ? 'bad' : total >= 10 ? 'warn' : 'ok';
    return info;
  }

  /* --------------------------------------------------------------- header parsing */
  function headerLine(raw, name) {
    const m = new RegExp('^' + name + '[ \\t]*:[ \\t]*(.+)$', 'im').exec(raw);
    return m ? { value: m[1].trim(), start: m.index, end: m.index + m[0].length } : null;
  }

  function parseAddress(value) {
    if (!value) return null;
    let name = ''; let addr = '';
    const m = /^(?:"?([^"<]*?)"?\s*)?<\s*([^<>\s]+@[^<>\s]+)\s*>/.exec(value);
    if (m) { name = (m[1] || '').trim(); addr = m[2]; } else {
      const a = /([^\s<>"]+@[^\s<>"]+)/.exec(value);
      addr = a ? a[1] : '';
      name = value.replace(addr, '').replace(/[<>"]/g, '').trim();
    }
    addr = addr.replace(/[>.,;]+$/, '').toLowerCase();
    const domain = addr.includes('@') ? addr.split('@').pop() : '';
    return { name, addr, domain, registrable: domain ? splitHost(domain).registrable : '' };
  }

  /* --------------------------------------------------------------- content rules */
  const NEGATION = /(?:\bno|\bnot|\bnon|\bwithout|\bnever)[\s-]*(?:\w+\s+)?$/i;
  const CONTENT_RULES = [
    { id: 'urgency', cat: 'urgency', pts: 8, cap: 20, title: 'Pressure to act quickly',
      why: 'Attackers create artificial time pressure so you react before you think. Real organisations rarely demand action within minutes.',
      re: /\b(urgent(?:ly)?|immediate(?:ly)?|act now|right away|asap|as soon as possible|final (?:notice|warning|reminder)|last (?:chance|warning)|expires? (?:in|today|soon)|within (?:\d+|one|two|24|48) ?(?:hours?|hrs?|minutes?|mins?|days?)|before (?:the )?close of business|by end of (?:the )?day|action required|(?:account|access|password) (?:will be|has been|will) (?:suspended|locked|closed|disabled|terminated|deactivated|expire)|time[- ]sensitive|do not delay|failure to (?:comply|respond|act))\b/gi },
    { id: 'threat', cat: 'threat', pts: 8, cap: 16, title: 'Fear or threat language',
      why: 'Threats of lost access, fines or legal action are designed to trigger a fight-or-flight reaction that reduces careful thinking.',
      re: /\b(legal action|lawsuit|prosecut\w+|arrest\w*|police|penalt(?:y|ies)|suspicious (?:activity|sign[- ]?in|login)|unusual (?:activity|sign[- ]?in|login)|unauthori[sz]ed (?:access|transaction|login|sign[- ]?in)|your account (?:has been|was) (?:compromised|hacked|limited|restricted|locked)|security (?:breach|incident)|virus|infected|malware detected|permanent(?:ly)? (?:lockout|locked|closed)|locked out)\b/gi },
    { id: 'reward', cat: 'reward', pts: 8, cap: 16, title: 'Too-good-to-be-true reward',
      why: 'Unexpected prizes and refunds play on greed and curiosity. If you did not enter or expect it, it is almost certainly bait.',
      re: /\b(you(?:'ve| have)? (?:been selected|won)|congratulations[,!]? you|winner|prize|lottery|gift ?card|free (?:gift|iphone|money)|claim your|refund (?:is )?(?:pending|waiting|available)|inheritance|unclaimed)\b/gi },
    { id: 'authority', cat: 'authority', pts: 6, cap: 6, title: 'Claims to be someone in authority',
      why: 'Impersonating executives, IT or officials pressures people to comply without questioning. Authority alone is not proof, but it is a common disguise.',
      re: /\b(ceo|chief executive|cfo|managing director|chairman|hr department|human resources|hr team|it (?:support|department|helpdesk|team|security)|help ?desk|security team|system administrator|internal revenue|law enforcement|compliance (?:team|department)|account team)\b/gi },
    { id: 'credential', cat: 'credential', pts: 15, cap: 30, title: 'Asks for credentials or sensitive data',
      why: 'Legitimate organisations do not ask you to send passwords, one-time codes or card details by email, message or phone.',
      re: /\b((?:verify|confirm|validate|re-?enter|restore) (?:your )?(?:account|identity|password|credentials|login|billing|payment|banking|card)(?: details| information| info)?|(?:reset|change|update) (?:it|your (?:network |account |email )?password)|update your (?:billing|payment)(?: details| information)?|enter your (?:password|credentials|pin|otp|code|card)|(?:send|share|reply with|provide|read out|give)(?: me| us)? (?:the |your )?(?:otp|code|verification code|mfa code|security code|password|pin|ssn)|social security number|card (?:number|details)|bank (?:account )?(?:details|number)|routing number|one[- ]time (?:code|password|passcode))\b/gi },
    { id: 'secrecy', cat: 'secrecy', pts: 20, cap: 20, title: 'Demands secrecy or bypassing procedure',
      why: 'Requests to keep quiet or skip normal approvals are a hallmark of business email compromise: they stop colleagues from spotting the fraud.',
      re: /\b(do not (?:discuss|share|tell|mention)|don'?t (?:tell|share|discuss|mention)|strictly confidential|keep (?:this|it) (?:confidential|between us|secret|quiet)|bypass (?:the )?(?:normal |standard |usual )?(?:procedure|process|approval|controls?)|no need to (?:verify|call|check)|skip (?:approval|verification))\b/gi },
    { id: 'payment', cat: 'payment', pts: 20, cap: 30, title: 'Money or payment request',
      why: 'Wire transfers, gift cards, changed bank details and fake billing problems are how attackers turn a message into cash.',
      re: /\b(wire (?:transfer|funds)|bank transfer|gift ?cards?|(?:new|updated|changed) (?:bank|banking|account|payment) (?:details|information|number)|process (?:the )?(?:attached )?(?:payment|invoice|wire)|(?:unpaid|overdue|outstanding) invoice|payment (?:failed|failure|declined|overdue)|billing (?:information|details)|update your billing)\b/gi },
    { id: 'qr', cat: 'qr', pts: 20, cap: 20, title: 'Asks you to scan a QR code',
      why: 'QR phishing ("quishing") moves you to a phone where desktop link filters do not apply and fake domains are harder to spot.',
      re: /\b(scan (?:the |this |our |below |attached )?(?:qr|barcode|code)\b|scan to (?:unlock|verify|secure|recover|log ?in))/gi },
    { id: 'macros', cat: 'attachment', pts: 25, cap: 25, title: 'Tells you to enable macros or content',
      why: 'Enabling content lets a document run code. Legitimate documents almost never need this.',
      re: /\b(enable (?:content|macros|editing))\b/gi },
    { id: 'mfa', cat: 'credential', pts: 10, cap: 10, title: 'Pushes you to approve a sign-in prompt',
      why: 'MFA-fatigue attacks spam approval prompts until someone taps Approve. Only approve prompts you started yourself.',
      re: /\b(approve (?:the |this )?(?:sign[- ]?in|login|request|notification|prompt)|accept (?:the )?(?:prompt|notification))\b/gi },
    { id: 'greeting', cat: 'other', pts: 6, cap: 6, title: 'Generic greeting',
      why: 'Bulk phishing rarely knows your name. "Dear customer" is a hint that the sender does not know who you are.',
      re: /^\s*(?:dear (?:customer|user|client|member|sir|madam|sir\/madam|valued (?:customer|user|member)|account holder|email user|friend|beneficiary)|hello (?:customer|user|member))\b/gim },
  ];

  function findAll(re, text, negationAware) {
    const out = [];
    const rx = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    let m;
    while ((m = rx.exec(text))) {
      if (m[0] === '') { rx.lastIndex++; continue; }
      if (negationAware && NEGATION.test(text.slice(Math.max(0, m.index - 14), m.index))) continue;
      out.push({ start: m.index, end: m.index + m[0].length, text: m[0] });
    }
    return out;
  }

  const DANGEROUS_EXT = 'iso|img|js|jse|vbs|vbe|wsf|scr|exe|bat|cmd|lnk|jar|msi|ps1|hta|dll|reg|chm|cab|one';
  const RE_ATTACH = new RegExp('[\\w\\-()]+(?:\\.[\\w\\-()]+)*\\.(?:' + DANGEROUS_EXT + '|html?|xhtml|svg|docm|xlsm|pptm|zip|rar|7z)\\b', 'gi');
  const RE_DOUBLE = new RegExp('[\\w\\-()]+\\.(?:pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|csv)\\.(?:' + DANGEROUS_EXT + '|html?)\\b', 'gi');
  const RE_PHONE = /(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}|\b1[- ]?8\d\d[- ]?[\dX]{3}[- ]?[\dX]{4}\b/gi;

  /* ------------------------------------------------------------------- main API */
  function analyze(input) {
    const raw = String(input || '');
    const findings = [];
    const highlights = [];
    const add = (f) => {
      f.severity = f.severity || severityFor(f.points);
      findings.push(f);
    };

    /* ---- headers ---- */
    const fromH = headerLine(raw, 'From');
    const replyH = headerLine(raw, 'Reply-To');
    const retH = headerLine(raw, 'Return-Path');
    const subjH = headerLine(raw, 'Subject');
    const from = fromH ? parseAddress(fromH.value) : null;
    const reply = replyH ? parseAddress(replyH.value) : null;
    const ret = retH ? parseAddress(retH.value) : null;
    const auth = {};
    let am; const reAuth = /\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|none|neutral|temperror|permerror)/gi;
    while ((am = reAuth.exec(raw))) auth[am[1].toLowerCase()] = am[2].toLowerCase();

    if (from) {
      const mark = fromH ? { start: fromH.start, end: fromH.end } : null;
      const ev = [`From: ${fromH.value}`];
      const nameLower = from.name.toLowerCase();
      // display name claims a brand that does not own the address domain
      const brandInName = BRANDS.find((b) => new RegExp('\\b' + b.key + '\\b').test(nameLower.replace(/[^a-z0-9 ]/g, '')) || nameLower.includes(b.name.toLowerCase().split(' ')[0]) && b.key.length >= 5 && nameLower.includes(b.key));
      if (brandInName && !ownerOf(from.registrable)) {
        add({ id: 'display-mismatch', category: 'sender', points: 30, title: `Display name says "${brandInName.name}" but the address is ${from.domain}`,
          why: 'Mail apps often show only the friendly name. Attackers set it to a trusted brand while the real address belongs to someone else.', evidence: ev });
        if (mark) highlights.push({ ...mark, cat: 'sender', label: 'Display name does not match sender domain' });
      } else if (/@/.test(from.name) && from.name.toLowerCase().match(/[^\s@]+@[^\s@]+/) && !from.name.toLowerCase().includes(from.domain)) {
        add({ id: 'display-email', category: 'sender', points: 30, title: 'Display name contains a different email address',
          why: 'Showing one address in the name while sending from another is a classic spoofing trick.', evidence: ev });
        if (mark) highlights.push({ ...mark, cat: 'sender', label: 'Display name contains another address' });
      } else if (/\b(ceo|cfo|director|president|chairman|hr|payroll|it support|help ?desk|security|admin|billing|accounts?)\b/i.test(from.name) && FREEMAIL.has(from.registrable)) {
        add({ id: 'freemail-role', category: 'sender', points: 30, title: `Sounds like an organisation or executive but sends from free mail (${from.domain})`,
          why: 'Executives and IT teams write from company addresses. A free-mail address behind an official-sounding name is a strong impersonation signal.', evidence: ev });
        if (mark) highlights.push({ ...mark, cat: 'sender', label: 'Official-sounding name on a free mail address' });
      }
      if (from.domain) {
        const d = analyzeDomain(from.domain, from.domain);
        const bad = d.reasons.find((r) => ['typo', 'combo', 'subdomain', 'homoglyph', 'nested'].includes(r.code));
        if (bad) {
          add({ id: 'sender-lookalike', category: 'sender', points: 50, title: 'Sender domain looks like an imitation',
            why: 'The domain the message really comes from imitates a trusted name. Check the address after the @, not the friendly name.', evidence: [`${from.addr}: ${bad.text}`] });
          if (mark) highlights.push({ ...mark, cat: 'sender', label: bad.text });
        }
      }
    }
    if (reply && from && reply.registrable && from.registrable && reply.registrable !== from.registrable) {
      add({ id: 'reply-mismatch', category: 'sender', points: 20, title: 'Reply-To goes to a different domain than the sender',
        why: 'Replies would go to an address the attacker controls, not to the apparent sender.', evidence: [`From: ${from.addr}`, `Reply-To: ${reply.addr}`] });
      highlights.push({ start: replyH.start, end: replyH.end, cat: 'sender', label: 'Reply-To differs from sender' });
    }
    if (ret && from && ret.registrable && from.registrable && ret.registrable !== from.registrable) {
      add({ id: 'return-mismatch', category: 'sender', points: 10, title: 'Return-Path domain differs from the sender',
        why: 'The technical sending address differs from the visible one. Sometimes legitimate (mailing services), but worth checking.', evidence: [`From: ${from.addr}`, `Return-Path: ${ret.addr}`] });
    }
    const authFail = ['spf', 'dkim', 'dmarc'].filter((k) => ['fail', 'softfail', 'permerror'].includes(auth[k]));
    if (authFail.length) {
      add({ id: 'auth-fail', category: 'sender', points: Math.min(35, authFail.length * 15), title: `Email authentication failed (${authFail.map((k) => k.toUpperCase()).join(', ')})`,
        why: 'SPF, DKIM and DMARC let receiving servers check that a domain really sent the message. A failure means the sender could not prove it.',
        evidence: authFail.map((k) => `${k.toUpperCase()}=${auth[k]}`) });
    }

    /* ---- links ---- */
    const urlMatches = extractUrlMatches(raw);
    const anchors = extractAnchors(raw);
    const urls = [];
    const seen = new Map();
    urlMatches.forEach((u) => {
      const key = normalizeUrlText(u.raw);
      const anchor = anchors.find((a) => normalizeUrlText(a.href) === key);
      if (seen.has(key)) { if (anchor && !seen.get(key).linkText) { Object.assign(seen.get(key), analyzeUrl(u.raw, u.hasScheme, anchor.text)); } return; }
      const info = analyzeUrl(u.raw, u.hasScheme, anchor ? anchor.text : '');
      info.count = 1; seen.set(key, info); urls.push(info);
    });
    anchors.filter((a) => /^(javascript|data|vbscript):/i.test(a.href)).forEach((a) => urls.push(analyzeUrl(a.href, true, a.text)));
    urlMatches.forEach((u) => {
      const info = seen.get(normalizeUrlText(u.raw));
      if (info) highlights.push({ start: u.start, end: u.end, cat: 'link', label: info.reasons.length ? info.reasons[0].text : 'Link', risk: info.risk });
    });

    const byCode = {};
    urls.forEach((u) => u.reasons.forEach((r) => { (byCode[r.code] = byCode[r.code] || { r, urls: [] }).urls.push(u.display); }));
    const LINK_TEXT = {
      ip: ['Link points to a raw IP address', 'Real services use domain names. IP-address links are typical of throw-away phishing servers.'],
      homoglyph: ['Link uses look-alike characters', 'Characters from other alphabets can look identical to Latin letters, so the address appears to be a trusted brand.'],
      typo: ['Link domain is a look-alike spelling of a brand', 'A single swapped character (0 for o, 1 for l) is easy to miss and is enough to send you to an attacker\'s site.'],
      combo: ['Link domain wraps a brand in security-style words', 'Adding words such as "secure" or "login" to a brand name makes a fake site look official. The brand does not own this domain.'],
      subdomain: ['Real domain is hidden behind a brand name in the sub-domain', 'Read a web address from right to left: the part just before the ending is the true owner, whatever appears in front of it.'],
      nested: ['Sub-domain trap: a trusted-looking address is buried at the front', 'Attackers place a familiar domain first and their own domain last. The last domain is the one that counts.'],
      mismatch: ['Link text does not match where the link goes', 'What you see is not where you land. Hover or long-press to reveal the real destination before you click.'],
      userinfo: ['Link contains "@" before the host', 'Everything before the "@" is ignored by the browser. The site after it is the real destination.'],
      shortener: ['Shortened link hides the destination', 'You cannot judge a short link by looking at it. Expand it in a safe tool before opening.'],
      tld: ['Link ends in a commonly abused domain ending', 'Some cheap domain endings are heavily used for scams. Not proof on its own, but suspicious with other signs.'],
      http: ['Link is not encrypted (http)', 'Login pages should always use https. Missing encryption is a warning sign.'],
      hyphens: ['Domain has many hyphens', 'Long hyphenated names are a common pattern in disposable phishing domains.'],
      depth: ['Unusually deep chain of sub-domains', 'Long sub-domain chains are used to push the real domain out of view, especially on phones.'],
      freehost: ['Link is on a free hosting platform', 'Phishing pages are often hosted on free platforms. Companies use their own domains for sign-in.'],
      loginpath: ['Login-style page on an unfamiliar domain', 'Pages asking you to sign in or verify should live on the organisation\'s own domain.'],
      encoded: ['Heavily encoded link', 'Excess encoding can hide the real destination or bypass filters.'],
      jsdata: ['Link runs a script instead of opening a site', 'script: and data: links can execute code or display a fake page.'],
      malformed: ['Malformed link', 'The address could not be parsed cleanly.'],
    };
    Object.keys(byCode).forEach((code) => {
      const { r, urls: list } = byCode[code];
      const t = LINK_TEXT[code];
      if (!t) return;
      const pts = Math.min(60, r.points + Math.min(10, (list.length - 1) * 5));
      add({ id: 'link-' + code, category: 'link', points: pts, title: t[0], why: t[1], evidence: uniq(list).slice(0, 4) });
    });

    /* ---- attachments (scan with links and emails blanked out) ---- */
    let scrub = raw;
    urlMatches.forEach((u) => { scrub = scrub.slice(0, u.start) + ' '.repeat(u.end - u.start) + scrub.slice(u.end); });
    scrub = scrub.replace(/[^\s<>"]+@[^\s<>"]+/g, (m) => ' '.repeat(m.length));
    const doubles = findAll(RE_DOUBLE, scrub);
    const attach = findAll(RE_ATTACH, scrub).filter((a) => !doubles.some((d) => a.start >= d.start && a.end <= d.end));
    if (doubles.length) {
      add({ id: 'attach-double', category: 'attachment', points: 50, title: 'Attachment hides an executable behind a document name',
        why: 'A file like invoice.pdf.exe looks like a document but runs as a program. Extensions are often hidden by default.', evidence: uniq(doubles.map((d) => d.text)) });
      doubles.forEach((d) => highlights.push({ start: d.start, end: d.end, cat: 'attachment', label: 'Double extension' }));
    }
    const exec = attach.filter((a) => new RegExp('\\.(?:' + DANGEROUS_EXT + ')$', 'i').test(a.text));
    const web = attach.filter((a) => /\.(?:html?|xhtml|svg)$/i.test(a.text));
    const macro = attach.filter((a) => /\.(?:docm|xlsm|pptm)$/i.test(a.text));
    const arch = attach.filter((a) => /\.(?:zip|rar|7z)$/i.test(a.text));
    [[exec, 'attach-exec', 45, 'Attachment type can run code', 'Disk images, scripts, shortcuts and executables are common malware carriers and are rarely sent legitimately.'],
      [web, 'attach-html', 25, 'HTML attachment', 'HTML files can display a fake login page from your own computer ("HTML smuggling"), bypassing link checks.'],
      [macro, 'attach-macro', 25, 'Macro-enabled Office file', 'Macros can run code as soon as you enable them.'],
      [arch, 'attach-archive', 12, 'Compressed archive attachment', 'Archives are used to hide malicious files from scanners. Treat unexpected ones with caution.']]
      .forEach(([list, id, pts, title, why]) => {
        if (!list.length) return;
        add({ id, category: 'attachment', points: pts, title, why, evidence: uniq(list.map((x) => x.text)) });
        list.forEach((x) => highlights.push({ start: x.start, end: x.end, cat: 'attachment', label: title }));
      });

    /* ---- content rules ---- */
    CONTENT_RULES.forEach((rule) => {
      const matches = findAll(rule.re, scrub, true); // scrubbed: ignore words inside addresses and URLs
      if (!matches.length) return;
      const distinct = uniq(matches.map((m) => m.text.toLowerCase().trim()));
      const pts = Math.min(rule.cap, distinct.length * rule.pts);
      add({ id: rule.id, category: rule.cat, points: pts, title: rule.title, why: rule.why, evidence: distinct.slice(0, 5).map((d) => `"${d}"`) });
      matches.forEach((m) => highlights.push({ start: m.start, end: m.end, cat: rule.cat, label: rule.title }));
    });

    /* ---- callback / TOAD ---- */
    const phones = findAll(RE_PHONE, raw).filter((p) => p.text.replace(/\D/g, '').length >= 10 || /X/i.test(p.text));
    if (phones.length && /\b(call|dial|phone|contact (?:our )?support|hotline)\b/i.test(raw) && /\b(subscription|renewal|renewed|charge[ds]?|invoice|payment|refund|order|virus|infected|security alert|billing|overdue)\b/i.test(raw)) {
      const noLinks = urls.length === 0;
      add({ id: 'callback', category: 'callback', points: 30, title: 'Tells you to phone a number about a charge or problem',
        why: 'Callback phishing (TOAD) contains no malicious link, only a phone number. The "support agent" then steals money or installs remote-access software.' + (noLinks ? ' This message has no links at all, which is how it slips past filters.' : ''),
        evidence: uniq(phones.map((p) => p.text.trim())).slice(0, 3) });
      phones.forEach((p) => highlights.push({ start: p.start, end: p.end, cat: 'callback', label: 'Callback number' }));
    }
    if (/\b(voice ?mail|voice message)\b/i.test(raw) && /\b(confirm|as discussed|urgent request|asap)\b/i.test(raw)) {
      add({ id: 'voicemail', category: 'other', points: 10, title: 'Voicemail follow-up asking you to confirm a request',
        why: 'Attackers pair AI-cloned voicemails with a short email asking you to confirm. Verify through a number you already know.', evidence: ['voicemail + "confirm" request'] });
    }
    if (subjH && /^\s*(?:fw|fwd)\s*:/i.test(subjH.value) && (raw.match(/^(?:from|sent|to|subject)\s*:/gim) || []).length >= 4) {
      add({ id: 'fake-forward', category: 'other', points: 10, title: 'Forwarded chain with pasted headers',
        why: 'Fake "FW:" threads borrow the look of a conversation you were never part of to appear legitimate.', evidence: [subjH.value] });
    }

    /* ---- score + verdict ---- */
    const score = Math.min(100, findings.reduce((s, f) => s + f.points, 0));
    const verdict = score >= 50 ? 'malicious' : score >= 20 ? 'suspicious' : 'safe';
    findings.sort((a, b) => b.points - a.points);

    const domains = uniq([
      ...(from && from.registrable && !ownerOf(from.registrable) && verdict === 'malicious' ? [from.registrable] : []),
      ...urls.filter((u) => u.risk === 'bad' && u.parts && !ownerOf(u.parts.registrable)).map((u) => u.parts.registrable),
    ]);

    const top = findings.slice(0, 3).map((f) => f.title.replace(/\.$/, ''));
    const summaries = {
      safe: findings.length ? 'No strong phishing signals. A few minor observations are listed below.' : 'No phishing signals found in the text you pasted.',
      suspicious: 'Some signals are present, but not enough to be sure. Treat the message with caution and verify it before acting. Main concerns: ' + top.join('; ') + '.',
      malicious: 'Several strong phishing signals appear together. Do not interact with this message. Main concerns: ' + top.join('; ') + '.',
    };
    const actions = { safe: 'Close', suspicious: 'Warn user', malicious: 'Block domain & escalate' };

    highlights.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const merged = [];
    highlights.forEach((h) => { const last = merged[merged.length - 1]; if (!last || h.start >= last.end) merged.push(h); });

    return {
      raw, score, verdict, action: actions[verdict], summary: summaries[verdict], findings, urls,
      highlights: merged, blockList: domains,
      headers: { from, reply, returnPath: ret, subject: subjH ? subjH.value : '', auth },
      counts: { high: findings.filter((f) => f.severity === 'high').length, medium: findings.filter((f) => f.severity === 'medium').length, low: findings.filter((f) => f.severity === 'low').length },
    };
  }

  return { CATEGORIES, BRANDS, analyze, analyzeDomain, splitHost, defang, levenshtein, parseAddress, extractUrlMatches };
});
