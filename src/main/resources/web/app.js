/* snap-sim console: signs SNAP requests in the browser with WebCrypto.
 * The RSA private key is generated non-extractable and never leaves this page. */
'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const SNAP = '/snap/v1.0';
  const enc = new TextEncoder();
  const state = { keys: null, clientKey: null, secret: null, hmacKey: null, accounts: [], benef: [], token: null, tokenExp: 0, last: null, refSeq: 0 };

  // ---------------------------------------------------------------- crypto helpers
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  const sha256hex = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
  const rsaSign = async (s) => b64(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', state.keys.privateKey, enc.encode(s)));
  const hmacSign = async (s) => b64(await crypto.subtle.sign('HMAC', state.hmacKey, enc.encode(s)));

  /** X-TIMESTAMP in local time with its offset, e.g. 2026-11-21T16:30:00+07:00 */
  function timestamp() {
    const d = new Date();
    const p = (n) => String(Math.abs(n)).padStart(2, '0');
    const off = -d.getTimezoneOffset();
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
      + `${off >= 0 ? '+' : '-'}${p(Math.trunc(off / 60))}:${p(off % 60)}`;
  }
  const externalId = () => String(Date.now()) + String(crypto.getRandomValues(new Uint32Array(1))[0] % 100000).padStart(5, '0');
  const newRef = () => `TRX-${Date.now().toString(36).toUpperCase()}-${++state.refSeq}`;

  // ---------------------------------------------------------------- http
  async function send(path, headers, body) {
    const res = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body });
    let json = null;
    try { json = await res.json(); } catch { json = { error: 'respons bukan JSON' }; }
    return { status: res.status, json };
  }

  async function snap(path, bodyObj, opt = {}) {
    if (!state.token || Date.now() > state.tokenExp) await getToken(true);
    const ts = timestamp();
    const signedBody = JSON.stringify(bodyObj); // already minified
    const sentBody = opt.sentBody || signedBody;
    const token = opt.token || state.token;
    const bodyHash = await sha256hex(signedBody);
    const sts = `POST:${SNAP}${path}:${token}:${bodyHash}:${ts}`;
    const headers = {
      Authorization: `Bearer ${token}`,
      'X-TIMESTAMP': ts,
      'X-SIGNATURE': await hmacSign(sts),
      'X-PARTNER-ID': state.clientKey,
      'X-EXTERNAL-ID': opt.externalId || externalId(),
      'CHANNEL-ID': '95221',
    };
    const r = await send(SNAP + path, headers, sentBody);
    if (opt.silent) return r;
    state.last = { path, bodyObj, headers };
    show({
      method: 'POST', path: SNAP + path, headers, body: sentBody, res: r,
      segs: [['method', 'HTTP method', 'POST'], ['path', 'Path', SNAP + path], ['token', 'Access token', token],
        ['hash', 'SHA-256(minify(body))', bodyHash], ['time', 'X-TIMESTAMP', ts]],
      algo: 'X-SIGNATURE = Base64(HMAC-SHA512(clientSecret, string di atas))'
        + (opt.sentBody ? '\nCatatan: body yang dikirim BUKAN body yang ditandatangani.' : ''),
    });
    return r;
  }

  async function getToken(silent) {
    const ts = timestamp();
    const sts = `${state.clientKey}|${ts}`;
    const headers = { 'X-TIMESTAMP': ts, 'X-CLIENT-KEY': state.clientKey, 'X-SIGNATURE': await rsaSign(sts) };
    const body = JSON.stringify({ grantType: 'client_credentials' });
    const r = await send(SNAP + '/access-token/b2b', headers, body);
    if (r.status === 200) {
      state.token = r.json.accessToken;
      state.tokenExp = Date.now() + (Number(r.json.expiresIn) - 30) * 1000;
      done('s2');
      enable(true);
    }
    if (!silent) {
      show({ method: 'POST', path: SNAP + '/access-token/b2b', headers, body, res: r,
        segs: [['key', 'X-CLIENT-KEY', state.clientKey], ['time', 'X-TIMESTAMP', ts]], joiner: '|',
        algo: 'X-SIGNATURE = Base64(SHA256withRSA(kunci privat di browser, string di atas))' });
    }
    return r;
  }

  // ---------------------------------------------------------------- inspector
  function show({ method, path, headers, body, res, segs, algo, joiner = ':' }) {
    $('ins-empty').hidden = true;
    $('ins').hidden = false;
    $('r-method').textContent = method;
    $('r-path').textContent = path;
    const sts = $('r-sts');
    sts.replaceChildren();
    segs.forEach(([cls, label, value], i) => {
      if (i) { const s = document.createElement('span'); s.className = 'sep'; s.textContent = joiner; sts.append(s); }
      const d = document.createElement('div'); d.className = `seg ${cls}`;
      const b = document.createElement('b'); b.textContent = label;
      const v = document.createElement('span'); v.textContent = value;
      d.append(b, v); sts.append(d);
    });
    $('r-algo').textContent = algo;
    const tb = $('r-headers');
    tb.replaceChildren(...Object.entries({ 'Content-Type': 'application/json', ...headers }).map(([k, v]) => {
      const tr = document.createElement('tr');
      const a = document.createElement('td'); a.textContent = k;
      const b = document.createElement('td'); b.textContent = v;
      tr.append(a, b); return tr;
    }));
    $('r-body').textContent = pretty(body);
    const st = $('r-status');
    st.textContent = `HTTP ${res.status}`;
    st.className = `status${res.status >= 400 ? ' bad' : ''}`;
    const code = res.json && res.json.responseCode;
    const parts = $('r-code');
    parts.replaceChildren();
    if (typeof code === 'string' && code.length === 7) {
      [['HTTP', code.slice(0, 3)], ['Layanan', code.slice(3, 5)], ['Kasus', code.slice(5)], ['Arti', res.json.responseMessage || '']]
        .forEach(([k, v]) => { const d = document.createElement('div'); const b = document.createElement('b'); b.textContent = k; d.append(b, document.createTextNode(v)); parts.append(d); });
    }
    $('r-res').textContent = JSON.stringify(res.json, null, 2);
    const h = Object.entries({ 'Content-Type': 'application/json', ...headers }).map(([k, v]) => `  -H '${k}: ${v}'`).join(' \\\n');
    $('r-curl').textContent = `curl -X POST '${location.origin}${path}' \\\n${h} \\\n  -d '${body}'`;
  }
  const pretty = (s) => { try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; } };

  // ---------------------------------------------------------------- ui state
  const done = (id) => $(id).classList.add('done');
  function enable(on) {
    ['b-balance', 'b-inquiry', 'b-transfer', 'b-status', 'x-replay', 'x-tamper', 'x-token', 'x-peek', 'x-dormant']
      .forEach((id) => { $(id).disabled = !on; });
  }
  const rupiah = (v) => 'Rp' + Number(v).toLocaleString('id-ID', { minimumFractionDigits: 2 });
  function fillAccounts() {
    for (const id of ['i-bal-acc', 'i-tr-src']) {
      $(id).replaceChildren(...state.accounts.map((a) => {
        const o = document.createElement('option'); o.value = a.accountNo; o.textContent = `${a.accountNo} · ${rupiah(a.balance.value)}`; return o;
      }));
    }
  }
  function busy(btn, fn) {
    return async () => {
      btn.disabled = true;
      try { await fn(); } catch (e) { alert('Gagal: ' + e.message); } finally { btn.disabled = false; }
    };
  }

  // ---------------------------------------------------------------- steps
  $('b-sandbox').addEventListener('click', busy($('b-sandbox'), async () => {
    state.keys = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      false, ['sign', 'verify']);
    const spki = b64(await crypto.subtle.exportKey('spki', state.keys.publicKey));
    const body = JSON.stringify({ publicKey: spki });
    const r = await send('/sandbox/partners', {}, body);
    if (r.status !== 201) {
      show({ method: 'POST', path: '/sandbox/partners', headers: {}, body, res: r, segs: [], algo: '' });
      return;
    }
    Object.assign(state, { clientKey: r.json.clientKey, secret: r.json.clientSecret, accounts: r.json.accounts, benef: r.json.beneficiaries, token: null });
    state.hmacKey = await crypto.subtle.importKey('raw', enc.encode(state.secret), { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
    $('f-client').textContent = state.clientKey;
    $('f-secret').textContent = state.secret;
    $('f-accounts').textContent = state.accounts.map((a) => `${a.accountNo} (${rupiah(a.balance.value)})`).join(', ');
    $('f-benef').textContent = state.benef.map((b) => `${b.accountNo}${b.status === 'DORMANT' ? ' (dormant)' : ''}`).join(', ');
    $('sandbox-facts').hidden = false;
    fillAccounts();
    $('i-inq-acc').value = state.benef[0].accountNo;
    $('i-tr-dst').value = state.benef[0].accountNo;
    $('i-tr-ref').value = newRef();
    $('b-token').disabled = false;
    done('s1');
    show({ method: 'POST', path: '/sandbox/partners', headers: {}, body, res: { status: r.status, json: { ...r.json } },
      segs: [['key', 'Kunci publik (SPKI, Base64)', spki.slice(0, 64) + '…']], algo: 'Kunci privat tetap di browser ini (non-extractable).' });
  }));

  $('b-token').addEventListener('click', busy($('b-token'), () => getToken(false)));

  $('b-balance').addEventListener('click', busy($('b-balance'), async () => {
    const r = await snap('/balance-inquiry', { partnerReferenceNo: newRef(), accountNo: $('i-bal-acc').value });
    if (r.status === 200) done('s3');
  }));

  $('b-inquiry').addEventListener('click', busy($('b-inquiry'), async () => {
    const r = await snap('/account-inquiry-internal', { partnerReferenceNo: newRef(), beneficiaryAccountNo: $('i-inq-acc').value.trim() });
    if (r.status === 200) done('s4');
  }));

  function transferBody() {
    const amt = Number(String($('i-tr-amt').value).replace(/[^0-9.]/g, ''));
    return {
      partnerReferenceNo: $('i-tr-ref').value.trim(),
      amount: { value: Number.isFinite(amt) ? amt.toFixed(2) : $('i-tr-amt').value, currency: 'IDR' },
      beneficiaryAccountNo: $('i-tr-dst').value.trim(),
      sourceAccountNo: $('i-tr-src').value,
      remark: $('i-tr-remark').value,
    };
  }
  $('b-transfer').addEventListener('click', busy($('b-transfer'), async () => {
    const body = transferBody();
    const r = await snap('/transfer-intrabank', body);
    if (r.status === 200) {
      done('s5');
      $('i-st-ref').value = body.partnerReferenceNo;
      const acc = state.accounts.find((a) => a.accountNo === body.sourceAccountNo);
      if (acc) {
        // refresh the balance shown in the dropdown without replacing the transfer in the inspector
        const b = await snap('/balance-inquiry', { partnerReferenceNo: newRef(), accountNo: acc.accountNo }, { silent: true });
        if (b.status === 200) { acc.balance = b.json.accountInfos[0].availableBalance; fillAccounts(); $('i-tr-src').value = acc.accountNo; }
      }
    }
  }));

  $('b-status').addEventListener('click', busy($('b-status'), async () => {
    const r = await snap('/transfer/status', { originalPartnerReferenceNo: $('i-st-ref').value.trim(), serviceCode: '17' });
    if (r.status === 200) done('s6');
  }));

  // ---------------------------------------------------------------- attacks
  $('x-replay').addEventListener('click', busy($('x-replay'), async () => {
    if (!state.last) await snap('/balance-inquiry', { partnerReferenceNo: newRef(), accountNo: state.accounts[0].accountNo });
    const { path, bodyObj, headers } = state.last;
    await snap(path, bodyObj, { externalId: headers['X-EXTERNAL-ID'] });
  }));
  $('x-tamper').addEventListener('click', busy($('x-tamper'), async () => {
    const signed = { ...transferBody(), partnerReferenceNo: newRef(), amount: { value: '10.00', currency: 'IDR' } };
    const sent = JSON.stringify({ ...signed, amount: { value: '20000000.00', currency: 'IDR' } });
    await snap('/transfer-intrabank', signed, { sentBody: sent });
  }));
  $('x-token').addEventListener('click', busy($('x-token'), async () => {
    const fake = b64(crypto.getRandomValues(new Uint8Array(32))).replace(/[+/=]/g, 'A');
    await snap('/balance-inquiry', { partnerReferenceNo: newRef(), accountNo: state.accounts[0].accountNo }, { token: fake });
  }));
  $('x-peek').addEventListener('click', busy($('x-peek'), () =>
    snap('/balance-inquiry', { partnerReferenceNo: newRef(), accountNo: state.benef[0].accountNo })));
  $('x-dormant').addEventListener('click', busy($('x-dormant'), () =>
    snap('/transfer-intrabank', { ...transferBody(), partnerReferenceNo: newRef(), beneficiaryAccountNo: state.benef[2].accountNo })));

  if (!window.crypto || !crypto.subtle) {
    $('b-sandbox').disabled = true;
    $('ins-empty').textContent = 'Browser ini tidak mendukung WebCrypto (butuh HTTPS atau localhost).';
  }
})();
