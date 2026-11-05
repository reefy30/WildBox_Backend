const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createAuthController, normalizeEmail } = require('../controllers/authController');
const { loadConfig } = require('../lib/config');
const { createApp } = require('../app');
const { createLimiter } = require('../lib/rateLimit');
const config = { jwtSecret: 'a'.repeat(32), otpSecret: 'b'.repeat(32), mailFrom: 'test@example.com', origins: ['https://example.com'] };
function harness() {
  let record, delivered, calls = 0, allowed = true, mailError = false, time = Date.now();
  const matches = q => record && (!q._id || q._id === record._id) && (!q.codeHash || q.codeHash === record.codeHash) && (!q.expiresAt || record.expiresAt > q.expiresAt.$gt) && (!q.attempts || (q.attempts.$lt !== undefined ? record.attempts < q.attempts.$lt : record.attempts <= q.attempts.$lte));
  const VerificationCode = {
    async findOneAndUpdate(q, u) {
      if (u.$set) { record = { _id: 'code-id', email: q.email, ...u.$set }; return { ...record }; }
      if (!matches(q)) return null;
      record.attempts += 1; return { ...record };
    },
    async findOneAndDelete(q) { if (!matches(q)) return null; const old = record; record = null; return old; },
    async deleteOne(q) { if (matches(q)) record = null; }
  };
  const User = { async findOneAndUpdate(q) { calls++; return { _id: 'user-id', email: q.email }; } };
  const allow = async () => allowed;
  const controller = createAuthController({ User, VerificationCode, config, allow, now: () => time,
    mailer: { emails: { async send(message) { delivered = message; return mailError ? { error: { message: 'private' } } : { data: {} }; } } } });
  const invoke = async (method, body) => {
    const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(value) { this.body = value; return this; } };
    await controller[method]({ body }, res); return res;
  };
  return { controller, allow, invoke, get record() { return record; }, get calls() { return calls; },
    get code() { return delivered.text.match(/\d{6}/)[0]; }, setAllowed(v) { allowed = v; }, setMailError() { mailError = true; }, expire() { time += 120001; } };
}
test('email normalization rejects NoSQL operators and malformed input', () => {
  for (const value of [null, {}, { $ne: null }, ['a@b.com'], 'bad', 'a@b.com\r\nBcc:x']) assert.equal(normalizeEmail(value), null);
  assert.equal(normalizeEmail(' User@Example.com '), 'user@example.com');
});
test('email alone never issues a JWT', async () => {
  const h = harness(); const res = await h.invoke('signIn', { email: 'user@example.com' });
  assert.equal(res.statusCode, 200); assert.equal(res.body.token, undefined); assert.equal(h.calls, 0);
  assert.equal(h.record.code, undefined); assert.notEqual(h.record.codeHash, h.code);
});
test('unconfigured provider login fails closed', async () => {
  const h = harness(); const res = await h.invoke('googleAppleSignIn', { email: 'victim@example.com' });
  assert.equal(res.statusCode, 501); assert.equal(res.body.token, undefined); assert.equal(h.calls, 0);
});
test('correct code returns constrained JWT and replay fails', async () => {
  const h = harness(); await h.invoke('sendCode', { email: 'USER@example.com' });
  const code = h.code; const res = await h.invoke('verifyCode', { email: 'user@example.com', code });
  const decoded = jwt.verify(res.body.token, config.jwtSecret, { algorithms: ['HS256'], issuer: 'wildbox-api', audience: 'wildbox-client' });
  assert.equal(decoded.sub, 'user-id'); assert.equal(decoded.exp - decoded.iat, 3600);
  assert.equal((await h.invoke('verifyCode', { email: 'user@example.com', code })).statusCode, 400);
});
test('concurrent correct submissions issue only one token', async () => {
  const h = harness(); await h.invoke('sendCode', { email: 'user@example.com' });
  const results = await Promise.all([1, 2].map(() => h.invoke('verifyCode', { email: 'user@example.com', code: h.code })));
  assert.equal(results.filter(r => r.body.token).length, 1); assert.equal(h.calls, 1);
});
test('expired codes fail and five guesses exhaust the challenge', async () => {
  const h = harness(); await h.invoke('sendCode', { email: 'user@example.com' }); const code = h.code;
  for (let i = 0; i < 5; i++) assert.equal((await h.invoke('verifyCode', { email: 'user@example.com', code: '000000' })).statusCode, 400);
  assert.equal((await h.invoke('verifyCode', { email: 'user@example.com', code })).statusCode, 400);
  await h.invoke('sendCode', { email: 'user@example.com' }); h.expire();
  assert.equal((await h.invoke('verifyCode', { email: 'user@example.com', code: h.code })).statusCode, 400);
});
test('provider send failure invalidates challenge and exposes no provider details', async () => {
  const h = harness(); h.setMailError(); const res = await h.invoke('sendCode', { email: 'user@example.com' });
  assert.equal(res.statusCode, 503); assert.equal(h.record, null); assert.ok(!JSON.stringify(res.body).includes('private'));
});
test('limits stop issuance and verification', async () => {
  const h = harness(); h.setAllowed(false);
  assert.equal((await h.invoke('sendCode', { email: 'user@example.com' })).statusCode, 429);
  assert.equal((await h.invoke('verifyCode', { email: 'user@example.com', code: '123456' })).statusCode, 429);
  assert.equal(h.record, undefined);
});
test('configuration rejects missing, short, or shared secrets', () => {
  const env = { MONGO_URI: 'mongodb://localhost/test', JWT_SECRET: config.jwtSecret, OTP_SECRET: config.otpSecret, RESEND_API: 'test-only', MAIL_FROM: config.mailFrom };
  assert.throws(() => loadConfig({})); assert.throws(() => loadConfig({ ...env, JWT_SECRET: 'short' }));
  assert.throws(() => loadConfig({ ...env, OTP_SECRET: config.jwtSecret }));
  assert.throws(() => loadConfig({ ...env, NODE_ENV: 'production', CORS_ORIGINS: 'http://example.com' }));
  assert.equal(loadConfig(env).port, 5000);
});
test('database limiter hashes identities and enforces shared bucket count', async () => {
  let count = 0, id;
  const allow = createLimiter({ async findOneAndUpdate(q) { id = q._id; return { count: ++count }; } }, config.otpSecret, () => 100);
  assert.equal(await allow('email', 'private@example.com', 1, 1000), true);
  assert.equal(await allow('email', 'private@example.com', 1, 1000), false);
  assert.match(id, /^[a-f0-9]{64}$/);
});
test('HTTP rejects malformed/oversize bodies, handles errors, and restricts CORS', async t => {
  const h = harness(); const server = createApp({ controller: h.controller, allow: h.allow, config }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve)); t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = (body, origin = 'https://evil.example') => fetch(`${base}/api/auth/sign-in`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body });
  let res = await request('{'); assert.equal(res.status, 400); assert.equal(res.headers.get('access-control-allow-origin'), null);
  res = await request(JSON.stringify({ email: 'user@example.com', padding: 'x'.repeat(9000) })); assert.equal(res.status, 413);
  res = await request(JSON.stringify({ email: { $ne: null } })); assert.equal(res.status, 400);
  res = await request(JSON.stringify({ email: 'user@example.com' }), 'https://example.com'); assert.equal(res.status, 200); assert.equal(res.headers.get('access-control-allow-origin'), 'https://example.com'); assert.equal(res.headers.get('cache-control'), 'no-store');
});
test('database failure produces generic HTTP error with no token', async t => {
  const h = harness();
  const server = createApp({ controller: h.controller, allow: async () => { throw new Error('private database details'); }, config }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve)); t.after(() => new Promise(resolve => server.close(resolve)));
  const res = await fetch(`http://127.0.0.1:${server.address().port}/api/auth/sign-in`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'user@example.com' }) });
  assert.equal(res.status, 503); const body = await res.json(); assert.equal(body.token, undefined); assert.ok(!JSON.stringify(body).includes('private'));
});
test('replacement code invalidates previous challenge', async () => {
  const h = harness(); await h.invoke('sendCode', { email: 'user@example.com' }); const oldCode = h.code;
  // Force a different challenge without relying on random uniqueness in the assertion.
  do { await h.invoke('sendCode', { email: 'user@example.com' }); } while (h.code === oldCode);
  assert.equal((await h.invoke('verifyCode', { email: 'user@example.com', code: oldCode })).statusCode, 400);
  assert.equal((await h.invoke('verifyCode', { email: 'user@example.com', code: h.code })).statusCode, 200);
});
test('installed Resend adapter accepts text messages without network access', async t => {
  const { Resend } = require('resend'); const originalFetch = global.fetch;
  t.after(() => { global.fetch = originalFetch; });
  let payload;
  global.fetch = async (_url, options) => { payload = JSON.parse(options.body); return new Response(JSON.stringify({ id: 'offline-test' }), { status: 200, headers: { 'Content-Type': 'application/json' } }); };
  const result = await new Resend('re_offline_test_not_a_real_key').emails.send({ from: 'test@example.com', to: ['user@example.com'], subject: 'Test', text: 'Verification test' });
  assert.equal(result.data.id, 'offline-test'); assert.equal(payload.text, 'Verification test');
});
