const { randomInt, createHmac, timingSafeEqual } = require('node:crypto');
const jwt = require('jsonwebtoken');
function normalizeEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}
function createAuthController({ User, VerificationCode, mailer, config, allow, now = Date.now }) {
  const hash = (email, code) => createHmac('sha256', config.otpSecret).update(`${email}:${code}`).digest('hex');
  const invalid = res => res.status(400).json({ message: 'Invalid or expired code' });
  const sendCode = async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    if (!email) return res.status(400).json({ message: 'Invalid email address' });
    if (!await allow('send-email', email, 3, 15 * 60 * 1000)) return res.status(429).json({ message: 'Please try again later' });
    const code = randomInt(100000, 1000000).toString();
    const codeHash = hash(email, code);
    await VerificationCode.findOneAndUpdate({ email }, { $set: { codeHash, attempts: 0, expiresAt: new Date(now() + 120000) } }, { upsert: true });
    try {
      const result = await mailer.emails.send({ from: config.mailFrom, to: [email], subject: 'WildBox Verification', text: `Your verification code is: ${code}` });
      if (result.error) throw new Error('Mail provider rejected request');
    } catch (_) {
      await VerificationCode.deleteOne({ email, codeHash });
      return res.status(503).json({ message: 'Unable to send code. Please try again later' });
    }
    return res.json({ message: 'Verification code sent' });
  };
  const verifyCode = async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const code = req.body?.code;
    if (!email || typeof code !== 'string' || !/^\d{6}$/.test(code)) return invalid(res);
    if (!await allow('verify-email', email, 15, 15 * 60 * 1000)) return res.status(429).json({ message: 'Please try again later' });
    const entry = await VerificationCode.findOneAndUpdate({ email, expiresAt: { $gt: new Date(now()) }, attempts: { $lt: 5 } }, { $inc: { attempts: 1 } }, { new: true });
    if (!entry || typeof entry.codeHash !== 'string' || !/^[a-f0-9]{64}$/.test(entry.codeHash)) return invalid(res);
    const codeHash = hash(email, code);
    if (!timingSafeEqual(Buffer.from(entry.codeHash, 'hex'), Buffer.from(codeHash, 'hex'))) return invalid(res);
    // One atomic consumption wins, including simultaneous correct requests.
    const consumed = await VerificationCode.findOneAndDelete({ _id: entry._id, codeHash, expiresAt: { $gt: new Date(now()) }, attempts: { $lte: 5 } });
    if (!consumed) return invalid(res);
    let user;
    try {
      user = await User.findOneAndUpdate({ email }, { $setOnInsert: { email } }, { new: true, upsert: true, runValidators: true });
    } catch (err) {
      if (err.code !== 11000) throw err;
      user = await User.findOne({ email });
      if (!user) throw err;
    }
    const token = jwt.sign({ userId: String(user._id) }, config.jwtSecret, { algorithm: 'HS256', expiresIn: '1h', issuer: 'wildbox-api', audience: 'wildbox-client', subject: String(user._id) });
    return res.json({ token, user: { id: user._id, email: user.email } });
  };
  return { sendCode, verifyCode, signIn: sendCode,
    googleAppleSignIn: (_req, res) => res.status(501).json({ message: 'Provider sign-in is not configured' }) };
}
module.exports = { createAuthController, normalizeEmail };
