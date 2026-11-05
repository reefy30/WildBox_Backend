function loadConfig(env = process.env) {
  for (const name of ['MONGO_URI', 'JWT_SECRET', 'OTP_SECRET', 'RESEND_API', 'MAIL_FROM']) {
    if (!env[name]) throw new Error(`Missing configuration: ${name}`);
  }
  for (const name of ['JWT_SECRET', 'OTP_SECRET']) {
    if (Buffer.byteLength(env[name]) < 32) throw new Error(`${name} must contain at least 32 bytes`);
  }
  if (env.JWT_SECRET === env.OTP_SECRET) throw new Error('JWT_SECRET and OTP_SECRET must differ');
  const origins = (env.CORS_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
  for (const origin of origins) {
    const url = new URL(origin);
    if (url.origin !== origin || !['http:', 'https:'].includes(url.protocol)) throw new Error('Invalid CORS origin');
    if (env.NODE_ENV === 'production' && url.protocol !== 'https:') throw new Error('Production origins must use HTTPS');
  }
  return { mongoUri: env.MONGO_URI, jwtSecret: env.JWT_SECRET, otpSecret: env.OTP_SECRET,
    resendApi: env.RESEND_API, mailFrom: env.MAIL_FROM, origins, port: Number(env.PORT || 5000) };
}
module.exports = { loadConfig };
