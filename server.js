require('dotenv').config();
const mongoose = require('mongoose');
const { Resend } = require('resend');
const { loadConfig } = require('./lib/config');
const { createLimiter } = require('./lib/rateLimit');
const { createAuthController } = require('./controllers/authController');
const { createApp } = require('./app');
const User = require('./models/user');
const VerificationCode = require('./models/verificationCode');
const RateLimit = require('./models/rateLimit');
async function start() {
  const config = loadConfig();
  await mongoose.connect(config.mongoUri, { serverSelectionTimeoutMS: 10000 });
  await Promise.all([User.init(), VerificationCode.init(), RateLimit.init()]);
  const allow = createLimiter(RateLimit, config.otpSecret);
  const controller = createAuthController({ User, VerificationCode, mailer: new Resend(config.resendApi), config, allow });
  const server = createApp({ controller, allow, config }).listen(config.port, '0.0.0.0');
  const stop = () => server.close(() => mongoose.disconnect().finally(() => process.exit(0)));
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
}
if (require.main === module) start().catch(() => { console.error('Startup failed; check configuration and database connectivity'); process.exitCode = 1; });
module.exports = { start };
