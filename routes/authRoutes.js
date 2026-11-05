const express = require('express');
function createAuthRoutes(controller, allow) {
  const router = express.Router();
  const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
  router.use(wrap(async (req, res, next) => {
    if (!await allow('auth-ip', req.ip, 30, 60000)) return res.status(429).json({ message: 'Please try again later' });
    next();
  }));
  router.post('/send-code', wrap(controller.sendCode));
  router.post('/sign-up', wrap(controller.sendCode));
  router.post('/verify-code', wrap(controller.verifyCode));
  router.post('/sign-in', wrap(controller.signIn));
  router.post('/google-apple-signin', wrap(controller.googleAppleSignIn));
  return router;
}
module.exports = { createAuthRoutes };
