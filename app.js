const express = require('express');
const cors = require('cors');
const { createAuthRoutes } = require('./routes/authRoutes');
function createApp({ controller, allow, config }) {
  const app = express();
  app.disable('x-powered-by');
  // Do not trust client-supplied forwarding headers. Configure only a verified proxy topology before deployment.
  app.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); res.set('X-Content-Type-Options', 'nosniff'); next(); });
  app.use(cors({ origin: config.origins, methods: ['POST'], allowedHeaders: ['Content-Type', 'Authorization'] }));
  app.use(express.json({ limit: '8kb', strict: true }));
  app.get('/health', (_req, res) => res.json({ status: 'ok' }));
  app.use('/api/auth', createAuthRoutes(controller, allow));
  app.use((err, _req, res, _next) => {
    const status = err.type === 'entity.too.large' ? 413 : err.type === 'entity.parse.failed' ? 400 : 503;
    res.status(status).json({ message: status === 503 ? 'Service temporarily unavailable' : 'Invalid request body' });
  });
  return app;
}
module.exports = { createApp };
