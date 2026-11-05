# WildBox authentication backend

Local hardening candidate. Not deployed, and not safe to deploy until the incident and release gates in SECURITY.md are completed.

## Run locally

Use Node.js 22 or newer. Run `npm ci`, copy `.env.example` to a private `.env`, and configure a disposable development database plus independently generated JWT/OTP secrets of at least 32 random bytes each. Do not use the old committed credentials. Set an authorized Resend key and verified `MAIL_FROM`. `npm start` connects to MongoDB and initializes required indexes before serving. `npm test` runs offline regression tests without database credentials or outbound email.

## API

- `POST /api/auth/send-code`, `/sign-up`, and `/sign-in`: JSON `{ "email": "user@example.com" }`. Sends a two-minute email challenge, never a token.
- `POST /api/auth/verify-code`: JSON `{ "email": "user@example.com", "code": "123456" }`. After proof of inbox possession, atomically consumes the challenge and creates/loads the user, returning `{ token, user: { id, email } }`.
- `POST /api/auth/google-apple-signin`: disabled with HTTP 501. Never exchange a caller-supplied email for a session. Add provider-specific ID-token verification, configured audiences, issuer/signature/expiry/nonce checks, verified-email policy, and stable provider-subject identity before enabling it.
- `GET /health`: basic process health.

The sign-in response deliberately changes from the unsafe previous email-only token response. Clients must complete the OTP flow. JWTs are HS256 with a one-hour lifetime, issuer `wildbox-api`, audience `wildbox-client`, and user ID subject. Every future protected route must verify all of these before authorization. This repository does not yet implement protected gameplay/business endpoints.

## Abuse controls

MongoDB-backed fixed-window limits are shared across instances: 30 authentication requests/IP/minute, three sends/email/15 minutes, 15 verification submissions/email/15 minutes, and five guesses per challenge. Counters expire using MongoDB TTL indexes; expiration is enforced by bucket selection, not TTL cleanup timing. Email identity is normalized and validated as a string. Codes use cryptographic randomness and keyed HMAC storage. Expiry and atomic one-time consumption are enforced in queries.

Proxy trust is intentionally off. Before deployment, configure only the exact trusted ingress topology and test client-IP behavior; otherwise shared ingress addresses may receive shared limits. Add edge-level volumetric protection. CORS permits only configured browser origins, but is not authentication or an abuse barrier for non-browser clients.

## Test scope

Offline tests use deterministic fake data stores and fake email delivery plus a real local HTTP server. They cover email-only/provider auth bypass, invalid inputs, OTP expiry/guess exhaustion/replay/concurrency, mail failure, configuration, limits, request size, and CORS. These tests do not prove real MongoDB concurrency/index behavior, deliverability, or deployed network security. A fresh disposable MongoDB integration run and authorized staging email test are release gates.
