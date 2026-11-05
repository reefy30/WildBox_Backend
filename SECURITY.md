# Security audit and release gates

Audit date: 2026-11-05. Baseline: `5496018830fef43f747ce804e0ed66fd071d2add` in the public `reefy30/WildBox_Backend` repository.

## Exposed credentials: remediation incomplete

The tracked `.env` contained a credential-bearing MongoDB Atlas connection URI, a populated JWT signing secret, and a populated Resend API key. Treat these as compromised even if the app was unused. No credential validity test was performed. Empty Hotmail and Google settings did not contain secrets.

Removing `.env` in this candidate does not erase Git history, forks, clones, caches, or the currently public default branch. No live secret has been rotated or revoked. No repository history, visibility, production settings, or deployment was changed.

### Owner-approved remediation sequence

1. Identify the exact Atlas organization/project/cluster and database user from the private credential record. Inventory other consumers of that user and inspect available access/audit logs. Through the correct Atlas admin account, rotate its password or revoke that specific database user if no legitimate use remains. Confirm exact target and impact before making security changes. Do not delete the cluster or data. For future reuse, approve a new least-privilege app-specific database user and restricted network access; store credentials only in the deployment secret manager.
2. Identify the exposed Resend key in its owning account/team using owner records and available metadata. The connected account inspected during audit did not establish a match to the legacy key. Do not revoke unrelated current keys by name guessing. Once identified, revoke the compromised key with explicit action-time approval. Review sending activity and billing. Creating a replacement sending-only/domain-restricted key and installing it in a secret manager requires explicit approval; other apps using the old key will stop sending when it is revoked.
3. Replace the app JWT signing secret anywhere it was used, after checking shared consumers. Invalidate old sessions by rejecting the old key everywhere. New app/OTP secrets must be independently random, not copied from the public file. No replacement keys are generated in this patch.
4. Confirm the old credential can no longer authorize access through provider-side evidence or an owner-approved verification. Record the remediation without recording secret values.
5. Only after revocation, decide whether history cleanup and hosting-cache cleanup are needed. Those are separate approved operations and cannot guarantee all public copies disappear.

## Critical code findings addressed locally

- Email-only `/sign-in` issued valid sessions without any proof; it now sends an email challenge.
- Claimed email in combined Google/Apple route created sessions without a provider token; the route is disabled until proper provider verification exists.
- OTPs used Math.random, plaintext storage, no guess bounds, and non-atomic consumption. The candidate uses cryptographic randomness, HMAC, expiry queries, bounded attempts, and atomic consumption.
- Added shared database rate limits, input validation against operator/object injection, conservative request size/CORS, generic errors/no user or provider log dumps, and fail-closed startup/config validation.

## Deployment observations and required QA

GitHub public deployment metadata returned no deployments and Actions listed zero workflows. External hosts were not ruled out; no production endpoint or database was contacted. Any existing host must be independently identified before declaring the old backend disabled or secure.

Before any merge/deploy:
- Complete secret remediation above and approve publication separately.
- Use a new isolated database or inspect/migrate existing data. Existing verification codes must be invalidated, duplicate verification rows removed, and normalized user-email collisions resolved before creating the unique indexes. Do not run automatic destructive migrations against a live database.
- Run real MongoDB tests for unique indexes, parallel issuance/consumption, rate-counter concurrency, restart behavior, and database outages. Offline fakes do not establish these properties.
- Configure a verified sender and perform an authorized staging delivery test with new credentials.
- Confirm client OTP flow compatibility; provider login is intentionally unavailable.
- Review deployment TLS, secret storage, ingress/client IP handling, database privilege/network policies, edge abuse control, dependency audit, and data retention.

This is an authentication foundation only, not a complete WildBox game backend or a claim of production security certification.

## Verification results for this candidate

- `npm test`: 14 tests passed, including a mocked-network test of the installed Resend SDK.
- `node --check server.js`, `node --check app.js`, and `git diff --check`: passed.
- Dependency refresh removed unused bcrypt, Nodemailer, and Google auth packages, updated compatible security fixes, and upgraded Resend to 6.37.0. Final npm audit reported zero known vulnerabilities. Audit is point-in-time, not a guarantee of no vulnerabilities.
- No local MongoDB server or Docker executable was available; real-database integration tests were not run.
- No live provider email was sent, no exposed credential was exercised, and no new credential was created.
