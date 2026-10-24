# Gerrit 639742 — AI Code Review Triage

Change: `Secure_TUT/MDNA-Server` → `zDNAMicroservice/ssoManager/**` (imports the entire
SSO microservice into MDNA-Server as new files). Reviewer: "Adithi Kulkarni" (AI Code
Review), Jul 20. Reviewed 2026-07-21 against the Mac copy `zdna-sso-latest` (same source).

**~87 raw comments across 30 files → ~22 distinct finding-classes.** The AI heavily
duplicates (SAML god-function ×4, filename typo ×3, `JSON.stringify` logging ×3, TLS
`rejectUnauthorized` across 3 files). Most Gerrit threads are already "Resolved"; this
doc records the *reviewer verdict* for each so they were resolved for the right reason.

Verdict legend: **ACCEPT** (genuine, fix) · **CHEAP** (low/style, do if trivial) ·
**DEFER** (valid but out of scope / risky here) · **PUSHBACK** (suggested fix is wrong)
· **HANDLED** (already addressed elsewhere in the CL).

---

## Tier 1 — Genuine (ACCEPT)

| # | Finding | Site(s) | Sev | Verified | Fix |
|---|---------|---------|-----|----------|-----|
| 1 | Graph **groups**-overage awaited with no try/catch → Graph outage fails whole OIDC login | `services/oidc/oidcTokenExchange.service.js` `resolveUserGroups` | HIGH | ✅ real | try/catch → `[]`, let `default` JIT mapping apply (fallback, not reject) |
| 2 | `JSON.stringify` into log message (bypasses `maskPii`; PII `relayState`) | `controllers/samlCallback.Controller.js` ×3, `services/Saml/samlCallback.service.js` L243 ×3 | CRIT | ✅ | structured object + `action` code; drop `relayState` |
| 3 | Input type + max-length validation before base64/PKCS12 decode | `domianCheck.Controller`, `testConnection.controller`, `samlCallback.Controller` | CRIT/HIGH | ✅ | `typeof`+`MAX_*` caps |
| 4 | TLS `rejectUnauthorized:false` when `DB_SSL=true` | `config/db.js:45`, `scripts/testDbConnection.js` | CRIT | ✅ | `DB_SSL_ALLOW_SELF_SIGNED` gate + optional `DB_SSL_CA` (TCP path only) |
| 5 | Hardcoded fallback DB password `'sso_secret'` | `config/database.js:19` | CRIT | ✅ | remove `|| 'sso_secret'` / `|| 'sso_user'` |
| 6 | Insecure `http://localhost` defaults, no prod guard | `config/constants.js:51,54` | CRIT | ✅ | `assertSecureUrl` throws in prod |
| 7 | `trimStr`/`firstDomain` duplicated → shared util | domianCheck / testConnection / saveSsoConfig controllers | MED | ✅ | `requestNormalize.util` (like 632518 `isCertAuth`) |
| 8 | `createHttpError(msg,status,code)` — repeated `new Error()+statusCode+code` (8× file, 20+ repo) | samlCallback.service, domainCheck.service, samlValidator.util, userResolution.service | MED | ✅ | shared helper (wide touch, low urgency) |
| 9 | Missing tests (SAML pipeline replay/TTL/error codes; rate-limiter 429) | `services/Saml/samlCallback.service.js`, `middlewares/rateLimiter.js` | CRIT/MED | ✅ | add Jest files (AI supplied them) |

## Tier 2 — Low / style (CHEAP)

- Per-request `logger.info` → `debug` (triple-logging) — domianCheck, testConnection.
- Don't `await` the fire-and-forget audit write — testConnection.controller.
- Naming: `a`→`attrs` (samlCallback.service); mixed snake/camel params (audit.service).
- Filename typo/casing: `domianCheck.Controller.js` + `samlCallback.Controller.js` → `*.controller.js`; also update `routers/sso.routes.js` require() paths (one coordinated rename, 4 sites).
- Double XML parse (`samlCallback.service` L120 + L168) — reuse first parse.
- Sync SAML sig verify blocks event loop (`samlCallback.service:184/200`) — `setImmediate` yield only; low-volume path; NOT the emergency the CRIT tag implies.
- `maskPii` doesn't mask `tenantId` (`config/logger.js:32`).
- Missing/unwired OpenAPI docs (`docs/paths/admin.js`, `docs/swagger.js`, sso.routes) — wire `domain.js`/`oidc.js` if cheap.

## Tier 3 — Defer / pushback / already-handled

| Finding | Verdict |
|---------|---------|
| SRP "god-function" split (`processSamlCallback` 190-line ×4, others) | **DEFER** — pure refactor of crypto-critical SAML path; not in an import CL without its test suite |
| DB startup retry (`connectWithRetry`/`verifyConnection`) + audit INSERT retry | **PUSHBACK** — 632518 deferred it (Cloud Run + Sequelize pool lazy-reconnect; audit always logs to stdout, no permanent gap). Small retry on one-shot `migrate.js` OK |
| FK `jit_mappings.role_id → zdna_roles` (add-fk migration) | **HANDLED** — reverted by `20260715…-drop-jit-mappings-role-fk.js` in the same CL to preserve RMS passthrough |
| `setDomainTenantScope.js` deprecated-Firestore + `domains` scalar-vs-array + `tenantId` type-check | **PUSHBACK/DEFER** — self-contradictory: Firestore path is deprecated (PostgreSQL is sole backend), so tuning its query is moot; delete or leave the legacy helper |
| i18n hardcoded English messages | **DEFER** — 632518 marked LOW/acceptable for an internal service |
| domianCheck.Controller comment #7 `[CRITICAL IS WRONG HERE — THIS IS A T…]` | **SKIP** — a human reviewer already annotated the AI as wrong |

---

## Summary
~9 genuine · ~8 low/style · ~5 defer/pushback/already-handled. The one clean **code
bug** worth fixing in this repo is **#1 (oidcTokenExchange groups-Graph try/catch)**.
