# 0001 — Self-hosted server authentication boundaries

## Scope and decisions

Protect first-admin setup, revoke compromised sessions, and enforce the existing
single-administrator trust model. Memory identifiers describe application data;
they are not authenticated dashboard identities or tenant authorization rules.

The deployment branch already provides `BOOTSTRAP_SECRET`, password-confirmed
API-key creation, refresh-session families, browser Web Locks, and GPT-6 support.
Preserve these interfaces and protections. Add migration `008` after the existing
refresh-session migration `007`; do not reuse a deployed revision number.

## Acceptance criteria

- First registration requires a host-provisioned `BOOTSTRAP_SECRET` of at least
  32 characters through `X-Bootstrap-Secret`, including with `ADMIN_API_KEY`.
  Missing or invalid proof fails closed with 401. Existing dashboard and seed
  flows retain this deployment interface.
- Reference Compose ports bind to loopback by default.
- Access and refresh tokens carry the current account authentication version,
  alongside the existing credential version and session-family checks. Reject
  missing, malformed, and stale versions. Pre-upgrade users sign in again.
- Explicit logout revokes all browser sessions, including after another caller
  rotates the refresh token. Older versions cannot revoke a subsequent login.
  Refresh replay continues to revoke only its affected session family.
- Password change and host password reset revoke browser sessions and account
  API keys in one transaction. Login, refresh, key issuance, and recovery use the
  same owner lock. Recheck detached authentication and candidate key revocation
  after acquiring the lock. Failed token issuance must not consume its predecessor.
- API-key creation continues to require a bearer session and password confirmation.
  API keys cannot mint replacement keys. Browser refresh and logout continue to
  use the existing shared Web Lock; revocation failures remain retryable.
- Shared memory CRUD, search, history, entity listing, configuration, and LLM
  instruction generation require administrator privileges. Non-admin JWTs and
  API keys receive 403 before memory/provider access. Preserve legacy admin and
  explicit local authentication bypass behavior.
- Document migration, session revocation, API-key recovery, and the single-admin
  boundary. Untrusted end users must use an application backend enforcing ownership.

## Verification evidence — 2026-10-29

- 28 HTTP security regressions pass against real PostgreSQL 17 using isolated
  temporary schemas and synthetic provider data. These cover malformed/legacy
  versions, refresh replay, issuance versus password change, rollback on storage
  failure, recovery, and a deterministic key scan blocked by password reset.
- The deployment branch's existing authentication and GPT-6 tests pass as well:
  49 tests pass across the three suites. All 68 server parameter tests pass.
- Seven Bun session/dashboard tests pass, including the existing deployment
  session-lock tests. TypeScript checking and the production dashboard build pass.
- Alembic `007 -> 008 -> 007 -> 008` passes on disposable PostgreSQL. A seeded
  account retains authentication version 0; old refresh tokens and families are
  invalidated. The migration graph has one head, `008`.
- Ruff, isort pre-commit hooks, affected frontend formatting, shell syntax,
  documentation index validation, and `git diff --check` pass.
- The older upstream `tests/test_server_auth.py` has a pre-existing failure:
  `test_supplying_key_still_works_when_auth_disabled` expects 200 for an invalid
  supplied key, while upstream returns 401. This was reproduced on untouched
  commit `26cdefb46600c0fa5953c4b5ee5003c125539fc4`; the older suite was not rewritten.

## Operational limits

Run migration `008` before starting the updated API. Account-owned API keys are
revoked by password change/reset; the independent legacy `ADMIN_API_KEY` must be
rotated separately. Already authenticated in-flight work may finish. Administrator
credentials remain instance-wide; this change does not implement tenant ownership.
Local verification does not establish live deployment health or provider behavior.
