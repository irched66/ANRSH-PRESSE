# ANRSH MAGAZINE API — staged implementation

This Worker is separate from ANRSH DIGITAL. It is not deployed by this repository change.

## Required setup (do not run until reviewed)
1. Confirm the D1 database is the magazine database `anrsh_presse`.
2. Review and apply `migrations/0001_editorial_auth.sql` to that database only.
3. Replace the placeholder `database_id` in `wrangler.toml` with the ID shown for `anrsh_presse`.
4. Set `EDITORIAL_BOOTSTRAP_SECRET` using Cloudflare Secrets. Never put the value in Git or send it in chat.
5. Deploy as a new Worker named `anrsh-magazine-api`; do not reuse ANRSH DIGITAL workers.
6. Set the production origin exactly in `ALLOWED_ORIGIN`; if using a different Pages custom domain, update it before deployment.
7. Bootstrap once at `POST /api/admin/bootstrap` with header `x-bootstrap-key` and JSON `{"display_name":"..."}`. Save the returned one-time API key offline, then rotate/remove the bootstrap secret.
8. Admin creates individual editor/contributor keys. Each user logs in at `POST /api/auth/login`; keys are displayed once and stored only as SHA-256 hashes.

## Endpoints
- Public: `GET /api/health`, `GET /api/public/articles`, `GET /api/public/breaking`.
- Login/logout: `POST /api/auth/login`, `POST /api/auth/logout`.
- Admin: `POST /api/admin/accounts`, `POST /api/admin/accounts/revoke`.
- Editorial: `POST /api/editorial/articles`; `POST /api/editorial/{articles|breaking}/{id}/{approve|publish|reject}`.

Contributors can submit drafts only. Editors can approve/reject. Only admins can publish and manage accounts. All decisions are enforced in the Worker.

## Important limitations before production
- This is staged code, not a security certification. It requires a staging deployment, migration review, integration tests, rate-limit/load tests, and independent security review.
- The existing `editorial_logs` table stores a plain display name. This Worker derives that name from the authenticated account, not the request body.
- The login API key is a bootstrap credential; the session cookie is HttpOnly/Secure/SameSite=Strict. Keep the frontend and API on the same site if possible.
- Configure Cloudflare WAF/rate limiting and observability. The D1 rate-limit table is a basic per-IP application guard, not a substitute for edge protection.
- No Meta/Facebook API integration or automatic Facebook publishing is included.
