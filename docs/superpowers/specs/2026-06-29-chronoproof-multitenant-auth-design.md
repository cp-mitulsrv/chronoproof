# ChronoProof — Multi-Tenant Identity Provider (Design Spec)

- **Date:** 2026-06-29
- **Status:** Approved for planning
- **Scope of this effort:** Build **ChronoProof** (the identity/auth provider) and the **shared verification pattern** that the five Chrono resource services plug into. The five services' business logic is out of scope; a single sample resource service is built only to prove the contract.

---

## 1. Background & goal

ChronoProof is the parent platform for five analysis products — **ChronoScout, ChronoTruth, ChronoPulse, ChronoSee, ChronoCurve**. The customers are **VC firms** that analyze healthcare companies (Pfizer, Moderna, …). Healthcare companies are *shared reference data*, **not** tenants. Each VC firm's work (reports, notes, watchlists, alerts) must be strictly isolated from every other firm's.

Today each service would handle its own auth, causing duplicate users, duplicate passwords, and no shared workspace. The goal is to make **ChronoProof the single source of truth for identity**: it handles registration, login, sessions, organizations, workspaces, members, and invitations, and issues JWTs that the five services *trust* and use to isolate data. This is the standard enterprise-SaaS identity-provider + resource-server pattern (single sign-on, centralized security, strict tenant isolation).

---

## 2. Locked decisions

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | Scope | ChronoProof identity provider + shared verifier pattern | Foundation everything else depends on |
| 2 | Stack | **Bun + TypeScript + Azure SQL**; **Hono** web framework; `mssql` (tedious) or **Kysely** query builder | Bun's native SQL driver does not support MSSQL, so use the `mssql`/Kysely path |
| 3 | Tenant model | **Organization = Tenant**, owns **many Workspaces**; isolate on `tenant_id (= org_id)`, sub-scope on `workspace_id` | Standard SaaS (Slack/Notion); fits a VC firm with internal teams. Resolves the conversation's central ambiguity: there is **no separate tenant table — the organization *is* the tenant** |
| 4 | User reach | **One org per user**, **many workspaces** within it; JWT carries an **active** workspace | Matches a VC firm with internal teams; avoids cross-company account complexity |
| 5 | Token trust | **RS256 + JWKS** | Services verify with the public key only; never hold a token-minting secret |
| 6 | Sessions | **Stateless access (~15 min, not stored)** + **stored hashed refresh** (rotating, reuse-detected, revocable rows) | Fast verification, real "log out this device", revocation of access propagates within the access-token TTL |
| 7 | Onboarding | **Self-serve register + email invites**; **Owner/Member** workspace roles, **owner/admin/member** org roles | Matches the user-journey described; supports team growth |

### Default resolutions (correct during spec review if wrong)
- **Registration vs. invite (single responsibility each):** `POST /auth/register` is **new-signup only** — it creates user + organization + first workspace, and the caller becomes org owner & workspace owner. **All invite acceptance goes through `POST /invitations/accept`**, which creates the user if they are new and joins them to the existing org/workspace. No new org is ever created via the invite path.
- **`org_role` retained:** governs who can create workspaces, invite, and manage the org.
- **Refresh token delivery:** default **httpOnly, Secure, SameSite** cookie for browser clients; return in the JSON body for non-browser/service clients (configurable per request).

---

## 3. Architecture overview

```
                ChronoProof (Hono on Bun, Azure SQL)
                ├─ register / login / refresh / switch-workspace / logout
                ├─ orgs / workspaces / members / invitations
                ├─ sessions  (the "login_logon" table)
                └─ GET /.well-known/jwks.json          ← public key (RS256)
                              │  issues short-lived RS256 access token
        ┌─────────────┬───────┴───────┬─────────────┬─────────────┐
   ChronoScout    ChronoTruth    ChronoPulse    ChronoSee    ChronoCurve
        └── each imports @chronoproof/auth → verify JWT via cached JWKS
            → AuthContext { userId, tenantId, workspaceId, role }
            → every query:  WHERE tenant_id = ctx.tenantId [AND workspace_id = ctx.workspaceId]
```

**Units & boundaries**
- **`apps/chronoproof`** — the identity provider HTTP service. Owns all auth/org/workspace/session data.
- **`packages/auth` (`@chronoproof/auth`)** — pure verification library + Hono middleware + a `CONTRACT.md`. Depends only on the JWKS endpoint and the documented claim shape. No DB access.
- **`packages/db`** — schema, migrations, and typed query layer for ChronoProof.
- **Sample resource service** — minimal app that imports `@chronoproof/auth` to prove the contract end-to-end.

Each unit can be understood and tested independently. The five real services depend only on `@chronoproof/auth` + the contract — not on ChronoProof's internals.

---

## 4. Data model (Azure SQL / T-SQL)

IDs are `UNIQUEIDENTIFIER` with `DEFAULT NEWSEQUENTIALID()` (index-friendly). `tenant_id` is the organization id; there is no separate tenant table. Email uniqueness uses a normalized lowercase column. Every FK and every isolation column (`org_id`, `workspace_id`) is indexed.

**organizations** *(= tenant)*
| column | type | notes |
|---|---|---|
| id | UNIQUEIDENTIFIER PK | tenant_id |
| name | NVARCHAR | display name (e.g. "Sequoia Capital") |
| slug | NVARCHAR UNIQUE | URL-safe handle |
| status | NVARCHAR | active / suspended |
| created_at | DATETIME2 | |

**users** *(global login identity; one org per user)*
| column | type | notes |
|---|---|---|
| id | UNIQUEIDENTIFIER PK | |
| org_id | UNIQUEIDENTIFIER FK→organizations | the user's single org |
| email | NVARCHAR | original casing |
| email_normalized | NVARCHAR UNIQUE | lowercased, for uniqueness/lookup |
| password_hash | NVARCHAR | argon2id via `Bun.password` |
| name | NVARCHAR | |
| org_role | NVARCHAR | owner / admin / member |
| status | NVARCHAR | active / invited / disabled |
| created_at | DATETIME2 | |

**workspaces** *(many per org)*
| column | type | notes |
|---|---|---|
| id | UNIQUEIDENTIFIER PK | workspace_id |
| org_id | UNIQUEIDENTIFIER FK→organizations | tenant_id |
| name | NVARCHAR | e.g. "Healthcare" |
| slug | NVARCHAR | unique within org |
| created_at | DATETIME2 | |

**workspace_members** *(m:n user↔workspace within one org)*
| column | type | notes |
|---|---|---|
| id | UNIQUEIDENTIFIER PK | |
| workspace_id | UNIQUEIDENTIFIER FK | |
| user_id | UNIQUEIDENTIFIER FK | |
| role | NVARCHAR | owner / member |
| created_at | DATETIME2 | |
| | UNIQUE(workspace_id, user_id) | |

**invitations** *(single-use, hashed, expiring)*
| column | type | notes |
|---|---|---|
| id | UNIQUEIDENTIFIER PK | |
| org_id | UNIQUEIDENTIFIER FK | |
| workspace_id | UNIQUEIDENTIFIER FK | |
| email | NVARCHAR | invitee |
| role | NVARCHAR | workspace role to grant |
| token_hash | NVARCHAR | hash of the emailed token |
| status | NVARCHAR | pending / accepted / expired / revoked |
| invited_by | UNIQUEIDENTIFIER FK→users | |
| expires_at | DATETIME2 | |
| created_at | DATETIME2 | |

**sessions** *(the boss's `login_logon`; one row per device login)*
| column | type | notes |
|---|---|---|
| id | UNIQUEIDENTIFIER PK | session id (`sid` claim) |
| user_id | UNIQUEIDENTIFIER FK | |
| org_id | UNIQUEIDENTIFIER | denormalized for fast filtering |
| workspace_id | UNIQUEIDENTIFIER | active workspace for this session |
| refresh_token_hash | NVARCHAR | only the hash is stored |
| device | NVARCHAR | label |
| ip | NVARCHAR | |
| user_agent | NVARCHAR | |
| expires_at | DATETIME2 | refresh expiry (~30 days) |
| last_used_at | DATETIME2 | |
| created_at | DATETIME2 | |
| revoked | BIT | logout / admin revoke |

**signing_keys** *(key rotation)*
| column | type | notes |
|---|---|---|
| kid | NVARCHAR PK | key id, appears in JWT header |
| public_pem | NVARCHAR | served via JWKS |
| private_pem_encrypted | NVARCHAR | dev only; in prod the private key lives in **Azure Key Vault** and this row holds metadata + public key |
| is_active | BIT | the current signing key |
| created_at | DATETIME2 | |

---

## 5. The contract: JWT claims + JWKS

**Access token** — RS256, ~15 min, **never stored**, verified statelessly by services:
```jsonc
{
  "iss": "https://auth.chronoproof.com",
  "aud": "chrono-services",
  "sub": "<user_id>",
  "tid": "<org_id = tenant_id>",
  "wsid": "<active_workspace_id>",
  "role": "owner|member",          // role in the ACTIVE workspace
  "orole": "owner|admin|member",   // org-level role
  "sid": "<session_id>",
  "typ": "access",
  "jti": "<uuid>",
  "iat": 0,
  "exp": 0
}
```

**Refresh token** — opaque, high-entropy random string (NOT a JWT). Returned to the client; only its hash is stored in `sessions`. **Rotated on every refresh** with **reuse detection**: presenting a previously-rotated/revoked refresh token revokes the entire session.

**JWKS** — `GET /.well-known/jwks.json` → `{ "keys": [ { "kty":"RSA", "kid":"...", "use":"sig", "alg":"RS256", "n":"...", "e":"..." } ] }`. Services cache it and refetch when they see an unknown `kid` (supports rotation). This endpoint + the claim shape is the **single documented integration point**; any service in any language verifies identically.

---

## 6. API surface (ChronoProof)

**Auth & session**
- `POST /auth/register` — **new signup only**: creates user + org + first workspace (caller = org owner & workspace owner). Invite acceptance is handled exclusively by `POST /invitations/accept`.
- `POST /auth/login` — email + password → if the user is in exactly one workspace, auto-select it; otherwise return the workspace list to choose from → issue access + refresh, create a `sessions` row.
- `POST /auth/token/refresh` — validate + rotate refresh, issue a new access token.
- `POST /auth/switch-workspace` — re-issue an access token bound to a different workspace the user belongs to (updates the session's active workspace).
- `POST /auth/logout` — revoke the current session. `POST /auth/logout-all` — revoke all the user's sessions.
- `GET /auth/sessions` / `DELETE /auth/sessions/:id` — list/revoke devices.
- `GET /.well-known/jwks.json` — public keys.

**Org / workspace / members**
- `POST /orgs` — create org (caller becomes org owner). *(Primarily exercised via register; exposed for completeness.)*
- `POST /workspaces` — create a workspace in the caller's org (org owner/admin).
- `GET /workspaces` — list workspaces the caller can access.
- `POST /workspaces/:id/invitations` — invite an email with a role (org owner/admin or workspace owner).
- `POST /invitations/accept` — accept an invite token (joins; may create the user).
- `GET /workspaces/:id/members`, `PATCH /workspaces/:id/members/:userId` (role change), `DELETE /workspaces/:id/members/:userId`.

All non-auth endpoints require a valid access token and enforce org/workspace role guards.

---

## 7. Key flows

1. **Signup (new firm):** `register` → create org (caller = org owner) → create first workspace → caller added as workspace owner → issue tokens + session.
2. **Login:** verify password (`Bun.password`, argon2id) → choose active workspace (auto if single) → create session → return access + refresh.
3. **Service request:** client sends `Authorization: Bearer <access>` → `@chronoproof/auth` verifies signature/`iss`/`aud`/`exp`/`typ` via cached JWKS → attaches `AuthContext` → service runs `... WHERE tenant_id = ctx.tenantId [AND workspace_id = ctx.workspaceId]`.
4. **Refresh:** present refresh → match hash against a non-revoked, unexpired session → rotate token + update session → return new tokens. Reuse of an old token ⇒ revoke session family.
5. **Switch workspace:** caller requests a workspace they're a member of → new access token with updated `wsid`/`role`.
6. **Invite:** owner/admin invites email → invitee opens link with token → `invitations/accept` → user + `workspace_member` created, invite marked accepted.
7. **Logout / revoke:** set `revoked = 1` on the session row; access dies within its TTL, refresh dies immediately.

---

## 8. `@chronoproof/auth` shared package

- `chronoAuth(opts)` — Hono middleware: extract Bearer token → verify via cached JWKS (using `jose`) → validate `iss`/`aud`/`exp`/`typ` → set `c.get('auth'): AuthContext`. Returns `401` on any failure.
- `requireOrgRole(role)` / `requireWorkspaceRole(role)` — authorization guards.
- `AuthContext` type (`{ userId, tenantId, workspaceId, role, orgRole, sessionId }`) exported for app code.
- `CONTRACT.md` — documents the JWKS URL, claim shape, and verification steps so a non-TypeScript service can replicate verification exactly.
- No database access; depends only on the public JWKS + claims.

---

## 9. Security

- **Passwords:** `Bun.password` with **argon2id**.
- **Refresh tokens:** rotation + reuse detection; stored only as a hash; bound to a session row that can be revoked.
- **Keys:** dev = generated PEM files / `signing_keys` row; **prod = Azure Key Vault**, rotation via `kid` (old public keys remain in JWKS until their tokens expire).
- **Tenant isolation:** enforced in the query layer — every business query MUST filter by `tenant_id` (and `workspace_id` where workspace-scoped). Backed by a code-review/lint rule. **Optional defense-in-depth:** Azure SQL **Row-Level Security** policy keyed on a `SESSION_CONTEXT('tenant_id')`.
- **Hardening:** rate-limit `login`/`refresh`; email-enumeration-safe responses; single-use, expiring, hashed invitations; HTTPS-only; refresh as httpOnly+Secure+SameSite cookie by default; strict CORS allow-list for the five service origins.

---

## 10. Project structure (Bun workspaces monorepo)

```
chronoproof/
  apps/
    chronoproof/             # identity provider (Hono)
    sample-service/          # minimal resource service proving the contract
  packages/
    auth/                    # @chronoproof/auth (verifier + middleware + CONTRACT.md)
    db/                      # schema, migrations, typed queries
  docs/superpowers/specs/    # this spec
```

---

## 11. Testing strategy

- **Unit:** access-token sign/verify, password hashing, refresh rotation + reuse detection, role guards, JWKS serialization.
- **Integration:** all endpoints against a **real, reachable Azure SQL / SQL Server configured via env (no Docker)**; integration tests skip cleanly when no DB is configured so pure-logic tests always run; **tenant-isolation tests** proving a user in org A cannot read org B data via any endpoint; invite + accept; switch-workspace re-issues correct claims.
- **Contract test:** the sample resource service uses `@chronoproof/auth` to **accept** a genuinely issued token and **reject** tampered, expired, wrong-`aud`, and unknown-`kid` tokens.

---

## 12. Out of scope (YAGNI)

- The five services' business logic (only a sample verifier service is built).
- Billing/subscriptions, multi-org-per-user, external SSO (Google/SAML), and an API gateway — all deferred (the JWKS contract makes adding a gateway later non-breaking).
- **"Email-prefix = workspace name"** (floated by the boss): **dropped** — it conflicts with the Org→Workspace model and breaks for personal emails like `dhruv@…`. Email is a plain login identifier; workspaces are created/selected explicitly.

---

## 13. Success criteria

1. A new VC firm can self-serve register, creating an org + first workspace, with the registrant as org owner.
2. The owner can invite a teammate by email; the teammate accepts and joins the workspace.
3. A user with multiple workspaces can log in, pick/switch the active workspace, and receive a correctly-scoped access token.
4. The sample resource service verifies a real token via JWKS with no shared secret, reads `tenant_id`, and returns only that tenant's data; tampered/expired/wrong-tenant tokens are rejected.
5. Logging out a device revokes that session; other devices keep working; reused refresh tokens revoke the session family.
6. Automated tests prove cross-tenant data access is impossible through the public API.
