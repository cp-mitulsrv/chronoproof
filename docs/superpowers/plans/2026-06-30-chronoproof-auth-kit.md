# `@chronoproof/auth-kit` — Implementation Plan (adapted from the migration plan's Repo 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the shared, publish-ready verification package every ChronoProof product service installs to trust ChronoProof's JWTs — JWT verification (via JWKS), role gates, tenant-context helpers, and the canonical claim/types — on **our** stack (Bun + Hono + Azure SQL), not the migration plan's Node/Express/Postgres baseline.

**Architecture:** A monorepo package `packages/auth-kit` (sibling to `packages/db`). A pure verify core accepts an injectable key resolver so it is unit-testable offline; a remote verifier wires `jose`'s `createRemoteJWKSet` for production. A thin Hono middleware adapter attaches a normalized `AuthContext` to the request. Role gates and a DB-agnostic tenant-context extractor round it out. No database or HTTP server code lives here — it is installed as a dependency, never run as a service.

**Tech Stack:** Bun, TypeScript, `jose` (verification + remote JWKS), Hono (middleware adapter, peer), `bun test`. Build via `tsup` for publishability (CJS+ESM+d.ts). Published name: `@chronoproof/auth-kit`.

## Global Constraints

- Runtime **Bun**; TypeScript; ESM; package is `"type": "module"`.
- **Verification only — never signing.** This package must contain no private key, no `jwt.sign`/`SignJWT`. It only verifies.
- **Claim contract (must match `apps/chronoproof/src/core/access-token.ts` exactly):** RS256; `iss = https://auth.chronoproof.com`; `aud = chrono-services`; `typ` must equal `"access"`; claims `sub, tid, wsid, role ("owner"|"member"), orole ("owner"|"admin"|"member"), sid, jti, iat, exp`. Any drift here is a Critical defect.
- Verifier MUST reject: bad signature, wrong `iss`, wrong `aud`, non-RS256 alg, expired, and `typ !== "access"`.
- Tenant scoping is **DB-agnostic** here (no `pg`, no SQL string-concatenation): export the `TenantContext` type + an extractor from `AuthContext`. Each service applies it in its own Kysely query layer.
- TDD: failing test first. `jose` is used in tests to mint tokens with a locally-generated RSA key — never reach a real network/JWKS in unit tests.
- Publish-ready but **publishing is deferred** (registry/CI is infra done later); the package must `tsup` build cleanly and `npm publish --dry-run` succeed.

---

## File structure created by this plan

```
packages/auth-kit/
  package.json
  tsconfig.json                # extends ../../tsconfig.base.json
  README.md
  CHANGELOG.md
  src/
    types.ts                   # JWTPayload (raw claims) + AuthContext (normalized) + TenantContext
    errors.ts                  # AuthError
    verifier.ts                # makeVerifier(keyResolver,cfg) + createRemoteVerifier(cfg)
    hono.ts                    # requireAuth(verifier) Hono middleware -> c.get('auth')
    roles.ts                   # requireOrgRole / requireWorkspaceRole (Hono guards)
    tenant.ts                  # tenantContextFromAuth(auth)
    index.ts                   # public exports
  test/
    verifier.test.ts
    hono.test.ts
    roles.test.ts
    tenant.test.ts
```

---

### Task 1: Scaffold the package (publish-ready)

**Files:** Create `packages/auth-kit/package.json`, `packages/auth-kit/tsconfig.json`, `packages/auth-kit/README.md`, `packages/auth-kit/CHANGELOG.md`.

**Interfaces:**
- Produces: an installable workspace package `@chronoproof/auth-kit` with a `tsup` build and `bun test` wired. Later tasks add `src/`.

- [ ] **Step 1: Create `packages/auth-kit/package.json`**

```json
{
  "name": "@chronoproof/auth-kit",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/index.cjs",
  "module": "dist/index.js",
  "types": "dist/index.d.ts",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js",
      "require": "./dist/index.cjs"
    }
  },
  "files": ["dist"],
  "scripts": {
    "build": "tsup src/index.ts --format esm,cjs --dts --clean",
    "test": "bun test"
  },
  "dependencies": {
    "jose": "^5.9.0"
  },
  "peerDependencies": {
    "hono": "^4.6.0"
  },
  "devDependencies": {
    "hono": "^4.6.0",
    "tsup": "^8.0.0",
    "typescript": "^5.6.0",
    "bun-types": "latest"
  }
}
```

- [ ] **Step 2: Create `packages/auth-kit/tsconfig.json`**

```json
{
  "extends": "../../tsconfig.base.json",
  "include": ["src/**/*.ts", "test/**/*.ts"]
}
```

- [ ] **Step 3: Create `packages/auth-kit/CHANGELOG.md`**

```markdown
# Changelog

## 0.1.0 — initial
- requireAuth() Hono middleware — RS256 JWT verification via JWKS (jose), checks iss/aud/typ
- requireOrgRole() / requireWorkspaceRole() — role gates
- tenantContextFromAuth() — DB-agnostic tenant scoping context
- JWTPayload / AuthContext / TenantContext types (match apps/chronoproof signer)
```

- [ ] **Step 4: Create `packages/auth-kit/README.md`** — a short usage doc: install, `createRemoteVerifier({ jwksUrl, issuer, audience })`, `app.use(requireAuth(verifier))`, read `c.get('auth')`, then scope every query by `auth.tenantId` (+ `auth.workspaceId`). State explicitly: this package verifies only; ChronoProof is the only signer.

- [ ] **Step 5: Install workspace deps**

Run: `bun install`
Expected: resolves `jose`, `hono`, `tsup` for the new workspace package, no errors.

- [ ] **Step 6: Commit** (only if git is in use this build — the controller decides)

```bash
git add packages/auth-kit/package.json packages/auth-kit/tsconfig.json packages/auth-kit/CHANGELOG.md packages/auth-kit/README.md
git commit -m "feat(auth-kit): scaffold publish-ready shared verifier package"
```

---

### Task 2: Types + errors (the contract)

**Files:** Create `packages/auth-kit/src/types.ts`, `packages/auth-kit/src/errors.ts`. Test: `packages/auth-kit/test` (covered indirectly by Task 3).

**Interfaces:**
- Produces:
  - `JWTPayload` — raw claims: `{ iss; aud; sub; tid; wsid; role: "owner"|"member"; orole: "owner"|"admin"|"member"; sid; typ: "access"; jti; iat: number; exp: number }`.
  - `AuthContext` — normalized: `{ userId; tenantId; workspaceId; role: "owner"|"member"; orgRole: "owner"|"admin"|"member"; sessionId }`.
  - `TenantContext` — `{ tenantId: string; workspaceId: string }`.
  - `class AuthError extends Error { status: number }` (default 401).

- [ ] **Step 1: Create `packages/auth-kit/src/errors.ts`**

```ts
export class AuthError extends Error {
  status: number;
  constructor(message: string, status = 401) {
    super(message);
    this.name = "AuthError";
    this.status = status;
  }
}
```

- [ ] **Step 2: Create `packages/auth-kit/src/types.ts`**

```ts
export interface JWTPayload {
  iss: string;
  aud: string;
  sub: string;
  tid: string;
  wsid: string;
  role: "owner" | "member";
  orole: "owner" | "admin" | "member";
  sid: string;
  typ: "access";
  jti: string;
  iat: number;
  exp: number;
}

export interface AuthContext {
  userId: string;
  tenantId: string;
  workspaceId: string;
  role: "owner" | "member";
  orgRole: "owner" | "admin" | "member";
  sessionId: string;
}

export interface TenantContext {
  tenantId: string;
  workspaceId: string;
}
```

- [ ] **Step 3: Commit** (if git in use)

```bash
git add packages/auth-kit/src/types.ts packages/auth-kit/src/errors.ts
git commit -m "feat(auth-kit): claim/auth-context types matching the signer + AuthError"
```

---

### Task 3: Verify core + remote (JWKS) verifier — TDD

**Files:** Create `packages/auth-kit/src/verifier.ts`. Test: `packages/auth-kit/test/verifier.test.ts`.

**Interfaces:**
- Consumes: `JWTPayload`, `AuthContext`, `AuthError`.
- Produces:
  - `type KeyInput = Parameters<typeof import("jose").jwtVerify>[1]` (a key or a `getKey` resolver — lets tests pass a local public key and prod pass a remote JWKS).
  - `interface VerifierConfig { issuer: string; audience: string }`.
  - `makeVerifier(key: KeyInput, cfg: VerifierConfig): (token: string) => Promise<AuthContext>` — verifies RS256/iss/aud/exp, enforces `typ === "access"`, maps claims → `AuthContext`; throws `AuthError` on any failure.
  - `createRemoteVerifier(cfg: { jwksUrl: string; issuer: string; audience: string }): (token: string) => Promise<AuthContext>` — wraps `createRemoteJWKSet(new URL(jwksUrl))` then `makeVerifier`.

- [ ] **Step 1: Write the failing test** — `packages/auth-kit/test/verifier.test.ts`

```ts
import { test, expect } from "bun:test";
import { generateKeyPair, SignJWT, exportPKCS8, importPKCS8 } from "jose";
import { makeVerifier } from "../src/verifier";

const ISS = "https://auth.chronoproof.com";
const AUD = "chrono-services";

async function setup() {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  // re-import private key from PEM to mimic how the signer loads it (sanity)
  const priv = await importPKCS8(await exportPKCS8(privateKey), "RS256");
  const verify = makeVerifier(publicKey, { issuer: ISS, audience: AUD });
  return { priv, verify, publicKey };
}

function baseClaims() {
  return {
    sub: "user-1", tid: "org-1", wsid: "ws-1",
    role: "owner", orole: "admin", sid: "sess-1", typ: "access",
  };
}

async function sign(priv: any, claims: Record<string, unknown>, opts: { iss?: string; aud?: string; exp?: string } = {}) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(opts.iss ?? ISS)
    .setAudience(opts.aud ?? AUD)
    .setIssuedAt()
    .setJti("jti-1")
    .setExpirationTime(opts.exp ?? "15m")
    .sign(priv);
}

test("valid access token maps to AuthContext", async () => {
  const { priv, verify } = await setup();
  const token = await sign(priv, baseClaims());
  const ctx = await verify(token);
  expect(ctx).toEqual({
    userId: "user-1", tenantId: "org-1", workspaceId: "ws-1",
    role: "owner", orgRole: "admin", sessionId: "sess-1",
  });
});

test("rejects wrong issuer", async () => {
  const { priv, verify } = await setup();
  const token = await sign(priv, baseClaims(), { iss: "https://evil.example" });
  await expect(verify(token)).rejects.toThrow();
});

test("rejects wrong audience", async () => {
  const { priv, verify } = await setup();
  const token = await sign(priv, baseClaims(), { aud: "someone-else" });
  await expect(verify(token)).rejects.toThrow();
});

test("rejects non-access typ (e.g. a refresh token)", async () => {
  const { priv, verify } = await setup();
  const token = await sign(priv, { ...baseClaims(), typ: "refresh" });
  await expect(verify(token)).rejects.toThrow();
});

test("rejects expired token", async () => {
  const { priv, verify } = await setup();
  const token = await sign(priv, baseClaims(), { exp: "-1s" });
  await expect(verify(token)).rejects.toThrow();
});

test("rejects a token signed by a different key", async () => {
  const { verify } = await setup();
  const other = await setup();
  const token = await sign(other.priv, baseClaims());
  await expect(verify(token)).rejects.toThrow();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test packages/auth-kit/test/verifier.test.ts`
Expected: FAIL — cannot resolve `../src/verifier`.

- [ ] **Step 3: Implement `packages/auth-kit/src/verifier.ts`**

```ts
import { jwtVerify, createRemoteJWKSet } from "jose";
import { AuthError } from "./errors";
import type { AuthContext, JWTPayload } from "./types";

type KeyInput = Parameters<typeof jwtVerify>[1];

export interface VerifierConfig {
  issuer: string;
  audience: string;
}

function toAuthContext(p: JWTPayload): AuthContext {
  return {
    userId: p.sub,
    tenantId: p.tid,
    workspaceId: p.wsid,
    role: p.role,
    orgRole: p.orole,
    sessionId: p.sid,
  };
}

export function makeVerifier(key: KeyInput, cfg: VerifierConfig) {
  return async function verifyAccessToken(token: string): Promise<AuthContext> {
    let payload: JWTPayload;
    try {
      const result = await jwtVerify(token, key, {
        issuer: cfg.issuer,
        audience: cfg.audience,
        algorithms: ["RS256"],
      });
      payload = result.payload as unknown as JWTPayload;
    } catch {
      throw new AuthError("Invalid or expired token");
    }
    if (payload.typ !== "access") {
      throw new AuthError("Wrong token type");
    }
    return toAuthContext(payload);
  };
}

export function createRemoteVerifier(cfg: {
  jwksUrl: string;
  issuer: string;
  audience: string;
}) {
  const jwks = createRemoteJWKSet(new URL(cfg.jwksUrl));
  return makeVerifier(jwks, { issuer: cfg.issuer, audience: cfg.audience });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test packages/auth-kit/test/verifier.test.ts`
Expected: PASS (6 pass).

- [ ] **Step 5: Commit** (if git in use)

```bash
git add packages/auth-kit/src/verifier.ts packages/auth-kit/test/verifier.test.ts
git commit -m "feat(auth-kit): RS256/JWKS verify core + remote verifier"
```

---

### Task 4: Hono `requireAuth` middleware — TDD

**Files:** Create `packages/auth-kit/src/hono.ts`. Test: `packages/auth-kit/test/hono.test.ts`.

**Interfaces:**
- Consumes: the verifier from Task 3, `AuthContext`, `AuthError`.
- Produces:
  - `type AuthVariables = { auth: AuthContext }` (Hono `Variables` binding).
  - `requireAuth(verify: (token: string) => Promise<AuthContext>)` — Hono middleware: reads `Authorization: Bearer`, runs `verify`, sets `c.set("auth", ctx)`; on missing/malformed header or verify failure responds `401 { message }`.

- [ ] **Step 1: Write the failing test** — `packages/auth-kit/test/hono.test.ts`

```ts
import { test, expect } from "bun:test";
import { Hono } from "hono";
import { generateKeyPair, SignJWT } from "jose";
import { makeVerifier } from "../src/verifier";
import { requireAuth } from "../src/hono";

const ISS = "https://auth.chronoproof.com";
const AUD = "chrono-services";

async function appWithToken() {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const verify = makeVerifier(publicKey, { issuer: ISS, audience: AUD });
  const app = new Hono();
  app.use("/api/*", requireAuth(verify));
  app.get("/api/me", (c) => c.json(c.get("auth")));
  const token = await new SignJWT({
    sub: "u1", tid: "t1", wsid: "w1", role: "member", orole: "member", sid: "s1", typ: "access",
  })
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(ISS).setAudience(AUD).setIssuedAt().setJti("j1").setExpirationTime("15m")
    .sign(privateKey);
  return { app, token };
}

test("valid bearer token populates auth and passes through", async () => {
  const { app, token } = await appWithToken();
  const res = await app.request("/api/me", { headers: { authorization: `Bearer ${token}` } });
  expect(res.status).toBe(200);
  expect(await res.json()).toMatchObject({ userId: "u1", tenantId: "t1", workspaceId: "w1" });
});

test("missing Authorization header -> 401", async () => {
  const { app } = await appWithToken();
  const res = await app.request("/api/me");
  expect(res.status).toBe(401);
});

test("malformed header (no Bearer) -> 401", async () => {
  const { app, token } = await appWithToken();
  const res = await app.request("/api/me", { headers: { authorization: token } });
  expect(res.status).toBe(401);
});

test("garbage token -> 401", async () => {
  const { app } = await appWithToken();
  const res = await app.request("/api/me", { headers: { authorization: "Bearer not-a-jwt" } });
  expect(res.status).toBe(401);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test packages/auth-kit/test/hono.test.ts`
Expected: FAIL — cannot resolve `../src/hono`.

- [ ] **Step 3: Implement `packages/auth-kit/src/hono.ts`**

```ts
import type { Context, MiddlewareHandler } from "hono";
import { AuthError } from "./errors";
import type { AuthContext } from "./types";

export type AuthVariables = { auth: AuthContext };

export function requireAuth(
  verify: (token: string) => Promise<AuthContext>,
): MiddlewareHandler<{ Variables: AuthVariables }> {
  return async (c: Context<{ Variables: AuthVariables }>, next) => {
    const header = c.req.header("authorization");
    if (!header || !header.startsWith("Bearer ")) {
      return c.json({ message: "Missing or malformed Authorization header" }, 401);
    }
    const token = header.slice(7);
    try {
      const ctx = await verify(token);
      c.set("auth", ctx);
    } catch (err) {
      const status = err instanceof AuthError ? err.status : 401;
      return c.json({ message: "Invalid or expired token" }, status as 401);
    }
    await next();
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test packages/auth-kit/test/hono.test.ts`
Expected: PASS (4 pass).

- [ ] **Step 5: Commit** (if git in use)

```bash
git add packages/auth-kit/src/hono.ts packages/auth-kit/test/hono.test.ts
git commit -m "feat(auth-kit): Hono requireAuth middleware"
```

---

### Task 5: Role gates + tenant context — TDD

**Files:** Create `packages/auth-kit/src/roles.ts`, `packages/auth-kit/src/tenant.ts`. Test: `packages/auth-kit/test/roles.test.ts`, `packages/auth-kit/test/tenant.test.ts`.

**Interfaces:**
- Consumes: `AuthContext`, `AuthVariables`, `TenantContext`.
- Produces:
  - `requireOrgRole(...allowed: Array<"owner"|"admin"|"member">)` — Hono guard; 401 if no `auth`, 403 if `auth.orgRole` not allowed.
  - `requireWorkspaceRole(...allowed: Array<"owner"|"member">)` — Hono guard; 401/403 likewise on `auth.role`.
  - `tenantContextFromAuth(auth: AuthContext): TenantContext`.

- [ ] **Step 1: Write the failing tests**

`packages/auth-kit/test/roles.test.ts`:
```ts
import { test, expect } from "bun:test";
import { Hono } from "hono";
import { requireOrgRole, requireWorkspaceRole } from "../src/roles";
import type { AuthContext, AuthVariables } from "../src/index";

function appWith(auth: AuthContext | null) {
  const app = new Hono<{ Variables: AuthVariables }>();
  app.use("*", async (c, next) => { if (auth) c.set("auth", auth); await next(); });
  app.get("/org", requireOrgRole("owner", "admin"), (c) => c.text("ok"));
  app.get("/ws", requireWorkspaceRole("owner"), (c) => c.text("ok"));
  return app;
}
const owner: AuthContext = { userId: "u", tenantId: "t", workspaceId: "w", role: "owner", orgRole: "admin", sessionId: "s" };

test("org role allowed passes", async () => {
  const res = await appWith(owner).request("/org");
  expect(res.status).toBe(200);
});
test("org role not allowed -> 403", async () => {
  const res = await appWith({ ...owner, orgRole: "member" }).request("/org");
  expect(res.status).toBe(403);
});
test("no auth -> 401", async () => {
  const res = await appWith(null).request("/org");
  expect(res.status).toBe(401);
});
test("workspace role not allowed -> 403", async () => {
  const res = await appWith({ ...owner, role: "member" }).request("/ws");
  expect(res.status).toBe(403);
});
```

`packages/auth-kit/test/tenant.test.ts`:
```ts
import { test, expect } from "bun:test";
import { tenantContextFromAuth } from "../src/tenant";
import type { AuthContext } from "../src/index";

test("extracts tenant + workspace from auth", () => {
  const auth: AuthContext = { userId: "u", tenantId: "t1", workspaceId: "w1", role: "owner", orgRole: "owner", sessionId: "s" };
  expect(tenantContextFromAuth(auth)).toEqual({ tenantId: "t1", workspaceId: "w1" });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `bun test packages/auth-kit/test/roles.test.ts packages/auth-kit/test/tenant.test.ts`
Expected: FAIL — cannot resolve modules.

- [ ] **Step 3: Implement `packages/auth-kit/src/roles.ts`**

```ts
import type { Context, MiddlewareHandler } from "hono";
import type { AuthVariables } from "./hono";

type OrgRole = "owner" | "admin" | "member";
type WsRole = "owner" | "member";

export function requireOrgRole(...allowed: OrgRole[]): MiddlewareHandler<{ Variables: AuthVariables }> {
  return async (c: Context<{ Variables: AuthVariables }>, next) => {
    const auth = c.get("auth");
    if (!auth) return c.json({ message: "Not authenticated" }, 401);
    if (!allowed.includes(auth.orgRole)) return c.json({ message: "Insufficient org role" }, 403);
    await next();
  };
}

export function requireWorkspaceRole(...allowed: WsRole[]): MiddlewareHandler<{ Variables: AuthVariables }> {
  return async (c: Context<{ Variables: AuthVariables }>, next) => {
    const auth = c.get("auth");
    if (!auth) return c.json({ message: "Not authenticated" }, 401);
    if (!allowed.includes(auth.role)) return c.json({ message: "Insufficient workspace role" }, 403);
    await next();
  };
}
```

- [ ] **Step 4: Implement `packages/auth-kit/src/tenant.ts`**

```ts
import type { AuthContext, TenantContext } from "./types";

export function tenantContextFromAuth(auth: AuthContext): TenantContext {
  return { tenantId: auth.tenantId, workspaceId: auth.workspaceId };
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `bun test packages/auth-kit/test/roles.test.ts packages/auth-kit/test/tenant.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit** (if git in use)

```bash
git add packages/auth-kit/src/roles.ts packages/auth-kit/src/tenant.ts packages/auth-kit/test/roles.test.ts packages/auth-kit/test/tenant.test.ts
git commit -m "feat(auth-kit): role gates + tenant-context extractor"
```

---

### Task 6: Public exports + build verification

**Files:** Create `packages/auth-kit/src/index.ts`. Modify root `package.json` `typecheck` script to include auth-kit.

**Interfaces:**
- Produces: `packages/auth-kit/src/index.ts` re-exporting everything; a clean `tsup` build and a passing `npm publish --dry-run`.

- [ ] **Step 1: Create `packages/auth-kit/src/index.ts`**

```ts
export { makeVerifier, createRemoteVerifier, type VerifierConfig } from "./verifier";
export { requireAuth, type AuthVariables } from "./hono";
export { requireOrgRole, requireWorkspaceRole } from "./roles";
export { tenantContextFromAuth } from "./tenant";
export { AuthError } from "./errors";
export type { JWTPayload, AuthContext, TenantContext } from "./types";
```

- [ ] **Step 2: Extend the root `typecheck` script** — in root `package.json`, add the auth-kit project to the `typecheck` chain:

```
"typecheck": "bunx tsc -p apps/chronoproof/tsconfig.json --noEmit && bunx tsc -p packages/db/tsconfig.json --noEmit && bunx tsc -p packages/auth-kit/tsconfig.json --noEmit"
```

- [ ] **Step 3: Run the full package test suite**

Run: `bun test packages/auth-kit`
Expected: all tests pass (verifier 6, hono 4, roles 4, tenant 1).

- [ ] **Step 4: Build + typecheck + dry-run publish**

Run: `cd packages/auth-kit && bun run build && cd ../.. && bun run typecheck && cd packages/auth-kit && npm publish --dry-run`
Expected: `dist/index.js`, `dist/index.cjs`, `dist/index.d.ts` produced; typecheck clean; dry-run lists only `dist/**` + package.json/README/CHANGELOG (no source, no keys).

- [ ] **Step 5: Commit** (if git in use)

```bash
git add packages/auth-kit/src/index.ts package.json
git commit -m "feat(auth-kit): public exports + build/typecheck wiring"
```

---

## Validation (Plan complete)

- [ ] `bun test packages/auth-kit` — all pass; verifier rejects wrong iss/aud/alg/typ/expired/wrong-key; middleware 401s on missing/malformed/garbage; role gates 401/403 correctly.
- [ ] `bun run typecheck` — clean across all three packages.
- [ ] `bun run build` in auth-kit produces ESM + CJS + d.ts; `npm publish --dry-run` ships only `dist/**` (no source, no secrets).
- [ ] Claim shape in `src/types.ts` byte-for-byte matches `apps/chronoproof/src/core/access-token.ts` (sub/tid/wsid/role/orole/sid/typ/jti/iat/exp; iss/aud values).
- [ ] **Deferred (infra, not this plan):** publishing to a registry (GitHub Packages / Azure Artifacts) + CI publish workflow; product services installing it; an end-to-end test where `apps/chronoproof` signs a token that `createRemoteVerifier` validates against the live JWKS.

## Notes on faithfulness to the migration plan (Repo 1)

- Same responsibilities (verify middleware, role gates, tenant helper, shared types) and same package name `@chronoproof/auth-kit`.
- Deliberate adaptations: Hono+jose instead of Express+jsonwebtoken/jwks-rsa; `bun test` instead of vitest; monorepo package (publish-ready) instead of a separate published repo now; DB-agnostic tenant context instead of pg string-concat. These follow the user's decision to keep Bun + Azure SQL and adapt the plan's architecture.
