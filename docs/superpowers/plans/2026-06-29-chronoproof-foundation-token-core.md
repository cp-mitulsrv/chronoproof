# ChronoProof Foundation & Token Core — Implementation Plan (Plan 1 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the ChronoProof monorepo and build the cryptographic + persistence core — DB layer with migrations, password hashing, RSA signing keys, RS256 access tokens, opaque refresh tokens, and the public JWKS endpoint — so later plans can issue and verify real tokens.

**Architecture:** A Bun-workspaces monorepo. `apps/chronoproof` is a Hono HTTP service. `packages/db` owns the Kysely (tedious/Azure SQL) connection, schema, and a minimal migration runner. Pure-logic modules (password, signing keys, tokens, JWKS) live under `apps/chronoproof/src/core` and depend on an injectable key store so they can be unit-tested without a database.

**Tech Stack:** Bun, TypeScript, Hono, Azure SQL (SQL Server) via Kysely + `tedious` + `tarn`, `jose` for RS256/JWK, `Bun.password` (argon2id). Tests run with `bun test`. **No Docker:** pure-logic tests need no database; the DB integration test runs against a real, reachable Azure SQL / SQL Server configured via env (`DB_SERVER`/`DB_PASSWORD`) and skips when unset.

## Global Constraints

- Runtime: **Bun** (no Node-only build step). TypeScript throughout; `"type": "module"`.
- Database: **Azure SQL / SQL Server**. IDs are `UNIQUEIDENTIFIER DEFAULT NEWSEQUENTIALID()`; timestamps `DATETIME2 DEFAULT SYSUTCDATETIME()`.
- Tokens: access tokens are **RS256**, TTL **15 minutes**, claims `iss/aud/sub/tid/wsid/role/orole/sid/typ/jti/iat/exp`; `iss = https://auth.chronoproof.com`, `aud = chrono-services`, `typ = access`. Refresh tokens are **opaque random**, never JWTs, stored only as a hash.
- Passwords: **argon2id** via `Bun.password`.
- Every monetary/business table created later filters by `tenant_id`; this plan only creates the schema.
- Frequent commits: one commit per task minimum. TDD: write the failing test first.
- Secrets via env vars; never commit `.env` or `*.pem` (already in `.gitignore`).
- **No Docker anywhere in this project.** The DB integration test targets a real, reachable SQL Server / Azure SQL via env and skips cleanly when `DB_SERVER`/`DB_PASSWORD` are unset.

---

## File structure created by this plan

```
package.json                         # workspace root
tsconfig.base.json                   # shared TS config
.env.example                         # documented env vars (point DB_* at a real SQL Server)
packages/db/
  package.json
  src/types.ts                       # Kysely DB interface (table row types)
  src/connection.ts                  # createDb() Kysely+tedious factory
  src/migrator.ts                    # minimal migration runner
  src/migrations/0001_initial.ts     # all tables
  test/migrator.test.ts
apps/chronoproof/
  package.json
  src/index.ts                       # Hono app + Bun.serve entry
  src/app.ts                         # buildApp() -> Hono instance (testable)
  src/core/password.ts               # hashPassword/verifyPassword
  src/core/keystore.ts               # KeyStore interface + InMemoryKeyStore + DbKeyStore
  src/core/signing-keys.ts           # generateSigningKey/loadActiveKey
  src/core/access-token.ts           # signAccessToken/verifyAccessToken
  src/core/refresh-token.ts          # generateRefreshToken/hashRefreshToken/compare
  src/core/jwks.ts                   # toJwks()
  src/routes/jwks.ts                 # GET /.well-known/jwks.json
  test/health.test.ts
  test/core/password.test.ts
  test/core/signing-keys.test.ts
  test/core/access-token.test.ts
  test/core/refresh-token.test.ts
  test/core/jwks.test.ts
  test/routes/jwks.test.ts
```

---

### Task 1: Monorepo scaffold + Hono health endpoint

**Files:**
- Create: `package.json`, `tsconfig.base.json`, `.env.example`
- Create: `apps/chronoproof/package.json`, `apps/chronoproof/src/app.ts`, `apps/chronoproof/src/index.ts`
- Test: `apps/chronoproof/test/health.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `buildApp(): Hono` from `apps/chronoproof/src/app.ts` — a Hono app with `GET /health` returning `{ status: "ok" }`. All later route tests call `buildApp()` and use `app.request(...)`.

- [ ] **Step 1: Create the workspace root `package.json`**

```json
{
  "name": "chronoproof-monorepo",
  "private": true,
  "type": "module",
  "workspaces": ["apps/*", "packages/*"],
  "scripts": {
    "test": "bun test",
    "test:db": "bun test packages/db"
  }
}
```

- [ ] **Step 2: Create `tsconfig.base.json`**

```json
{
  "compilerOptions": {
    "target": "ESNext",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "types": ["bun-types"],
    "strict": true,
    "skipLibCheck": true,
    "esModuleInterop": true,
    "verbatimModuleSyntax": false,
    "noUncheckedIndexedAccess": true
  }
}
```

- [ ] **Step 3: Create `.env.example`**

```bash
# ChronoProof
PORT=3000
ISSUER=https://auth.chronoproof.com
AUDIENCE=chrono-services
ACCESS_TOKEN_TTL_SECONDS=900
REFRESH_TOKEN_TTL_DAYS=30

# Azure SQL / SQL Server
DB_SERVER=localhost
DB_PORT=1433
DB_NAME=chronoproof
DB_USER=sa
DB_PASSWORD=Your_strong_Passw0rd
DB_ENCRYPT=true
```

- [ ] **Step 4: Create `apps/chronoproof/package.json`**

```json
{
  "name": "@chronoproof/server",
  "type": "module",
  "main": "src/index.ts",
  "dependencies": {
    "hono": "^4.6.0",
    "jose": "^5.9.0"
  },
  "devDependencies": {
    "bun-types": "latest",
    "typescript": "^5.6.0"
  }
}
```

> Note: `@chronoproof/db` is intentionally NOT a dependency here in Plan 1 — `apps/chronoproof` does not query the database yet (the core modules use an injectable in-memory key store, and `packages/db` is tested independently). The dependency is added in Plan 2 when ChronoProof first reads/writes the DB.

- [ ] **Step 5: Write the failing test** — `apps/chronoproof/test/health.test.ts`

```ts
import { test, expect } from "bun:test";
import { buildApp } from "../src/app";

test("GET /health returns ok", async () => {
  const app = buildApp();
  const res = await app.request("/health");
  expect(res.status).toBe(200);
  expect(await res.json()).toEqual({ status: "ok" });
});
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `cd /home/dhruv/Videos/chronoproof && bun install && bun test apps/chronoproof/test/health.test.ts`
Expected: FAIL — cannot resolve `../src/app`.

- [ ] **Step 7: Implement `apps/chronoproof/src/app.ts`**

```ts
import { Hono } from "hono";

export function buildApp(): Hono {
  const app = new Hono();
  app.get("/health", (c) => c.json({ status: "ok" }));
  return app;
}
```

- [ ] **Step 8: Implement `apps/chronoproof/src/index.ts`**

```ts
import { buildApp } from "./app";

const app = buildApp();
const port = Number(process.env.PORT ?? 3000);

export default { port, fetch: app.fetch };
```

- [ ] **Step 9: Run the test to verify it passes**

Run: `bun test apps/chronoproof/test/health.test.ts`
Expected: PASS (1 pass).

- [ ] **Step 10: Commit**

```bash
git add package.json tsconfig.base.json .env.example apps/chronoproof
git commit -m "feat: scaffold Bun monorepo with Hono health endpoint"
```

---

### Task 2: Password service (argon2id)

**Files:**
- Create: `apps/chronoproof/src/core/password.ts`
- Test: `apps/chronoproof/test/core/password.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `hashPassword(plain: string): Promise<string>`
  - `verifyPassword(plain: string, hash: string): Promise<boolean>`

- [ ] **Step 1: Write the failing test** — `apps/chronoproof/test/core/password.test.ts`

```ts
import { test, expect } from "bun:test";
import { hashPassword, verifyPassword } from "../../src/core/password";

test("hash then verify succeeds for correct password", async () => {
  const hash = await hashPassword("s3cret-pw");
  expect(hash).not.toBe("s3cret-pw");
  expect(await verifyPassword("s3cret-pw", hash)).toBe(true);
});

test("verify fails for wrong password", async () => {
  const hash = await hashPassword("s3cret-pw");
  expect(await verifyPassword("wrong", hash)).toBe(false);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test apps/chronoproof/test/core/password.test.ts`
Expected: FAIL — cannot resolve module.

- [ ] **Step 3: Implement `apps/chronoproof/src/core/password.ts`**

```ts
export function hashPassword(plain: string): Promise<string> {
  return Bun.password.hash(plain, { algorithm: "argon2id" });
}

export function verifyPassword(plain: string, hash: string): Promise<boolean> {
  return Bun.password.verify(plain, hash);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test apps/chronoproof/test/core/password.test.ts`
Expected: PASS (2 pass).

- [ ] **Step 5: Commit**

```bash
git add apps/chronoproof/src/core/password.ts apps/chronoproof/test/core/password.test.ts
git commit -m "feat: argon2id password hashing service"
```

---

### Task 3: Key store abstraction + RSA signing-key service

**Files:**
- Create: `apps/chronoproof/src/core/keystore.ts`
- Create: `apps/chronoproof/src/core/signing-keys.ts`
- Test: `apps/chronoproof/test/core/signing-keys.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `interface StoredKey { kid: string; publicPem: string; privatePem: string; isActive: boolean; createdAt: Date }`
  - `interface KeyStore { getActive(): Promise<StoredKey | null>; getAll(): Promise<StoredKey[]>; insert(k: StoredKey): Promise<void>; }`
  - `class InMemoryKeyStore implements KeyStore`
  - `generateSigningKey(store: KeyStore): Promise<StoredKey>` — generates an RSA keypair, marks it active, persists it.
  - `loadActiveKey(store: KeyStore): Promise<StoredKey>` — returns the active key or generates one if none exists.

- [ ] **Step 1: Write the failing test** — `apps/chronoproof/test/core/signing-keys.test.ts`

```ts
import { test, expect } from "bun:test";
import { InMemoryKeyStore, generateSigningKey, loadActiveKey } from "../../src/core/signing-keys";

test("generateSigningKey creates an active RSA PEM keypair", async () => {
  const store = new InMemoryKeyStore();
  const key = await generateSigningKey(store);
  expect(key.kid).toBeString();
  expect(key.privatePem).toContain("BEGIN PRIVATE KEY");
  expect(key.publicPem).toContain("BEGIN PUBLIC KEY");
  expect(key.isActive).toBe(true);
});

test("loadActiveKey returns existing active key without creating a new one", async () => {
  const store = new InMemoryKeyStore();
  const created = await generateSigningKey(store);
  const loaded = await loadActiveKey(store);
  expect(loaded.kid).toBe(created.kid);
  expect((await store.getAll()).length).toBe(1);
});

test("loadActiveKey generates a key when store is empty", async () => {
  const store = new InMemoryKeyStore();
  const loaded = await loadActiveKey(store);
  expect(loaded.isActive).toBe(true);
  expect((await store.getAll()).length).toBe(1);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test apps/chronoproof/test/core/signing-keys.test.ts`
Expected: FAIL — cannot resolve module.

- [ ] **Step 3: Implement `apps/chronoproof/src/core/keystore.ts`**

```ts
export interface StoredKey {
  kid: string;
  publicPem: string;
  privatePem: string;
  isActive: boolean;
  createdAt: Date;
}

export interface KeyStore {
  getActive(): Promise<StoredKey | null>;
  getAll(): Promise<StoredKey[]>;
  insert(key: StoredKey): Promise<void>;
}

export class InMemoryKeyStore implements KeyStore {
  private keys: StoredKey[] = [];

  async getActive(): Promise<StoredKey | null> {
    return this.keys.find((k) => k.isActive) ?? null;
  }
  async getAll(): Promise<StoredKey[]> {
    return [...this.keys];
  }
  async insert(key: StoredKey): Promise<void> {
    if (key.isActive) this.keys = this.keys.map((k) => ({ ...k, isActive: false }));
    this.keys.push(key);
  }
}
```

- [ ] **Step 4: Implement `apps/chronoproof/src/core/signing-keys.ts`**

```ts
import { generateKeyPair, exportPKCS8, exportSPKI } from "jose";
import { randomUUID } from "node:crypto";
import type { KeyStore, StoredKey } from "./keystore";

export { InMemoryKeyStore } from "./keystore";
export type { KeyStore, StoredKey } from "./keystore";

export async function generateSigningKey(store: KeyStore): Promise<StoredKey> {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const key: StoredKey = {
    kid: randomUUID(),
    publicPem: await exportSPKI(publicKey),
    privatePem: await exportPKCS8(privateKey),
    isActive: true,
    createdAt: new Date(),
  };
  await store.insert(key);
  return key;
}

export async function loadActiveKey(store: KeyStore): Promise<StoredKey> {
  const active = await store.getActive();
  if (active) return active;
  return generateSigningKey(store);
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test apps/chronoproof/test/core/signing-keys.test.ts`
Expected: PASS (3 pass).

- [ ] **Step 6: Commit**

```bash
git add apps/chronoproof/src/core/keystore.ts apps/chronoproof/src/core/signing-keys.ts apps/chronoproof/test/core/signing-keys.test.ts
git commit -m "feat: RSA signing-key service with pluggable key store"
```

---

### Task 4: Access-token service (RS256 sign + verify)

**Files:**
- Create: `apps/chronoproof/src/core/access-token.ts`
- Test: `apps/chronoproof/test/core/access-token.test.ts`

**Interfaces:**
- Consumes: `StoredKey` from Task 3.
- Produces:
  - `interface AccessClaims { sub: string; tid: string; wsid: string; role: "owner" | "member"; orole: "owner" | "admin" | "member"; sid: string }`
  - `interface TokenConfig { issuer: string; audience: string; ttlSeconds: number }`
  - `signAccessToken(claims: AccessClaims, key: StoredKey, cfg: TokenConfig): Promise<string>`
  - `verifyAccessToken(token: string, key: StoredKey, cfg: TokenConfig): Promise<AccessClaims & { iss: string; aud: string; typ: string; jti: string; iat: number; exp: number }>`

- [ ] **Step 1: Write the failing test** — `apps/chronoproof/test/core/access-token.test.ts`

```ts
import { test, expect } from "bun:test";
import { InMemoryKeyStore, generateSigningKey } from "../../src/core/signing-keys";
import { signAccessToken, verifyAccessToken } from "../../src/core/access-token";

const cfg = { issuer: "https://auth.chronoproof.com", audience: "chrono-services", ttlSeconds: 900 };
const claims = {
  sub: "user-1", tid: "org-1", wsid: "ws-1",
  role: "owner" as const, orole: "owner" as const, sid: "sess-1",
};

test("signed token verifies and round-trips claims", async () => {
  const key = await generateSigningKey(new InMemoryKeyStore());
  const token = await signAccessToken(claims, key, cfg);
  const decoded = await verifyAccessToken(token, key, cfg);
  expect(decoded.sub).toBe("user-1");
  expect(decoded.tid).toBe("org-1");
  expect(decoded.wsid).toBe("ws-1");
  expect(decoded.role).toBe("owner");
  expect(decoded.typ).toBe("access");
  expect(decoded.iss).toBe(cfg.issuer);
  expect(decoded.aud).toBe(cfg.audience);
  expect(decoded.jti).toBeString();
});

test("verification rejects a token with the wrong audience", async () => {
  const key = await generateSigningKey(new InMemoryKeyStore());
  const token = await signAccessToken(claims, key, cfg);
  await expect(
    verifyAccessToken(token, key, { ...cfg, audience: "someone-else" }),
  ).rejects.toThrow();
});

test("verification rejects a tampered token", async () => {
  const key = await generateSigningKey(new InMemoryKeyStore());
  const token = await signAccessToken(claims, key, cfg);
  const tampered = token.slice(0, -3) + "xxx";
  await expect(verifyAccessToken(tampered, key, cfg)).rejects.toThrow();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test apps/chronoproof/test/core/access-token.test.ts`
Expected: FAIL — cannot resolve module.

- [ ] **Step 3: Implement `apps/chronoproof/src/core/access-token.ts`**

```ts
import { SignJWT, jwtVerify, importPKCS8, importSPKI } from "jose";
import { randomUUID } from "node:crypto";
import type { StoredKey } from "./keystore";

export interface AccessClaims {
  sub: string;
  tid: string;
  wsid: string;
  role: "owner" | "member";
  orole: "owner" | "admin" | "member";
  sid: string;
}

export interface TokenConfig {
  issuer: string;
  audience: string;
  ttlSeconds: number;
}

const ALG = "RS256";

export async function signAccessToken(
  claims: AccessClaims,
  key: StoredKey,
  cfg: TokenConfig,
): Promise<string> {
  const privateKey = await importPKCS8(key.privatePem, ALG);
  return new SignJWT({
    tid: claims.tid,
    wsid: claims.wsid,
    role: claims.role,
    orole: claims.orole,
    sid: claims.sid,
    typ: "access",
  })
    .setProtectedHeader({ alg: ALG, kid: key.kid })
    .setSubject(claims.sub)
    .setIssuer(cfg.issuer)
    .setAudience(cfg.audience)
    .setIssuedAt()
    .setJti(randomUUID())
    .setExpirationTime(`${cfg.ttlSeconds}s`)
    .sign(privateKey);
}

export async function verifyAccessToken(token: string, key: StoredKey, cfg: TokenConfig) {
  const publicKey = await importSPKI(key.publicPem, ALG);
  const { payload } = await jwtVerify(token, publicKey, {
    issuer: cfg.issuer,
    audience: cfg.audience,
    algorithms: [ALG],
  });
  if (payload.typ !== "access") throw new Error("not an access token");
  return payload as unknown as AccessClaims & {
    iss: string; aud: string; typ: string; jti: string; iat: number; exp: number;
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test apps/chronoproof/test/core/access-token.test.ts`
Expected: PASS (3 pass).

- [ ] **Step 5: Commit**

```bash
git add apps/chronoproof/src/core/access-token.ts apps/chronoproof/test/core/access-token.test.ts
git commit -m "feat: RS256 access-token sign/verify service"
```

---

### Task 5: Refresh-token service (opaque + hash)

**Files:**
- Create: `apps/chronoproof/src/core/refresh-token.ts`
- Test: `apps/chronoproof/test/core/refresh-token.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `generateRefreshToken(): string` — 256 bits of entropy, base64url.
  - `hashRefreshToken(token: string): string` — SHA-256 hex of the token.
  - `refreshTokenMatches(token: string, hash: string): boolean` — constant-time compare against a stored hash.

- [ ] **Step 1: Write the failing test** — `apps/chronoproof/test/core/refresh-token.test.ts`

```ts
import { test, expect } from "bun:test";
import { generateRefreshToken, hashRefreshToken, refreshTokenMatches } from "../../src/core/refresh-token";

test("generated tokens are unique and high-entropy", () => {
  const a = generateRefreshToken();
  const b = generateRefreshToken();
  expect(a).not.toBe(b);
  expect(a.length).toBeGreaterThanOrEqual(43); // 32 bytes base64url
});

test("hash matches the originating token and rejects others", () => {
  const token = generateRefreshToken();
  const hash = hashRefreshToken(token);
  expect(refreshTokenMatches(token, hash)).toBe(true);
  expect(refreshTokenMatches(generateRefreshToken(), hash)).toBe(false);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test apps/chronoproof/test/core/refresh-token.test.ts`
Expected: FAIL — cannot resolve module.

- [ ] **Step 3: Implement `apps/chronoproof/src/core/refresh-token.ts`**

```ts
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";

export function generateRefreshToken(): string {
  return randomBytes(32).toString("base64url");
}

export function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function refreshTokenMatches(token: string, hash: string): boolean {
  const a = Buffer.from(hashRefreshToken(token), "hex");
  const b = Buffer.from(hash, "hex");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test apps/chronoproof/test/core/refresh-token.test.ts`
Expected: PASS (2 pass).

- [ ] **Step 5: Commit**

```bash
git add apps/chronoproof/src/core/refresh-token.ts apps/chronoproof/test/core/refresh-token.test.ts
git commit -m "feat: opaque refresh-token generation and hashing"
```

---

### Task 6: JWKS serialization + public endpoint

**Files:**
- Create: `apps/chronoproof/src/core/jwks.ts`
- Create: `apps/chronoproof/src/routes/jwks.ts`
- Modify: `apps/chronoproof/src/app.ts` (mount the route + provide a key store)
- Test: `apps/chronoproof/test/core/jwks.test.ts`, `apps/chronoproof/test/routes/jwks.test.ts`

**Interfaces:**
- Consumes: `StoredKey` (Task 3); `loadActiveKey`, `KeyStore`, `InMemoryKeyStore`.
- Produces:
  - `toJwks(keys: StoredKey[]): Promise<{ keys: object[] }>` — every key as a JWK with `kid`, `use:"sig"`, `alg:"RS256"`.
  - `buildApp(deps?: { keyStore?: KeyStore }): Hono` — `buildApp` now accepts an optional key store so tests inject `InMemoryKeyStore`; default is a module-level `InMemoryKeyStore` (DB-backed store arrives in Plan 2).
  - Route: `GET /.well-known/jwks.json` → `{ keys: [...] }`.

- [ ] **Step 1: Write the failing core test** — `apps/chronoproof/test/core/jwks.test.ts`

```ts
import { test, expect } from "bun:test";
import { InMemoryKeyStore, generateSigningKey } from "../../src/core/signing-keys";
import { toJwks } from "../../src/core/jwks";

test("toJwks emits a signing JWK per key with kid and alg", async () => {
  const store = new InMemoryKeyStore();
  const key = await generateSigningKey(store);
  const jwks = await toJwks(await store.getAll());
  expect(jwks.keys.length).toBe(1);
  const jwk = jwks.keys[0] as Record<string, unknown>;
  expect(jwk.kid).toBe(key.kid);
  expect(jwk.use).toBe("sig");
  expect(jwk.alg).toBe("RS256");
  expect(jwk.kty).toBe("RSA");
  expect(jwk.d).toBeUndefined(); // public only — no private exponent
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test apps/chronoproof/test/core/jwks.test.ts`
Expected: FAIL — cannot resolve module.

- [ ] **Step 3: Implement `apps/chronoproof/src/core/jwks.ts`**

```ts
import { importSPKI, exportJWK } from "jose";
import type { StoredKey } from "./keystore";

export async function toJwks(keys: StoredKey[]): Promise<{ keys: object[] }> {
  const jwks = await Promise.all(
    keys.map(async (k) => {
      const publicKey = await importSPKI(k.publicPem, "RS256");
      const jwk = await exportJWK(publicKey);
      return { ...jwk, kid: k.kid, use: "sig", alg: "RS256" };
    }),
  );
  return { keys: jwks };
}
```

- [ ] **Step 4: Run the core test to verify it passes**

Run: `bun test apps/chronoproof/test/core/jwks.test.ts`
Expected: PASS (1 pass).

- [ ] **Step 5: Write the failing route test** — `apps/chronoproof/test/routes/jwks.test.ts`

```ts
import { test, expect } from "bun:test";
import { InMemoryKeyStore, generateSigningKey } from "../../src/core/signing-keys";
import { buildApp } from "../../src/app";

test("GET /.well-known/jwks.json returns the active public key", async () => {
  const keyStore = new InMemoryKeyStore();
  const key = await generateSigningKey(keyStore);
  const app = buildApp({ keyStore });
  const res = await app.request("/.well-known/jwks.json");
  expect(res.status).toBe(200);
  const body = (await res.json()) as { keys: Array<{ kid: string }> };
  expect(body.keys[0]?.kid).toBe(key.kid);
});
```

- [ ] **Step 6: Run the route test to verify it fails**

Run: `bun test apps/chronoproof/test/routes/jwks.test.ts`
Expected: FAIL — `buildApp` does not accept deps / route missing.

- [ ] **Step 7: Implement `apps/chronoproof/src/routes/jwks.ts`**

```ts
import { Hono } from "hono";
import type { KeyStore } from "../core/keystore";
import { toJwks } from "../core/jwks";

export function jwksRoute(keyStore: KeyStore): Hono {
  const route = new Hono();
  route.get("/.well-known/jwks.json", async (c) => {
    const keys = await keyStore.getAll();
    return c.json(await toJwks(keys));
  });
  return route;
}
```

- [ ] **Step 8: Update `apps/chronoproof/src/app.ts` to accept deps and mount the route**

```ts
import { Hono } from "hono";
import { InMemoryKeyStore } from "./core/keystore";
import type { KeyStore } from "./core/keystore";
import { jwksRoute } from "./routes/jwks";

export interface AppDeps {
  keyStore?: KeyStore;
}

const defaultKeyStore = new InMemoryKeyStore();

export function buildApp(deps: AppDeps = {}): Hono {
  const keyStore = deps.keyStore ?? defaultKeyStore;
  const app = new Hono();
  app.get("/health", (c) => c.json({ status: "ok" }));
  app.route("/", jwksRoute(keyStore));
  return app;
}
```

- [ ] **Step 9: Run all app tests to verify they pass**

Run: `bun test apps/chronoproof`
Expected: PASS (health + jwks core + jwks route + earlier core tests all green).

- [ ] **Step 10: Commit**

```bash
git add apps/chronoproof/src/core/jwks.ts apps/chronoproof/src/routes/jwks.ts apps/chronoproof/src/app.ts apps/chronoproof/test/core/jwks.test.ts apps/chronoproof/test/routes/jwks.test.ts
git commit -m "feat: JWKS serialization and public /.well-known/jwks.json endpoint"
```

---

### Task 7: Database package — connection + row types

**Files:**
- Create: `packages/db/package.json`, `packages/db/src/types.ts`, `packages/db/src/connection.ts`

**Interfaces:**
- Consumes: env vars from `.env.example` (point `DB_*` at a real, reachable Azure SQL / SQL Server — no Docker).
- Produces:
  - `interface DB` — Kysely database interface with tables `organizations`, `users`, `workspaces`, `workspace_members`, `invitations`, `sessions`, `signing_keys`, `migrations`.
  - `createDb(cfg: DbConfig): Kysely<DB>` where `DbConfig = { server: string; port: number; database: string; user: string; password: string; encrypt: boolean }`.

- [ ] **Step 1: Create `packages/db/package.json`**

```json
{
  "name": "@chronoproof/db",
  "type": "module",
  "main": "src/index.ts",
  "dependencies": {
    "kysely": "^0.27.4",
    "tedious": "^18.6.1",
    "tarn": "^3.0.2"
  },
  "devDependencies": {
    "bun-types": "latest",
    "typescript": "^5.6.0"
  }
}
```

- [ ] **Step 2: Create `packages/db/src/types.ts`**

```ts
import type { Generated } from "kysely";

export interface OrganizationsTable {
  id: Generated<string>;
  name: string;
  slug: string;
  status: string;
  created_at: Generated<Date>;
}

export interface UsersTable {
  id: Generated<string>;
  org_id: string;
  email: string;
  email_normalized: string;
  password_hash: string;
  name: string;
  org_role: string;
  status: string;
  created_at: Generated<Date>;
}

export interface WorkspacesTable {
  id: Generated<string>;
  org_id: string;
  name: string;
  slug: string;
  created_at: Generated<Date>;
}

export interface WorkspaceMembersTable {
  id: Generated<string>;
  workspace_id: string;
  user_id: string;
  role: string;
  created_at: Generated<Date>;
}

export interface InvitationsTable {
  id: Generated<string>;
  org_id: string;
  workspace_id: string;
  email: string;
  role: string;
  token_hash: string;
  status: string;
  invited_by: string;
  expires_at: Date;
  created_at: Generated<Date>;
}

export interface SessionsTable {
  id: Generated<string>;
  user_id: string;
  org_id: string;
  workspace_id: string;
  refresh_token_hash: string;
  device: string | null;
  ip: string | null;
  user_agent: string | null;
  expires_at: Date;
  last_used_at: Generated<Date>;
  created_at: Generated<Date>;
  revoked: Generated<boolean>;
}

export interface SigningKeysTable {
  kid: string;
  public_pem: string;
  private_pem_encrypted: string;
  is_active: boolean;
  created_at: Generated<Date>;
}

export interface MigrationsTable {
  name: string;
  applied_at: Generated<Date>;
}

export interface DB {
  organizations: OrganizationsTable;
  users: UsersTable;
  workspaces: WorkspacesTable;
  workspace_members: WorkspaceMembersTable;
  invitations: InvitationsTable;
  sessions: SessionsTable;
  signing_keys: SigningKeysTable;
  migrations: MigrationsTable;
}
```

- [ ] **Step 3: Create `packages/db/src/connection.ts`**

```ts
import { Kysely, MssqlDialect } from "kysely";
import * as tedious from "tedious";
import * as tarn from "tarn";
import type { DB } from "./types";

export interface DbConfig {
  server: string;
  port: number;
  database: string;
  user: string;
  password: string;
  encrypt: boolean;
}

export function createDb(cfg: DbConfig): Kysely<DB> {
  const dialect = new MssqlDialect({
    tarn: { ...tarn, options: { min: 0, max: 10 } },
    tedious: {
      ...tedious,
      connectionFactory: () =>
        new tedious.Connection({
          server: cfg.server,
          authentication: {
            type: "default",
            options: { userName: cfg.user, password: cfg.password },
          },
          options: {
            database: cfg.database,
            port: cfg.port,
            encrypt: cfg.encrypt,
            trustServerCertificate: true,
          },
        }),
    },
  });
  return new Kysely<DB>({ dialect });
}

export function dbConfigFromEnv(): DbConfig {
  return {
    server: process.env.DB_SERVER ?? "localhost",
    port: Number(process.env.DB_PORT ?? 1433),
    database: process.env.DB_NAME ?? "chronoproof",
    user: process.env.DB_USER ?? "sa",
    password: process.env.DB_PASSWORD ?? "",
    encrypt: (process.env.DB_ENCRYPT ?? "true") === "true",
  };
}
```

- [ ] **Step 4: Install and smoke-check the module loads**

Run: `bun install && bun -e "await import('./packages/db/src/connection.ts'); await import('./packages/db/src/types.ts'); console.log('db package loads ok')"`
Expected: prints `db package loads ok` with no import/resolution errors (confirms `kysely`, `tedious`, `tarn` resolve and the modules parse). (No unit test here — this is wiring; `connection.ts` is exercised for real by the migrator integration test in Task 8, which connects to a real SQL Server via env — no Docker.)

- [ ] **Step 5: Commit**

```bash
git add packages/db/package.json packages/db/src/types.ts packages/db/src/connection.ts
git commit -m "feat: Kysely+tedious Azure SQL connection and DB row types"
```

---

### Task 8: Migration runner + initial schema (integration-tested)

**Files:**
- Create: `packages/db/src/migrator.ts`, `packages/db/src/migrations/0001_initial.ts`, `packages/db/src/index.ts`
- Test: `packages/db/test/migrator.test.ts`

**Interfaces:**
- Consumes: `createDb`, `DB` (Task 7).
- Produces:
  - `interface Migration { name: string; up(db: Kysely<DB>): Promise<void> }`
  - `migrations: Migration[]` (ordered).
  - `runMigrations(db: Kysely<DB>): Promise<string[]>` — creates the `migrations` table if absent, applies each unapplied migration in order, returns the names applied this run.
  - `packages/db/src/index.ts` re-exports `createDb`, `dbConfigFromEnv`, `runMigrations`, and `DB`.

> **Execution note (NO Docker):** This integration test connects to a real, reachable SQL Server / Azure SQL configured via env (`DB_SERVER`/`DB_PASSWORD`, see `.env.example`; Bun auto-loads `.env`). It **skips cleanly** when those are unset, so `bun test` is always green without a database. To actually run it, point `DB_*` at your Azure SQL dev DB (or any SQL Server you can reach) and run `bun test packages/db`.

- [ ] **Step 1: Write the failing test** — `packages/db/test/migrator.test.ts`

```ts
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { Kysely, sql } from "kysely";
import { createDb, dbConfigFromEnv } from "../src/connection";
import { runMigrations } from "../src/migrator";
import type { DB } from "../src/types";

// Integration test — runs against a REAL, reachable SQL Server / Azure SQL.
// No Docker. Configure DB_SERVER + DB_PASSWORD (see .env.example) to enable it;
// otherwise it is skipped so `bun test` stays green with no database.
const dbConfigured = Boolean(process.env.DB_SERVER && process.env.DB_PASSWORD);

if (!dbConfigured) {
  console.info(
    "[migrator.test] DB_SERVER/DB_PASSWORD not set — skipping DB integration test. " +
      "Point these at your Azure SQL / SQL Server to run it.",
  );
}

describe.skipIf(!dbConfigured)("migration runner (integration)", () => {
  let db: Kysely<DB>;

  beforeAll(async () => {
    // ensure the target database exists, then connect to it
    const admin = createDb({ ...dbConfigFromEnv(), database: "master" });
    await sql`IF DB_ID('chronoproof') IS NULL CREATE DATABASE chronoproof`.execute(admin);
    await admin.destroy();
    db = createDb(dbConfigFromEnv());
  });

  afterAll(async () => {
    await db?.destroy();
  });

  test("runMigrations creates all tables and is idempotent", async () => {
    const first = await runMigrations(db);
    expect(first).toContain("0001_initial");

    const tables = await sql<{ name: string }>`
      SELECT name FROM sys.tables
    `.execute(db);
    const names = tables.rows.map((r) => r.name);
    for (const t of [
      "organizations", "users", "workspaces", "workspace_members",
      "invitations", "sessions", "signing_keys",
    ]) {
      expect(names).toContain(t);
    }

    const second = await runMigrations(db);
    expect(second).toEqual([]); // nothing new to apply
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run (with `DB_*` configured for a reachable SQL Server): `bun test packages/db/test/migrator.test.ts`
Expected: FAIL — cannot resolve `../src/migrator`. (With no `DB_*` set, the test is skipped instead — implement first, then point at a real DB to see it pass.)

- [ ] **Step 3: Implement `packages/db/src/migrations/0001_initial.ts`**

```ts
import { sql, type Kysely } from "kysely";
import type { DB } from "../types";

export async function up(db: Kysely<DB>): Promise<void> {
  await sql`
    CREATE TABLE organizations (
      id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID() PRIMARY KEY,
      name NVARCHAR(200) NOT NULL,
      slug NVARCHAR(120) NOT NULL UNIQUE,
      status NVARCHAR(40) NOT NULL DEFAULT 'active',
      created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
    )`.execute(db);

  await sql`
    CREATE TABLE users (
      id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID() PRIMARY KEY,
      org_id UNIQUEIDENTIFIER NOT NULL REFERENCES organizations(id),
      email NVARCHAR(320) NOT NULL,
      email_normalized NVARCHAR(320) NOT NULL UNIQUE,
      password_hash NVARCHAR(400) NOT NULL,
      name NVARCHAR(200) NOT NULL,
      org_role NVARCHAR(20) NOT NULL DEFAULT 'member',
      status NVARCHAR(20) NOT NULL DEFAULT 'active',
      created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
    )`.execute(db);
  await sql`CREATE INDEX ix_users_org ON users(org_id)`.execute(db);

  await sql`
    CREATE TABLE workspaces (
      id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID() PRIMARY KEY,
      org_id UNIQUEIDENTIFIER NOT NULL REFERENCES organizations(id),
      name NVARCHAR(200) NOT NULL,
      slug NVARCHAR(120) NOT NULL,
      created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
      CONSTRAINT uq_workspace_slug UNIQUE (org_id, slug)
    )`.execute(db);
  await sql`CREATE INDEX ix_workspaces_org ON workspaces(org_id)`.execute(db);

  await sql`
    CREATE TABLE workspace_members (
      id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID() PRIMARY KEY,
      workspace_id UNIQUEIDENTIFIER NOT NULL REFERENCES workspaces(id),
      user_id UNIQUEIDENTIFIER NOT NULL REFERENCES users(id),
      role NVARCHAR(20) NOT NULL DEFAULT 'member',
      created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
      CONSTRAINT uq_ws_member UNIQUE (workspace_id, user_id)
    )`.execute(db);

  await sql`
    CREATE TABLE invitations (
      id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID() PRIMARY KEY,
      org_id UNIQUEIDENTIFIER NOT NULL REFERENCES organizations(id),
      workspace_id UNIQUEIDENTIFIER NOT NULL REFERENCES workspaces(id),
      email NVARCHAR(320) NOT NULL,
      role NVARCHAR(20) NOT NULL DEFAULT 'member',
      token_hash NVARCHAR(128) NOT NULL,
      status NVARCHAR(20) NOT NULL DEFAULT 'pending',
      invited_by UNIQUEIDENTIFIER NOT NULL REFERENCES users(id),
      expires_at DATETIME2 NOT NULL,
      created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
    )`.execute(db);
  await sql`CREATE INDEX ix_invitations_token ON invitations(token_hash)`.execute(db);

  await sql`
    CREATE TABLE sessions (
      id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID() PRIMARY KEY,
      user_id UNIQUEIDENTIFIER NOT NULL REFERENCES users(id),
      org_id UNIQUEIDENTIFIER NOT NULL,
      workspace_id UNIQUEIDENTIFIER NOT NULL,
      refresh_token_hash NVARCHAR(128) NOT NULL,
      device NVARCHAR(200) NULL,
      ip NVARCHAR(64) NULL,
      user_agent NVARCHAR(400) NULL,
      expires_at DATETIME2 NOT NULL,
      last_used_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
      created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
      revoked BIT NOT NULL DEFAULT 0
    )`.execute(db);
  await sql`CREATE INDEX ix_sessions_user ON sessions(user_id)`.execute(db);
  await sql`CREATE INDEX ix_sessions_refresh ON sessions(refresh_token_hash)`.execute(db);

  await sql`
    CREATE TABLE signing_keys (
      kid NVARCHAR(64) NOT NULL PRIMARY KEY,
      public_pem NVARCHAR(MAX) NOT NULL,
      private_pem_encrypted NVARCHAR(MAX) NOT NULL,
      is_active BIT NOT NULL DEFAULT 0,
      created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
    )`.execute(db);
}
```

- [ ] **Step 4: Implement `packages/db/src/migrator.ts`**

```ts
import { sql, type Kysely } from "kysely";
import type { DB } from "./types";
import { up as up0001 } from "./migrations/0001_initial";

export interface Migration {
  name: string;
  up(db: Kysely<DB>): Promise<void>;
}

export const migrations: Migration[] = [{ name: "0001_initial", up: up0001 }];

export async function runMigrations(db: Kysely<DB>): Promise<string[]> {
  await sql`
    IF OBJECT_ID('migrations') IS NULL
      CREATE TABLE migrations (
        name NVARCHAR(200) NOT NULL PRIMARY KEY,
        applied_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
      )`.execute(db);

  const applied = await db.selectFrom("migrations").select("name").execute();
  const appliedNames = new Set(applied.map((r) => r.name));
  const ran: string[] = [];

  for (const migration of migrations) {
    if (appliedNames.has(migration.name)) continue;
    await migration.up(db);
    await db.insertInto("migrations").values({ name: migration.name }).execute();
    ran.push(migration.name);
  }
  return ran;
}
```

- [ ] **Step 5: Implement `packages/db/src/index.ts`**

```ts
export { createDb, dbConfigFromEnv, type DbConfig } from "./connection";
export { runMigrations, migrations, type Migration } from "./migrator";
export type { DB } from "./types";
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `bun test packages/db/test/migrator.test.ts`
Expected: PASS (1 pass — all tables present, second run applies nothing).

- [ ] **Step 7: Commit**

```bash
git add packages/db/src/migrator.ts packages/db/src/migrations packages/db/src/index.ts packages/db/test/migrator.test.ts
git commit -m "feat: migration runner and initial ChronoProof schema"
```

---

## Plan 1 sign-off

Run the full suite (no Docker — no database needed for the logic tests):

```bash
bun test          # pure-logic tests: health, password, signing-keys, access-token, refresh-token, jwks core, jwks route
bun run typecheck  # static type check across both packages
```

The DB migration integration test runs only when you point `DB_*` at a real, reachable Azure SQL / SQL Server (otherwise it skips):

```bash
# set DB_SERVER / DB_PASSWORD etc. (e.g. via .env), then:
bun test packages/db
```

Expected: the logic suite passes with no database; with `DB_*` configured, the migrator test also passes and creates the full schema. At this point ChronoProof can generate signing keys, issue/verify RS256 access tokens, mint/hash refresh tokens, serve JWKS, and migrate the full database schema. **Plans 2–4 build on this** (auth/session endpoints, tenancy, the `@chronoproof/auth` verifier + sample service).

---

## Self-review against the spec (Plan 1 portion)

- **Stack (Bun/TS/Hono/Azure SQL/Kysely/jose/Bun.password):** Tasks 1, 2, 4, 6, 7. ✅
- **RS256 + JWKS contract (claims, iss/aud/typ):** Tasks 4 (claims/sign/verify) + 6 (JWKS endpoint). ✅
- **Stateless access (15m TTL) + hashed refresh:** Task 4 (TTL via config) + Task 5 (opaque + SHA-256 hash + constant-time compare). ✅
- **Schema = organizations/users/workspaces/workspace_members/invitations/sessions(login_logon)/signing_keys:** Task 8. ✅ `sessions` stores only `refresh_token_hash` (decision #6). ✅
- **Org=Tenant, one org per user, workspace membership:** encoded in `users.org_id` + `workspace_members` (Task 7/8 types & DDL). ✅
- **Key rotation via kid:** `kid` in token header (Task 4) + `signing_keys` table + JWKS lists all keys (Task 6/8). ✅
- **Out of scope here (register/login/refresh/switch/invite endpoints, verifier package, sample service):** deferred to Plans 2–4 by design. ✅
- **Placeholder scan:** none.
- **Type consistency:** `StoredKey`, `AccessClaims`, `TokenConfig`, `KeyStore`, `DbConfig`, `DB`, `Migration` defined once and reused consistently across tasks. ✅
