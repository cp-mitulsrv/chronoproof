/**
 * Dev/test seed: creates one login per org role (owner / admin / member) inside a
 * single "Test Org" tenant + "Test Workspace". Idempotent — re-running replaces the
 * test users. Run: `bun run src/db/seed_test_users.ts`
 *
 * These are TEST credentials only. Do not use in production.
 */
import { sql, getPool } from "./pool.js";
import { hashPassword } from "../services/passwordService.js";

const TENANT_NAME = "Test Org";
const TENANT_SLUG = "test-org";
const WORKSPACE_NAME = "Test Workspace";

interface SeedUser {
  email: string;
  password: string;
  name: string;
  orgRole: "owner" | "admin" | "member";
  wsRole: "owner" | "member";
}

const USERS: SeedUser[] = [
  { email: "owner@chronoproof.test", password: "Owner@12345", name: "Test Owner", orgRole: "owner", wsRole: "owner" },
  { email: "admin@chronoproof.test", password: "Admin@12345", name: "Test Admin", orgRole: "admin", wsRole: "member" },
  { email: "member@chronoproof.test", password: "Member@12345", name: "Test Member", orgRole: "member", wsRole: "member" },
];

async function main(): Promise<void> {
  const pool = await getPool();

  // Tenant (by slug)
  let tid = (
    await pool.request().input("slug", sql.NVarChar(200), TENANT_SLUG)
      .query<{ id: string }>(`SELECT id FROM dbo.tenants WHERE slug = @slug`)
  ).recordset[0]?.id;
  if (!tid) {
    tid = (
      await pool.request()
        .input("name", sql.NVarChar(200), TENANT_NAME)
        .input("slug", sql.NVarChar(200), TENANT_SLUG)
        .query<{ id: string }>(`INSERT INTO dbo.tenants (name, slug) OUTPUT INSERTED.id VALUES (@name, @slug)`)
    ).recordset[0].id;
  }

  // Workspace (by tenant + name)
  let wid = (
    await pool.request()
      .input("tid", sql.UniqueIdentifier, tid)
      .input("name", sql.NVarChar(200), WORKSPACE_NAME)
      .query<{ id: string }>(`SELECT id FROM dbo.workspaces WHERE tenant_id = @tid AND name = @name`)
  ).recordset[0]?.id;
  if (!wid) {
    wid = (
      await pool.request()
        .input("tid", sql.UniqueIdentifier, tid)
        .input("name", sql.NVarChar(200), WORKSPACE_NAME)
        .query<{ id: string }>(`INSERT INTO dbo.workspaces (tenant_id, name) OUTPUT INSERTED.id VALUES (@tid, @name)`)
    ).recordset[0].id;
  }

  for (const u of USERS) {
    // Idempotency: drop any existing user with this email + dependent rows.
    const existing = (
      await pool.request().input("email", sql.NVarChar(320), u.email)
        .query<{ id: string }>(`SELECT id FROM dbo.users WHERE email = @email`)
    ).recordset[0]?.id;
    if (existing) {
      for (const t of ["dbo.user_workspace", "dbo.user_org_roles", "dbo.login_session"]) {
        await pool.request().input("uid", sql.UniqueIdentifier, existing).query(`DELETE FROM ${t} WHERE user_id = @uid`);
      }
      await pool.request().input("uid", sql.UniqueIdentifier, existing).query(`DELETE FROM dbo.users WHERE id = @uid`);
    }

    const hash = await hashPassword(u.password);
    const uid = (
      await pool.request()
        .input("email", sql.NVarChar(320), u.email)
        .input("hash", sql.NVarChar(sql.MAX), hash)
        .input("name", sql.NVarChar(200), u.name)
        .query<{ id: string }>(`INSERT INTO dbo.users (email, password_hash, name) OUTPUT INSERTED.id VALUES (@email, @hash, @name)`)
    ).recordset[0].id;

    await pool.request()
      .input("uid", sql.UniqueIdentifier, uid)
      .input("tid", sql.UniqueIdentifier, tid)
      .input("role", sql.NVarChar(20), u.orgRole)
      .query(`INSERT INTO dbo.user_org_roles (user_id, tenant_id, org_role) VALUES (@uid, @tid, @role)`);

    await pool.request()
      .input("uid", sql.UniqueIdentifier, uid)
      .input("wid", sql.UniqueIdentifier, wid)
      .input("role", sql.NVarChar(20), u.wsRole)
      .query(`INSERT INTO dbo.user_workspace (user_id, workspace_id, role) VALUES (@uid, @wid, @role)`);

    console.log(`  seeded ${u.email}  org_role=${u.orgRole}  ws_role=${u.wsRole}`);
  }

  console.log(`\nDONE. tenant_id=${tid}  workspace_id=${wid}`);
  process.exit(0);
}

main().catch((err) => {
  console.error("seed failed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
