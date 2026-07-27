/**
 * migrate_service_users.ts — TEMPORARY one-off script.
 * Imports a product service's users into ChronoProof's `users` table. Delete after use.
 *
 * SAFETY (no data loss):
 *   • Reads the source service DB READ-ONLY — it NEVER modifies the source.
 *   • Only ADDS to ChronoProof: users (deduped by EMAIL) + org/workspace membership.
 *   • Idempotent — find-or-create by email; safe to re-run.
 *   • DRY-RUN by default: prints COUNTS only (no writes, no emails printed).
 *
 * No extra tables: email is the join key. Later, re-keying each service's business
 * data is `local_user_id → email → chronoproof_user_id` (email join) — no mapping table.
 *
 * Usage:
 *   # dry-run (read-only, counts only)
 *   SOURCE=scout SOURCE_DB="<source ADO.NET conn str>" bun run src/db/migrate_service_users.ts
 *   # apply (additive writes to ChronoProof only)
 *   SOURCE=scout SOURCE_DB="..." ORG_NAME="ChronoScout" APPLY=true bun run src/db/migrate_service_users.ts
 */
import mssql from "mssql";
import crypto from "crypto";
import { getPool, sql } from "./pool.js";
import { hashPassword } from "../services/passwordService.js";

const SOURCE = (process.env.SOURCE ?? "").toLowerCase();
const SOURCE_DB = process.env.SOURCE_DB ?? "";
const APPLY = process.env.APPLY === "true";
const SOURCE_TABLE = SOURCE === "scout" ? "users" : SOURCE === "truth" ? "vc_user" : "";
const ORG_NAME = process.env.ORG_NAME ?? (SOURCE === "scout" ? "ChronoScout" : "ChronoTruth");
const WORKSPACE_NAME = process.env.WORKSPACE_NAME ?? "Default";

if (!SOURCE_TABLE || !SOURCE_DB) {
  console.error("Set SOURCE=scout|truth and SOURCE_DB=<ADO.NET connection string>. Optional: APPLY=true, ORG_NAME, WORKSPACE_NAME");
  process.exit(1);
}

function parseAdoNet(str: string): mssql.config {
  str = str.trim().replace(/^['"]+|['"]+$/g, ""); // tolerate a value that's quoted in .env
  const m: Record<string, string> = {};
  for (const part of str.split(";").map((s) => s.trim()).filter(Boolean)) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    m[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  let server = (m["server"] ?? m["data source"] ?? "").replace(/^tcp:/i, "");
  let port = 1433;
  const c = server.indexOf(",");
  if (c !== -1) { port = Number(server.slice(c + 1)) || 1433; server = server.slice(0, c); }
  const enc = (m["encrypt"] ?? "true").toLowerCase();
  return {
    server, port,
    database: m["database"] ?? m["initial catalog"] ?? "",
    user: m["uid"] ?? m["user id"] ?? m["user"] ?? "",
    password: m["pwd"] ?? m["password"] ?? "",
    options: { encrypt: enc !== "false" && enc !== "no", trustServerCertificate: (m["trustservercertificate"] ?? "false").toLowerCase() === "true" },
    connectionTimeout: 20000,
  };
}

const slugify = (name: string) => name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "org";

async function main(): Promise<void> {
  console.log(`=== migrate ${SOURCE} → ChronoProof   [${APPLY ? "APPLY" : "DRY-RUN"}] ===`);

  const src = await new mssql.ConnectionPool(parseAdoNet(SOURCE_DB)).connect();
  const cols: string[] = (
    await src.request().query(`SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='${SOURCE_TABLE}'`)
  ).recordset.map((r: any) => String(r.COLUMN_NAME));
  if (cols.length === 0) { console.error(`Source table dbo.${SOURCE_TABLE} not found.`); process.exit(1); }
  const lc = cols.map((c) => c.toLowerCase());
  const emailCol = cols[lc.indexOf("email")] ?? "email";
  const nameIdx = lc.findIndex((c) => ["name", "full_name", "fullname", "display_name"].includes(c));
  const selectName = nameIdx >= 0 ? `, [${cols[nameIdx]}] AS name` : `, NULL AS name`;

  const rows: Array<{ email: string | null; name: string | null }> = (
    await src.request().query(`SELECT [${emailCol}] AS email ${selectName} FROM dbo.${SOURCE_TABLE}`)
  ).recordset;
  await src.close();

  const total = rows.length;
  const withEmail = rows.filter((r) => r.email && String(r.email).trim());
  // Dedup within source by email (multiple local rows with the same email → one ChronoProof user).
  const byEmail = new Map<string, string | null>();
  for (const r of withEmail) {
    const k = String(r.email).trim().toLowerCase();
    if (!byEmail.has(k)) byEmail.set(k, r.name ? String(r.name) : null);
  }

  const cp = await getPool();
  const cpEmails = new Set<string>((await cp.request().query(`SELECT LOWER(email) e FROM dbo.users`)).recordset.map((r: any) => r.e as string));
  const reuse = [...byEmail.keys()].filter((e) => cpEmails.has(e)).length;

  console.log(`source rows:              ${total}`);
  console.log(`  skipped (no email):     ${total - withEmail.length}`);
  console.log(`  distinct emails:        ${byEmail.size}`);
  console.log(`  already in ChronoProof: ${reuse}`);
  console.log(`  new (would create):     ${byEmail.size - reuse}`);

  if (!APPLY) {
    console.log(`\nDRY-RUN complete — nothing written. Re-run with APPLY=true to migrate.`);
    process.exit(0);
  }

  // ── APPLY (additive to ChronoProof `users` + org/workspace membership only) ──
  let tid = (await cp.request().input("slug", sql.NVarChar(200), slugify(ORG_NAME)).query<{ id: string }>(`SELECT id FROM dbo.tenants WHERE slug=@slug`)).recordset[0]?.id;
  if (!tid) tid = (await cp.request().input("n", sql.NVarChar(200), ORG_NAME).input("s", sql.NVarChar(200), slugify(ORG_NAME)).query<{ id: string }>(`INSERT INTO dbo.tenants (name, slug) OUTPUT INSERTED.id VALUES (@n,@s)`)).recordset[0].id;
  let wid = (await cp.request().input("tid", sql.UniqueIdentifier, tid).input("n", sql.NVarChar(200), WORKSPACE_NAME).query<{ id: string }>(`SELECT id FROM dbo.workspaces WHERE tenant_id=@tid AND name=@n`)).recordset[0]?.id;
  if (!wid) wid = (await cp.request().input("tid", sql.UniqueIdentifier, tid).input("n", sql.NVarChar(200), WORKSPACE_NAME).query<{ id: string }>(`INSERT INTO dbo.workspaces (tenant_id, name) OUTPUT INSERTED.id VALUES (@tid,@n)`)).recordset[0].id;

  let created = 0, reused = 0;
  for (const [email, name] of byEmail) {
    let uid = (await cp.request().input("e", sql.NVarChar(320), email).query<{ id: string }>(`SELECT id FROM dbo.users WHERE LOWER(email)=@e`)).recordset[0]?.id;
    if (!uid) {
      const hash = await hashPassword(crypto.randomBytes(24).toString("hex")); // random → user must reset
      uid = (await cp.request()
        .input("email", sql.NVarChar(320), email)
        .input("hash", sql.NVarChar(sql.MAX), hash)
        .input("name", sql.NVarChar(200), name ? name.slice(0, 200) : email.split("@")[0])
        .query<{ id: string }>(`INSERT INTO dbo.users (email, password_hash, name) OUTPUT INSERTED.id VALUES (@email,@hash,@name)`)).recordset[0].id;
      created++;
    } else {
      reused++;
    }
    await cp.request().input("uid", sql.UniqueIdentifier, uid).input("tid", sql.UniqueIdentifier, tid)
      .query(`IF NOT EXISTS (SELECT 1 FROM dbo.user_org_roles WHERE user_id=@uid AND tenant_id=@tid) INSERT INTO dbo.user_org_roles (user_id, tenant_id, org_role) VALUES (@uid,@tid,'member')`);
    await cp.request().input("uid", sql.UniqueIdentifier, uid).input("wid", sql.UniqueIdentifier, wid)
      .query(`IF NOT EXISTS (SELECT 1 FROM dbo.user_workspace WHERE user_id=@uid AND workspace_id=@wid) INSERT INTO dbo.user_workspace (user_id, workspace_id, role) VALUES (@uid,@wid,'member')`);
  }

  // Integrity: every distinct source email must now exist in ChronoProof.
  const present = (await cp.request().query(`SELECT LOWER(email) e FROM dbo.users`)).recordset.map((r: any) => r.e as string);
  const presentSet = new Set(present);
  const missing = [...byEmail.keys()].filter((e) => !presentSet.has(e)).length;

  console.log(`\nAPPLIED: created=${created}, reused=${reused}`);
  console.log(`integrity: all ${byEmail.size} source emails present in ChronoProof ? ${missing === 0 ? "OK ✓" : `MISSING ${missing} ✗`}`);
  console.log(`NOTE: migrated users have a random password → they must reset it (enable a password-reset flow before cutover).`);
  process.exit(0);
}

main().catch((e) => { console.error("MIGRATION FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
