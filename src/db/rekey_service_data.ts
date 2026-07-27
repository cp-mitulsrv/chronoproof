/**
 * rekey_service_data.ts — TEMPORARY one-off. Delete after use.
 *
 * Assigns a service's user-owned business data to the matching ChronoProof user,
 * by EMAIL join (local user_id → local users.email → ChronoProof users.id).
 *
 * SAFETY (no data loss):
 *   • ADD-ONLY: adds a `cp_user_id` column to each business table and backfills it.
 *     The original `user_id` columns are NEVER modified — so it's fully reversible
 *     (drop cp_user_id) and nothing is lost.
 *   • Idempotent — re-runnable (adds column if missing; only fills NULL cp_user_id).
 *   • DRY-RUN by default: reports tables + counts (mappable / orphan users), no writes.
 *   • Orphan rows (user_id with no matching ChronoProof user) are LEFT AS-IS (cp_user_id
 *     stays NULL) and reported — never dropped.
 *
 * Run AFTER migrate_service_users.ts has imported the users into ChronoProof.
 *
 * Usage:
 *   SOURCE_DB="<service ADO.NET conn str>" USERS_TABLE=users   bun run src/db/rekey_service_data.ts        # dry-run (scout)
 *   SOURCE_DB="..." USERS_TABLE=vc_user APPLY=true             bun run src/db/rekey_service_data.ts        # apply (truth)
 */
import mssql from "mssql";
import { getPool } from "./pool.js";

const SOURCE_DB = process.env.SOURCE_DB ?? "";
const USERS_TABLE = process.env.USERS_TABLE ?? ""; // 'users' (scout) | 'vc_user' (truth)
const APPLY = process.env.APPLY === "true";

if (!SOURCE_DB || !USERS_TABLE) {
  console.error("Set SOURCE_DB=<service conn str> and USERS_TABLE=users|vc_user. Optional: APPLY=true");
  process.exit(1);
}

function parseAdoNet(str: string): mssql.config {
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

async function main(): Promise<void> {
  console.log(`=== re-key ${USERS_TABLE}-owned data → ChronoProof user ids   [${APPLY ? "APPLY" : "DRY-RUN"}] ===`);
  const src = await new mssql.ConnectionPool(parseAdoNet(SOURCE_DB)).connect();

  // local user_id -> email
  const localUsers: Array<{ id: unknown; email: string | null }> =
    (await src.request().query(`SELECT id, email FROM dbo.${USERS_TABLE}`)).recordset;
  const localIdToEmail = new Map<string, string>();
  for (const u of localUsers) if (u.email) localIdToEmail.set(String(u.id), String(u.email).toLowerCase());

  // ChronoProof email -> id
  const cp = await getPool();
  const cpEmailToId = new Map<string, string>(
    (await cp.request().query(`SELECT id, LOWER(email) e FROM dbo.users`)).recordset.map((r: any) => [r.e as string, r.id as string])
  );

  // local user_id -> ChronoProof id (via email)
  const map = new Map<string, string>();
  for (const [lid, email] of localIdToEmail) {
    const cpid = cpEmailToId.get(email);
    if (cpid) map.set(lid, cpid);
  }
  console.log(`local users: ${localUsers.length} | mappable to ChronoProof (by email): ${map.size}`);
  if (map.size === 0) { console.error("No users map — run migrate_service_users.ts first."); process.exit(1); }

  // business tables that have a user_id column (excluding the users table itself)
  const tables: string[] = (await src.request().query(
    `SELECT TABLE_NAME FROM INFORMATION_SCHEMA.COLUMNS
     WHERE COLUMN_NAME='user_id' AND TABLE_SCHEMA='dbo' AND TABLE_NAME <> '${USERS_TABLE}'`
  )).recordset.map((r: any) => String(r.TABLE_NAME));
  console.log(`business tables with a user_id column: ${tables.length}\n`);

  for (const t of tables) {
    const total = (await src.request().query(`SELECT COUNT(*) n FROM dbo.[${t}]`)).recordset[0].n;
    const distinctUsers: string[] = (await src.request().query(`SELECT DISTINCT user_id FROM dbo.[${t}] WHERE user_id IS NOT NULL`))
      .recordset.map((r: any) => String(r.user_id));
    const orphanUsers = distinctUsers.filter((u) => !map.has(u)).length;

    if (!APPLY) {
      console.log(`  ${t}: rows=${total}, distinct users=${distinctUsers.length}, mappable=${distinctUsers.length - orphanUsers}, orphan-users=${orphanUsers}`);
      continue;
    }

    await src.request().query(`IF COL_LENGTH('dbo.${t}','cp_user_id') IS NULL ALTER TABLE dbo.[${t}] ADD cp_user_id UNIQUEIDENTIFIER NULL`);
    let updated = 0;
    for (const [lid, cpid] of map) {
      const r = await src.request()
        .input("cp", mssql.UniqueIdentifier, cpid)
        .input("lid", mssql.UniqueIdentifier, lid)
        .query(`UPDATE dbo.[${t}] SET cp_user_id=@cp WHERE user_id=@lid AND cp_user_id IS NULL`);
      updated += r.rowsAffected[0] ?? 0;
    }
    console.log(`  ${t}: cp_user_id filled on ${updated} rows; ${orphanUsers} orphan-user(s) left NULL (originals untouched)`);
  }

  await src.close();
  console.log(`\n${APPLY ? "APPLIED — add-only, original user_id columns untouched." : "DRY-RUN complete — no writes."}`);
  process.exit(0);
}

main().catch((e) => { console.error("REKEY FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
