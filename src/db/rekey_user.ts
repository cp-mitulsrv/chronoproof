/**
 * rekey_user.ts — TEMPORARY one-off. Link ONE service user to a specific ChronoProof
 * user, so the service shows that user's data to the ChronoProof login. Delete after use.
 *
 * It sets `cp_user_id` on the service's user ROW:
 *     dbo.<USERS_TABLE>.cp_user_id = <ChronoProof user id>   WHERE email = SOURCE_EMAIL
 * The service's auth middleware then resolves an incoming ChronoProof token → this local
 * user, so every existing user_id-scoped query returns that user's data — no per-query
 * changes needed.
 *
 * Example: Scout `msadmin@yopmail.com` → ChronoProof `owner@chronoproof.test`.
 *
 * SAFETY: ADD-ONLY (a nullable column + one UPDATE). Original data untouched, reversible.
 * DRY-RUN by default. Idempotent.
 *
 * Usage:
 *   SOURCE_DB="<scout conn>" USERS_TABLE=users \
 *     SOURCE_EMAIL=msadmin@yopmail.com CP_EMAIL=owner@chronoproof.test \
 *     bun run src/db/rekey_user.ts                 # dry-run
 *   ... APPLY=true bun run src/db/rekey_user.ts    # apply
 */
import mssql from "mssql";
import { getPool } from "./pool.js";

const SOURCE_DB = process.env.SOURCE_DB ?? "";
const USERS_TABLE = process.env.USERS_TABLE ?? ""; // 'users' (scout) | 'vc_user' (truth)
const SOURCE_EMAIL = (process.env.SOURCE_EMAIL ?? "").toLowerCase();
const CP_EMAIL = (process.env.CP_EMAIL ?? "").toLowerCase();
const APPLY = process.env.APPLY === "true";

if (!SOURCE_DB || !USERS_TABLE || !SOURCE_EMAIL || !CP_EMAIL) {
  console.error("Set SOURCE_DB, USERS_TABLE=users|vc_user, SOURCE_EMAIL, CP_EMAIL. Optional: APPLY=true");
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

async function main(): Promise<void> {
  console.log(`=== link ${SOURCE_EMAIL} → ChronoProof ${CP_EMAIL}   [${APPLY ? "APPLY" : "DRY-RUN"}] ===`);
  const src = await new mssql.ConnectionPool(parseAdoNet(SOURCE_DB)).connect();

  const localId: string | undefined = (await src.request().input("e", mssql.NVarChar, SOURCE_EMAIL)
    .query(`SELECT id FROM dbo.${USERS_TABLE} WHERE LOWER(email)=@e`)).recordset[0]?.id;
  if (!localId) { console.error(`Source user ${SOURCE_EMAIL} not found in dbo.${USERS_TABLE}.`); process.exit(1); }

  const cp = await getPool();
  const cpId: string | undefined = (await cp.request().input("e", mssql.NVarChar, CP_EMAIL)
    .query(`SELECT id FROM dbo.users WHERE LOWER(email)=@e`)).recordset[0]?.id;
  if (!cpId) { console.error(`ChronoProof user ${CP_EMAIL} not found — create/migrate it first.`); process.exit(1); }

  console.log(`local user id:        ${localId}`);
  console.log(`ChronoProof user id:  ${cpId}`);

  if (!APPLY) {
    console.log(`\nDRY-RUN — would set dbo.${USERS_TABLE}.cp_user_id = ${cpId} on the ${SOURCE_EMAIL} row.`);
    console.log(`Re-run with APPLY=true to write.`);
    process.exit(0);
  }

  await src.request().query(`IF COL_LENGTH('dbo.${USERS_TABLE}','cp_user_id') IS NULL ALTER TABLE dbo.[${USERS_TABLE}] ADD cp_user_id UNIQUEIDENTIFIER NULL`);
  const r = await src.request()
    .input("cp", mssql.UniqueIdentifier, cpId)
    .input("lid", mssql.UniqueIdentifier, localId)
    .query(`UPDATE dbo.[${USERS_TABLE}] SET cp_user_id=@cp WHERE id=@lid`);
  await src.close();

  console.log(`\nAPPLIED — dbo.${USERS_TABLE}.cp_user_id set on ${r.rowsAffected[0]} row.`);
  console.log(`The service's auth middleware will now resolve ChronoProof user ${cpId} → local user ${localId}.`);
  process.exit(0);
}

main().catch((e) => { console.error("REKEY FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
