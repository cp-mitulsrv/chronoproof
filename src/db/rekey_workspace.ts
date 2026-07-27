/**
 * rekey_workspace.ts — TEMPORARY one-off. Assign a ChronoTruth workspace's data to a
 * ChronoProof user's workspace, so the ChronoProof login sees it. Delete after use.
 *
 * ChronoTruth data is WORKSPACE-scoped, and its backend already reads `cp_workspace_id`
 * for ChronoProof tokens. So this sets:
 *     cp_workspace_id = <ChronoProof user's wsid>   WHERE workspace_id = <source user's workspace>
 * on every workspace-scoped table. After this, a ChronoProof login sees that workspace's data.
 *
 * Example: Truth `admin@chronotruth.dev`'s workspace → ChronoProof `owner@chronoproof.test`.
 *
 * SAFETY: ADD-ONLY (nullable cp_workspace_id + UPDATE); original workspace_id untouched.
 * DRY-RUN by default. Idempotent.
 *
 * Usage:
 *   SOURCE_DB="<truth conn>" SOURCE_EMAIL=admin@chronotruth.dev CP_EMAIL=owner@chronoproof.test bun run src/db/rekey_workspace.ts
 *   ... APPLY=true ...
 */
import mssql from "mssql";
import { getPool } from "./pool.js";

const SOURCE_DB = process.env.SOURCE_DB ?? "";
const SOURCE_EMAIL = (process.env.SOURCE_EMAIL ?? "").toLowerCase();
const CP_EMAIL = (process.env.CP_EMAIL ?? "").toLowerCase();
const APPLY = process.env.APPLY === "true";
const USERS_TABLE = process.env.USERS_TABLE ?? "vc_user"; // Truth's user table

if (!SOURCE_DB || !SOURCE_EMAIL || !CP_EMAIL) {
  console.error("Set SOURCE_DB, SOURCE_EMAIL, CP_EMAIL. Optional: APPLY=true, USERS_TABLE (default vc_user)");
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
  console.log(`=== re-key ${SOURCE_EMAIL}'s workspace → ChronoProof ${CP_EMAIL}'s wsid   [${APPLY ? "APPLY" : "DRY-RUN"}] ===`);
  const src = await new mssql.ConnectionPool(parseAdoNet(SOURCE_DB)).connect();

  const localWsId: string | undefined = (await src.request().input("e", mssql.NVarChar, SOURCE_EMAIL)
    .query(`SELECT workspace_id FROM dbo.${USERS_TABLE} WHERE LOWER(email)=@e`)).recordset[0]?.workspace_id;
  if (!localWsId) { console.error(`No workspace_id for ${SOURCE_EMAIL} in dbo.${USERS_TABLE}.`); process.exit(1); }

  const cp = await getPool();
  const cpWsId: string | undefined = (await cp.request().input("e", mssql.NVarChar, CP_EMAIL).query(
    `SELECT TOP 1 uw.workspace_id AS wsid
     FROM dbo.users u JOIN dbo.user_workspace uw ON uw.user_id = u.id
     WHERE LOWER(u.email)=@e ORDER BY uw.workspace_id`
  )).recordset[0]?.wsid;
  if (!cpWsId) { console.error(`No ChronoProof workspace for ${CP_EMAIL} — create/migrate it first.`); process.exit(1); }

  console.log(`Truth workspace_id:          ${localWsId}`);
  console.log(`→ ChronoProof cp_workspace_id: ${cpWsId}\n`);

  const tables: string[] = (await src.request().query(
    `SELECT TABLE_NAME FROM INFORMATION_SCHEMA.COLUMNS
     WHERE COLUMN_NAME='workspace_id' AND TABLE_SCHEMA='dbo' AND TABLE_NAME <> '${USERS_TABLE}'`
  )).recordset.map((r: any) => String(r.TABLE_NAME));

  let totalRows = 0;
  for (const t of tables) {
    const n = (await src.request().input("w", mssql.UniqueIdentifier, localWsId)
      .query(`SELECT COUNT(*) n FROM dbo.[${t}] WHERE workspace_id=@w`)).recordset[0].n;
    if (n === 0) continue;
    totalRows += n;
    if (!APPLY) { console.log(`  ${t}: ${n} rows would get cp_workspace_id`); continue; }
    await src.request().query(`IF COL_LENGTH('dbo.${t}','cp_workspace_id') IS NULL ALTER TABLE dbo.[${t}] ADD cp_workspace_id UNIQUEIDENTIFIER NULL`);
    const r = await src.request()
      .input("cp", mssql.UniqueIdentifier, cpWsId)
      .input("w", mssql.UniqueIdentifier, localWsId)
      .query(`UPDATE dbo.[${t}] SET cp_workspace_id=@cp WHERE workspace_id=@w`);
    console.log(`  ${t}: cp_workspace_id set on ${r.rowsAffected[0]} rows`);
  }

  await src.close();
  console.log(`\n${APPLY ? "APPLIED" : "DRY-RUN"} — ${totalRows} row(s) across ${tables.length} workspace-scoped table(s). Original workspace_id untouched.`);
  if (!APPLY) console.log("Re-run with APPLY=true to write.");
  process.exit(0);
}

main().catch((e) => { console.error("REKEY FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
