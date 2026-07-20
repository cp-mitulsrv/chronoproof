/**
 * backfill_truth_workspace.ts — TEMPORARY one-off. Delete after use.
 *
 * After the SSO migration, ChronoTruth scopes reads by `cp_workspace_id` (the ChronoProof
 * workspace from the token), but pre-existing rows have `cp_workspace_id = NULL` (they were
 * created with the internal `workspace_id`). So SSO users see EMPTY portfolio data.
 *
 * This stamps `cp_workspace_id` on EVERY currently-unowned row (cp_workspace_id IS NULL)
 * across all Truth tables that have the column, assigning them to ONE ChronoProof workspace
 * (default owner@chronoproof.test's) — so that SSO user sees the existing portfolio.
 * Deeper tables (compliance_finding, company_framework_score, …) have no own column and
 * become visible transitively via `company_id → portfolio_company.cp_workspace_id`.
 *
 * SAFETY: ADD-ONLY (fills a nullable column). DRY-RUN by default. Idempotent.
 *
 * Usage (run from the chronoproof repo root):
 *   TRUTH_DB="<truth ADO.NET conn>" bun run src/db/backfill_truth_workspace.ts            # dry-run
 *   TRUTH_DB="..." APPLY=true bun run src/db/backfill_truth_workspace.ts                   # write
 *   override target: CP_EMAIL=owner@chronoproof.test   or   TARGET_WSID=<guid>
 */
import mssql from "mssql";
import { getPool } from "./pool.js";

const TRUTH_DB = process.env.TRUTH_DB ?? process.env.SOURCE_DB ?? "";
const CP_EMAIL = (process.env.CP_EMAIL ?? "owner@chronoproof.test").toLowerCase();
const TARGET_WSID = process.env.TARGET_WSID ?? "";
const APPLY = process.env.APPLY === "true";

if (!TRUTH_DB) {
  console.error("Set TRUTH_DB=<ChronoTruth ADO.NET connection string>. Optional: APPLY=true, CP_EMAIL, TARGET_WSID");
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
  console.log(`=== backfill ChronoTruth cp_workspace_id → ${TARGET_WSID || CP_EMAIL}   [${APPLY ? "APPLY" : "DRY-RUN"}] ===`);

  // Resolve the target ChronoProof workspace id (unless given explicitly).
  let targetWsId = TARGET_WSID;
  if (!targetWsId) {
    const cp = await getPool();
    targetWsId = (await cp.request().input("e", mssql.NVarChar, CP_EMAIL).query(
      `SELECT TOP 1 uw.workspace_id AS wsid
       FROM dbo.users u JOIN dbo.user_workspace uw ON uw.user_id = u.id
       WHERE LOWER(u.email)=@e ORDER BY uw.workspace_id`
    )).recordset[0]?.wsid;
    if (!targetWsId) { console.error(`No ChronoProof workspace for ${CP_EMAIL} — pass TARGET_WSID instead.`); process.exit(1); }
  }
  console.log(`target cp_workspace_id: ${targetWsId}\n`);

  const src = await new mssql.ConnectionPool(parseAdoNet(TRUTH_DB)).connect();

  // Every Truth table that has a cp_workspace_id column.
  const tables: string[] = (await src.request().query(
    `SELECT TABLE_NAME FROM INFORMATION_SCHEMA.COLUMNS
     WHERE COLUMN_NAME='cp_workspace_id' AND TABLE_SCHEMA='dbo'`
  )).recordset.map((r: { TABLE_NAME: string }) => String(r.TABLE_NAME));

  if (tables.length === 0) {
    console.error("No tables with a cp_workspace_id column found — is migration 003 applied?");
    process.exit(1);
  }

  let total = 0;
  for (const t of tables) {
    const n = (await src.request().query(`SELECT COUNT(*) n FROM dbo.[${t}] WHERE cp_workspace_id IS NULL`)).recordset[0].n as number;
    if (n === 0) { console.log(`  ${t}: 0 unowned`); continue; }
    total += n;
    if (!APPLY) { console.log(`  ${t}: ${n} unowned row(s) would get cp_workspace_id`); continue; }
    const r = await src.request()
      .input("cp", mssql.UniqueIdentifier, targetWsId)
      .query(`UPDATE dbo.[${t}] SET cp_workspace_id=@cp WHERE cp_workspace_id IS NULL`);
    console.log(`  ${t}: cp_workspace_id set on ${r.rowsAffected[0]} row(s)`);
  }

  await src.close();
  console.log(`\n${APPLY ? "APPLIED" : "DRY-RUN"} — ${total} unowned row(s) across ${tables.length} table(s). Original data untouched.`);
  if (!APPLY) console.log("Re-run with APPLY=true to write.");
  process.exit(0);
}

main().catch((e) => { console.error("BACKFILL FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
