import fs from "fs";
import path from "path";
import { getPool } from "./pool.js";

async function migrate(): Promise<void> {
  const dir = path.join(import.meta.dir, "migrations");
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
  const pool = await getPool();
  for (const file of files) {
    const sqlText = fs.readFileSync(path.join(dir, file), "utf8");
    console.log(`applying ${file} ...`);
    await pool.request().batch(sqlText);
  }
  console.log(`migrations complete (${files.length} file(s))`);
}

if (import.meta.main) {
  migrate()
    .then(() => process.exit(0))
    .catch((err: unknown) => {
      console.error(err);
      process.exit(1);
    });
}

export { migrate };
