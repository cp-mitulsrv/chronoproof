import sql from "mssql";
import config from "../config/index.js";

let poolPromise: Promise<sql.ConnectionPool> | null = null;

export async function getPool(): Promise<sql.ConnectionPool> {
  if (!poolPromise) {
    poolPromise = sql
      .connect({
        server: config.db.server,
        port: config.db.port,
        database: config.db.database,
        user: config.db.user,
        password: config.db.password,
        options: config.db.options,
        pool: { max: 10, min: 0, idleTimeoutMillis: 30000 },
      })
      .catch((err: unknown) => {
        poolPromise = null;
        throw err;
      });
  }
  return poolPromise;
}

/** Run a parameterized query. `params` is an object of { name: value }. */
export async function query(text: string, params: Record<string, unknown> = {}): Promise<sql.IResult<unknown>> {
  const pool = await getPool();
  const request = pool.request();
  for (const [name, value] of Object.entries(params)) request.input(name, value);
  return request.query(text);
}

/** Run `fn(tx)` inside a transaction, committing on success and rolling back on error. */
export async function withTransaction<T>(fn: (tx: sql.Transaction) => Promise<T>): Promise<T> {
  const pool = await getPool();
  const tx = new sql.Transaction(pool);
  await tx.begin();
  try {
    const result = await fn(tx);
    await tx.commit();
    return result;
  } catch (err) {
    try {
      await tx.rollback();
    } catch {
      /* rollback failure is secondary to the original error */
    }
    throw err;
  }
}

export { sql };
