import express from "express";
import type { Request, Response, NextFunction } from "express";
import { sql, getPool, withTransaction } from "../db/pool.js";
import { requireAuth, requireOrgRole } from "../middleware/auth.js";
import { listUserWorkspaces } from "../db/repo.js";

const router = express.Router();

// GET /workspaces — workspaces the caller belongs to.
router.get("/", requireAuth(), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const rows = await listUserWorkspaces(req.user!.userId);
    res.json({
      workspaces: rows.map((w) => ({ id: w.id, name: w.name, tenantId: w.tenant_id, role: w.role })),
    });
  } catch (err) {
    next(err);
  }
});

// POST /workspaces — create a workspace in the caller's org (org owner/admin).
// The caller becomes the new workspace's owner.
router.post("/", requireAuth(), requireOrgRole("owner", "admin"), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name } = req.body || {};
    if (!name) return res.status(400).json({ message: "name is required" });
    const tenantId = req.user!.tenantId;
    const workspaceId = await withTransaction(async (tx) => {
      const w = await new sql.Request(tx)
        .input("tid", sql.UniqueIdentifier, tenantId)
        .input("name", sql.NVarChar(200), name as string)
        .query<{ id: string }>(`INSERT INTO dbo.workspaces (tenant_id, name) OUTPUT INSERTED.id VALUES (@tid, @name)`);
      const id = w.recordset[0].id;
      await new sql.Request(tx)
        .input("uid", sql.UniqueIdentifier, req.user!.userId)
        .input("wid", sql.UniqueIdentifier, id)
        .query(`INSERT INTO dbo.user_workspace (user_id, workspace_id, role) VALUES (@uid, @wid, 'owner')`);
      return id;
    });
    res.status(201).json({ workspace: { id: workspaceId, name, tenantId } });
  } catch (err) {
    next(err);
  }
});

// GET /workspaces/:id/members — members of a workspace the caller belongs to.
router.get("/:id/members", requireAuth(), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = await getPool();
    const mem = await pool
      .request()
      .input("uid", sql.UniqueIdentifier, req.user!.userId)
      .input("wid", sql.UniqueIdentifier, req.params.id)
      .query(`SELECT 1 AS ok FROM dbo.user_workspace WHERE user_id = @uid AND workspace_id = @wid`);
    if (mem.recordset.length === 0) {
      return res.status(403).json({ message: "Not a member of that workspace" });
    }
    const r = await pool
      .request()
      .input("wid", sql.UniqueIdentifier, req.params.id)
      .query(
        `SELECT u.id, u.email, u.name, uw.role
         FROM dbo.user_workspace uw
         JOIN dbo.users u ON u.id = uw.user_id
         WHERE uw.workspace_id = @wid
         ORDER BY u.name`
      );
    res.json({ members: r.recordset });
  } catch (err) {
    next(err);
  }
});

export default router;
