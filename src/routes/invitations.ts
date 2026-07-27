import express from "express";
import type { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { sql, getPool, withTransaction } from "../db/pool.js";
import { requireAuth, requireWorkspaceRole } from "../middleware/auth.js";
import { hashPassword } from "../services/passwordService.js";
import { findUserByEmail } from "../db/repo.js";
import { sendInvitationEmail } from "../services/emailService.js";
import config from "../config/index.js";

const router = express.Router();

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// POST /workspaces/:id/invitations — invite an email to the caller's ACTIVE
// workspace as owner|member. Workspace owner only. Returns the token so the
// caller can email the accept link (email delivery is out of scope here).
router.post(
  "/workspaces/:id/invitations",
  requireAuth(),
  requireWorkspaceRole("owner"),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, role } = req.body || {};
      if (!email || !["owner", "member"].includes(role as string)) {
        return res.status(400).json({ message: "email and role ('owner'|'member') are required" });
      }
      if (req.params.id !== req.user!.workspaceId) {
        return res.status(403).json({ message: "You can only invite to your active workspace" });
      }
      const token = crypto.randomBytes(32).toString("base64url");
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      const pool = await getPool();
      await pool
        .request()
        .input("wid", sql.UniqueIdentifier, req.params.id)
        .input("email", sql.NVarChar(320), email as string)
        .input("role", sql.NVarChar(20), role as string)
        .input("hash", sql.NVarChar(128), hashToken(token))
        .input("exp", sql.DateTime2, expiresAt)
        .query(
          `INSERT INTO dbo.invitations (workspace_id, email, role, token_hash, expires_at)
           VALUES (@wid, @email, @role, @hash, @exp)`
        );

      // Friendlier email: include the workspace name (best-effort lookup).
      const wsName = (
        await pool
          .request()
          .input("wid", sql.UniqueIdentifier, req.params.id)
          .query<{ name: string }>(`SELECT name FROM dbo.workspaces WHERE id = @wid`)
      ).recordset[0]?.name;

      const acceptUrl = `${config.appBaseUrl.replace(/\/$/, "")}/accept-invite?token=${token}`;
      const emailSent = await sendInvitationEmail({
        to: email as string,
        role: role as string,
        acceptUrl,
        workspaceName: wsName,
      });

      return res.status(201).json({
        invitation: { email, role, expiresAt, emailSent },
        // If email couldn't be delivered (SMTP off/failed), return the link + token
        // so the owner can share it manually. When emailed, we don't leak the token.
        ...(emailSent ? {} : { acceptUrl, token }),
      });
    } catch (err) {
      next(err);
    }
  }
);

interface InvitationRow {
  id: string;
  workspace_id: string;
  email: string;
  role: string;
  token_hash: string;
  expires_at: Date;
  status: string;
  tenant_id: string;
}

// POST /invitations/accept — accept an invite. Creates the user if new (needs
// name+password), joins the workspace with the invited role (owner|member),
// and ensures an org membership (member) exists.
router.post("/invitations/accept", async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token, name, password } = req.body || {};
    if (!token) return res.status(400).json({ message: "token is required" });

    const pool = await getPool();
    const inv = (
      await pool
        .request()
        .input("hash", sql.NVarChar(128), hashToken(token as string))
        .query<InvitationRow>(
          `SELECT i.*, w.tenant_id
           FROM dbo.invitations i
           JOIN dbo.workspaces w ON w.id = i.workspace_id
           WHERE i.token_hash = @hash`
        )
    ).recordset[0];

    if (!inv || inv.status !== "pending" || new Date(inv.expires_at) < new Date()) {
      return res.status(400).json({ message: "Invitation is invalid or expired" });
    }

    let user = await findUserByEmail(inv.email);

    await withTransaction(async (tx) => {
      if (!user) {
        if (!name || !password) {
          throw Object.assign(new Error("name and password are required for a new user"), {
            status: 400,
          });
        }
        const hash = await hashPassword(password as string);
        const u = await new sql.Request(tx)
          .input("email", sql.NVarChar(320), inv.email)
          .input("hash", sql.NVarChar(sql.MAX), hash)
          .input("name", sql.NVarChar(200), name as string)
          .query<{ id: string }>(`INSERT INTO dbo.users (email, password_hash, name) OUTPUT INSERTED.id VALUES (@email, @hash, @name)`);
        user = { id: u.recordset[0].id, email: inv.email, name: name as string, username: null, password_hash: hash, created_at: new Date() };
      }
      await new sql.Request(tx)
        .input("uid", sql.UniqueIdentifier, user.id)
        .input("tid", sql.UniqueIdentifier, inv.tenant_id)
        .query(
          `IF NOT EXISTS (SELECT 1 FROM dbo.user_org_roles WHERE user_id = @uid AND tenant_id = @tid)
             INSERT INTO dbo.user_org_roles (user_id, tenant_id, org_role) VALUES (@uid, @tid, 'member')`
        );
      await new sql.Request(tx)
        .input("uid", sql.UniqueIdentifier, user.id)
        .input("wid", sql.UniqueIdentifier, inv.workspace_id)
        .input("role", sql.NVarChar(20), inv.role)
        .query(
          `IF NOT EXISTS (SELECT 1 FROM dbo.user_workspace WHERE user_id = @uid AND workspace_id = @wid)
             INSERT INTO dbo.user_workspace (user_id, workspace_id, role) VALUES (@uid, @wid, @role)`
        );
      await new sql.Request(tx)
        .input("id", sql.UniqueIdentifier, inv.id)
        .query(`UPDATE dbo.invitations SET status = 'accepted' WHERE id = @id`);
    });

    return res.json({
      ok: true,
      workspaceId: inv.workspace_id,
      role: inv.role,
      user: { id: user!.id, email: inv.email },
    });
  } catch (err) {
    if ((err as { status?: number }).status) return res.status((err as { status: number }).status).json({ message: (err as Error).message });
    next(err);
  }
});

export default router;
