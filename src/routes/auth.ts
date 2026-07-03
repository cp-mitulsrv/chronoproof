import express from "express";
import type { Request, Response, NextFunction } from "express";
import { sql, withTransaction } from "../db/pool.js";
import { hashPassword, verifyPassword, needsRehash } from "../services/passwordService.js";
import { signAccessToken } from "../services/tokenService.js";
import * as sessionService from "../services/sessionService.js";
import { findUserByEmail, listUserWorkspaces, getWorkspaceMembership } from "../db/repo.js";
import { requireAuth } from "../middleware/auth.js";
import config from "../config/index.js";
import { getPool } from "../db/pool.js";

const router = express.Router();
const REFRESH_COOKIE = "chrono_refresh";

function setRefreshCookie(res: Response, token: string): void {
  res.cookie(REFRESH_COOKIE, token, {
    httpOnly: true,
    secure: true,
    // "none" so the browser sends the refresh cookie on cross-origin fetch()
    // from the frontend (different origin than the API). Requires secure:true.
    sameSite: "none",
    domain: config.cookieDomain,
    path: "/auth",
    maxAge: config.refreshTokenTtlDays * 24 * 60 * 60 * 1000,
  });
}
function clearRefreshCookie(res: Response): void {
  // Match the set attributes so logout reliably clears it in modern browsers.
  res.clearCookie(REFRESH_COOKIE, { domain: config.cookieDomain, path: "/auth", secure: true, sameSite: "none" });
}

async function issueSession(
  res: Response,
  req: Request,
  params: { userId: string; tenantId: string; workspaceId: string; role: "owner" | "member"; orgRole: "owner" | "admin" | "member" }
): Promise<string> {
  const { sessionId, refreshToken } = await sessionService.createSession({
    userId: params.userId,
    activeWorkspaceId: params.workspaceId,
    deviceLabel: (req.headers["user-agent"] || "").slice(0, 200) || null,
    ipAddress: req.ip ?? null,
  });
  setRefreshCookie(res, refreshToken);
  return signAccessToken({ ...params, sessionId });
}

function slugify(name: string): string {
  const base = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return `${base || "org"}-${Date.now().toString(36)}`;
}

// POST /auth/register — new signup: creates user + org(tenant) + first workspace,
// caller becomes org owner AND workspace owner. Atomic.
router.post("/register", async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password, name, organizationName, workspaceName } = req.body || {};
    if (!email || !password || !name || !organizationName) {
      return res
        .status(400)
        .json({ message: "email, password, name and organizationName are required" });
    }
    if (await findUserByEmail(email)) {
      return res.status(409).json({ message: "Email already registered" });
    }
    const passwordHash = await hashPassword(password as string);

    const created = await withTransaction(async (tx) => {
      const u = await new sql.Request(tx)
        .input("email", sql.NVarChar(320), email)
        .input("hash", sql.NVarChar(sql.MAX), passwordHash)
        .input("name", sql.NVarChar(200), name)
        .query<{ id: string }>(`INSERT INTO dbo.users (email, password_hash, name) OUTPUT INSERTED.id VALUES (@email, @hash, @name)`);
      const userId = u.recordset[0].id;

      const t = await new sql.Request(tx)
        .input("name", sql.NVarChar(200), organizationName)
        .input("slug", sql.NVarChar(200), slugify(organizationName as string))
        .query<{ id: string }>(`INSERT INTO dbo.tenants (name, slug) OUTPUT INSERTED.id VALUES (@name, @slug)`);
      const tenantId = t.recordset[0].id;

      const w = await new sql.Request(tx)
        .input("tid", sql.UniqueIdentifier, tenantId)
        .input("name", sql.NVarChar(200), workspaceName || "Default")
        .query<{ id: string }>(`INSERT INTO dbo.workspaces (tenant_id, name) OUTPUT INSERTED.id VALUES (@tid, @name)`);
      const workspaceId = w.recordset[0].id;

      await new sql.Request(tx)
        .input("uid", sql.UniqueIdentifier, userId)
        .input("tid", sql.UniqueIdentifier, tenantId)
        .query(`INSERT INTO dbo.user_org_roles (user_id, tenant_id, org_role) VALUES (@uid, @tid, 'owner')`);
      await new sql.Request(tx)
        .input("uid", sql.UniqueIdentifier, userId)
        .input("wid", sql.UniqueIdentifier, workspaceId)
        .query(`INSERT INTO dbo.user_workspace (user_id, workspace_id, role) VALUES (@uid, @wid, 'owner')`);

      return { userId, tenantId, workspaceId };
    });

    const accessToken = await issueSession(res, req, {
      userId: created.userId,
      tenantId: created.tenantId,
      workspaceId: created.workspaceId,
      role: "owner",
      orgRole: "owner",
    });
    return res.status(201).json({
      accessToken,
      user: { id: created.userId, email, name },
      tenant: { id: created.tenantId, name: organizationName },
      workspace: { id: created.workspaceId, name: workspaceName || "Default" },
      role: "owner",
      orgRole: "owner",
    });
  } catch (err) {
    next(err);
  }
});

// POST /auth/login — password check + workspace selection.
router.post("/login", async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password: passwordInput, workspaceId } = req.body || {};
    if (!email || !passwordInput) {
      return res.status(400).json({ message: "email and password are required" });
    }
    const user = await findUserByEmail(email as string);
    const ok = user && (await verifyPassword(passwordInput as string, user.password_hash));
    if (!ok) return res.status(401).json({ message: "Email or password is incorrect" });

    // Migrate legacy scrypt hash to argon2id on successful login.
    if (needsRehash(user.password_hash)) {
      const pool = await getPool();
      const newHash = await hashPassword(passwordInput as string);
      await pool
        .request()
        .input("hash", sql.NVarChar(sql.MAX), newHash)
        .input("id", sql.UniqueIdentifier, user.id)
        .query(`UPDATE dbo.users SET password_hash = @hash WHERE id = @id`);
    }

    const workspaces = await listUserWorkspaces(user.id);
    if (workspaces.length === 0) {
      return res.status(403).json({ message: "User belongs to no workspace" });
    }

    let chosen;
    if (workspaceId) {
      chosen = workspaces.find((w) => w.id === workspaceId);
      if (!chosen) return res.status(403).json({ message: "Not a member of that workspace" });
    } else if (workspaces.length === 1) {
      chosen = workspaces[0];
    } else {
      // No token, no cookie until a workspace is chosen.
      return res.json({
        needsWorkspaceSelection: true,
        workspaces: workspaces.map((w) => ({ id: w.id, name: w.name })),
      });
    }

    const m = await getWorkspaceMembership(user.id, chosen.id);
    if (!m) return res.status(403).json({ message: "Workspace membership missing" });
    const accessToken = await issueSession(res, req, {
      userId: user.id,
      tenantId: m.tenant_id,
      workspaceId: chosen.id,
      role: m.ws_role,
      orgRole: m.org_role,
    });
    return res.json({
      accessToken,
      user: { id: user.id, email: user.email, name: user.name },
      workspace: { id: chosen.id, name: chosen.name },
      role: m.ws_role,
      orgRole: m.org_role,
    });
  } catch (err) {
    next(err);
  }
});

// POST /auth/token/refresh — rotate refresh token, re-issue access token.
router.post("/token/refresh", async (req: Request, res: Response, next: NextFunction) => {
  try {
    const presented = req.cookies && (req.cookies[REFRESH_COOKIE] as string | undefined);
    if (!presented) return res.status(401).json({ message: "Missing refresh token" });

    const rotated = await sessionService.rotateSession(presented);
    if (!rotated) {
      clearRefreshCookie(res);
      return res.status(401).json({ message: "Invalid or expired session" });
    }
    const m = await getWorkspaceMembership(rotated.userId, rotated.activeWorkspaceId);
    if (!m) {
      clearRefreshCookie(res);
      return res.status(401).json({ message: "Workspace membership missing" });
    }
    setRefreshCookie(res, rotated.refreshToken);
    const accessToken = signAccessToken({
      userId: rotated.userId,
      tenantId: m.tenant_id,
      workspaceId: rotated.activeWorkspaceId,
      role: m.ws_role,
      orgRole: m.org_role,
      sessionId: rotated.sessionId,
    });
    return res.json({ accessToken });
  } catch (err) {
    next(err);
  }
});

// POST /auth/switch-workspace — re-issue an access token for another workspace
// the user belongs to (server-side membership check).
router.post("/switch-workspace", requireAuth(), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { workspaceId } = req.body || {};
    if (!workspaceId) return res.status(400).json({ message: "workspaceId is required" });
    const m = await getWorkspaceMembership(req.user!.userId, workspaceId as string);
    if (!m) return res.status(403).json({ message: "Not a member of that workspace" });
    await sessionService.setActiveWorkspace(req.user!.sessionId, workspaceId as string);
    const accessToken = signAccessToken({
      userId: req.user!.userId,
      tenantId: m.tenant_id,
      workspaceId: workspaceId as string,
      role: m.ws_role,
      orgRole: m.org_role,
      sessionId: req.user!.sessionId,
    });
    return res.json({ accessToken, workspace: { id: workspaceId }, role: m.ws_role, orgRole: m.org_role });
  } catch (err) {
    next(err);
  }
});

// POST /auth/logout — revoke current session.
router.post("/logout", requireAuth(), async (req: Request, res: Response, next: NextFunction) => {
  try {
    await sessionService.revokeSession(req.user!.sessionId);
    clearRefreshCookie(res);
    return res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// POST /auth/logout-all — revoke all of the user's sessions.
router.post("/logout-all", requireAuth(), async (req: Request, res: Response, next: NextFunction) => {
  try {
    await sessionService.revokeAllSessions(req.user!.userId);
    clearRefreshCookie(res);
    return res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

export default router;
