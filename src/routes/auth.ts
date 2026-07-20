import express from "express";
import type { Request, Response, NextFunction } from "express";
import { sql, withTransaction } from "../db/pool.js";
import { hashPassword, verifyPassword, needsRehash } from "../services/passwordService.js";
import { signAccessToken } from "../services/tokenService.js";
import * as sessionService from "../services/sessionService.js";
import {
  findUserByEmail,
  findUserById,
  findUserByUsername,
  findUserByIdentifier,
  listUserWorkspaces,
  getWorkspaceMembership,
} from "../db/repo.js";
import { requireAuth } from "../middleware/auth.js";
import config from "../config/index.js";
import { getPool } from "../db/pool.js";

const router = express.Router();
const REFRESH_COOKIE = "chrono_refresh";
// Username: 3-30 chars, lowercase letters/numbers/underscore. Login handle + display.
const USERNAME_RE = /^[a-z0-9_]{3,30}$/;

// Cookie security flags depend on the connection. Over HTTPS (production, possibly
// cross-domain) use SameSite=None + Secure. Over plain HTTP (local dev) the browser
// won't SEND a Secure cookie, so fall back to Lax + insecure (localhost is same-site).
function cookieFlags(req: Request): { secure: boolean; sameSite: "none" | "lax" } {
  const isHttps = req.secure || req.headers["x-forwarded-proto"] === "https";
  return isHttps ? { secure: true, sameSite: "none" } : { secure: false, sameSite: "lax" };
}

function setRefreshCookie(req: Request, res: Response, token: string): void {
  const { secure, sameSite } = cookieFlags(req);
  res.cookie(REFRESH_COOKIE, token, {
    httpOnly: true,
    secure,
    sameSite,
    domain: config.cookieDomain,
    path: "/auth",
    maxAge: config.refreshTokenTtlDays * 24 * 60 * 60 * 1000,
  });
}
function clearRefreshCookie(req: Request, res: Response): void {
  const { secure, sameSite } = cookieFlags(req);
  res.clearCookie(REFRESH_COOKIE, { domain: config.cookieDomain, path: "/auth", secure, sameSite });
}

async function issueSession(
  res: Response,
  req: Request,
  params: { userId: string; tenantId: string; workspaceId: string; role: "owner" | "member"; orgRole: "owner" | "admin" | "member"; username?: string | null; email?: string | null; name?: string | null }
): Promise<string> {
  const { sessionId, refreshToken } = await sessionService.createSession({
    userId: params.userId,
    activeWorkspaceId: params.workspaceId,
    deviceLabel: (req.headers["user-agent"] || "").slice(0, 200) || null,
    ipAddress: req.ip ?? null,
  });
  setRefreshCookie(req, res,refreshToken);
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
    const { email, password, name, username, organizationName, workspaceName } = req.body || {};
    if (!email || !password || !name || !organizationName) {
      return res
        .status(400)
        .json({ message: "email, password, name and organizationName are required" });
    }
    const uname = typeof username === "string" ? username.trim().toLowerCase() : "";
    if (!USERNAME_RE.test(uname)) {
      return res.status(400).json({
        message: "username is required: 3-30 chars, lowercase letters, numbers, or underscore",
      });
    }
    if (await findUserByEmail(email)) {
      return res.status(409).json({ message: "Email already registered" });
    }
    if (await findUserByUsername(uname)) {
      return res.status(409).json({ message: "Username already taken" });
    }
    const passwordHash = await hashPassword(password as string);

    const created = await withTransaction(async (tx) => {
      const u = await new sql.Request(tx)
        .input("email", sql.NVarChar(320), email)
        .input("hash", sql.NVarChar(sql.MAX), passwordHash)
        .input("name", sql.NVarChar(200), name)
        .input("username", sql.NVarChar(50), uname)
        .query<{ id: string }>(`INSERT INTO dbo.users (email, password_hash, name, username) OUTPUT INSERTED.id VALUES (@email, @hash, @name, @username)`);
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
      username: uname,
      email,
      name,
    });
    return res.status(201).json({
      accessToken,
      user: { id: created.userId, email, name, username: uname },
      organization: { id: created.tenantId, name: organizationName },
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
    const { email, identifier, username, password: passwordInput, workspaceId } = req.body || {};
    // Accept `identifier` (email OR username); keep `email`/`username` for back-compat.
    const idf = (identifier ?? email ?? username ?? "").toString().trim();
    if (!idf || !passwordInput) {
      return res.status(400).json({ message: "identifier (email or username) and password are required" });
    }
    const user = await findUserByIdentifier(idf);
    const ok = user && (await verifyPassword(passwordInput as string, user.password_hash));
    if (!ok) return res.status(401).json({ message: "Email/username or password is incorrect" });

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
      username: user.username,
      email: user.email,
      name: user.name,
    });
    return res.json({
      accessToken,
      user: { id: user.id, email: user.email, name: user.name, username: user.username },
      organization: { id: m.tenant_id, name: m.org_name },
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
      clearRefreshCookie(req, res);
      return res.status(401).json({ message: "Invalid or expired session" });
    }
    const m = await getWorkspaceMembership(rotated.userId, rotated.activeWorkspaceId);
    if (!m) {
      clearRefreshCookie(req, res);
      return res.status(401).json({ message: "Workspace membership missing" });
    }
    setRefreshCookie(req, res,rotated.refreshToken);
    const me = await findUserById(rotated.userId);
    const accessToken = signAccessToken({
      userId: rotated.userId,
      tenantId: m.tenant_id,
      workspaceId: rotated.activeWorkspaceId,
      role: m.ws_role,
      orgRole: m.org_role,
      sessionId: rotated.sessionId,
      username: me?.username,
      email: me?.email,
      name: me?.name,
    });
    return res.json({ accessToken });
  } catch (err) {
    next(err);
  }
});

// POST /auth/token/renew — SSO silent renew. Validates the session WITHOUT rotating
// the refresh token and mints a fresh access token. Product frontends call this on a
// 401 (using the shared central session cookie); non-rotating so concurrent renews
// from multiple products/tabs can't trip reuse-detection. No new cookie is set.
router.post("/token/renew", async (req: Request, res: Response, next: NextFunction) => {
  try {
    const presented = req.cookies && (req.cookies[REFRESH_COOKIE] as string | undefined);
    if (!presented) return res.status(401).json({ message: "Missing session" });

    const session = await sessionService.validateSession(presented);
    if (!session) {
      clearRefreshCookie(req, res);
      return res.status(401).json({ message: "Invalid or expired session" });
    }
    const m = await getWorkspaceMembership(session.userId, session.activeWorkspaceId);
    if (!m) return res.status(401).json({ message: "Workspace membership missing" });

    const me = await findUserById(session.userId);
    const accessToken = signAccessToken({
      userId: session.userId,
      tenantId: m.tenant_id,
      workspaceId: session.activeWorkspaceId,
      role: m.ws_role,
      orgRole: m.org_role,
      sessionId: session.sessionId,
      username: me?.username,
      email: me?.email,
      name: me?.name,
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
    const chosen = (await listUserWorkspaces(req.user!.userId)).find((w) => w.id === workspaceId);
    const me = await findUserById(req.user!.userId);
    const accessToken = signAccessToken({
      userId: req.user!.userId,
      tenantId: m.tenant_id,
      workspaceId: workspaceId as string,
      role: m.ws_role,
      orgRole: m.org_role,
      sessionId: req.user!.sessionId,
      username: me?.username,
      email: me?.email,
      name: me?.name,
    });
    return res.json({
      accessToken,
      organization: { id: m.tenant_id, name: m.org_name },
      workspace: { id: workspaceId, name: chosen?.name },
      role: m.ws_role,
      orgRole: m.org_role,
    });
  } catch (err) {
    next(err);
  }
});

// POST /auth/logout — revoke current session.
router.post("/logout", requireAuth(), async (req: Request, res: Response, next: NextFunction) => {
  try {
    await sessionService.revokeSession(req.user!.sessionId);
    clearRefreshCookie(req, res);
    return res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// POST /auth/logout-all — revoke all of the user's sessions.
router.post("/logout-all", requireAuth(), async (req: Request, res: Response, next: NextFunction) => {
  try {
    await sessionService.revokeAllSessions(req.user!.userId);
    clearRefreshCookie(req, res);
    return res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

export default router;
