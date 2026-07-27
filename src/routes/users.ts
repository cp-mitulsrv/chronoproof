import express from "express";
import type { Request, Response, NextFunction } from "express";
import { requireAuth } from "../middleware/auth.js";
import { findUserById, listUsersByIdsInTenant } from "../db/repo.js";

// The Users API is how product services resolve identity from the ONE central
// user store (they have no local user table). All routes require a valid
// ChronoProof token; lookups are scoped to the caller's tenant/org.
const router = express.Router();
const GUID_RE = /^[0-9a-fA-F-]{36}$/;

// GET /users/me — the caller's own identity, from the token + central DB.
router.get("/me", requireAuth(), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const me = await findUserById(req.user!.userId);
    if (!me) return res.status(404).json({ message: "User not found" });
    return res.json({
      id: me.id,
      email: me.email,
      name: me.name,
      username: me.username,
      tenantId: req.user!.tenantId,
      workspaceId: req.user!.workspaceId,
      role: req.user!.role,
      orgRole: req.user!.orgRole,
    });
  } catch (err) {
    next(err);
  }
});

// GET /users?ids=a,b,c — batch-resolve public profiles within the caller's org.
router.get("/", requireAuth(), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const raw = String(req.query.ids ?? "").trim();
    const ids = raw
      .split(",")
      .map((s) => s.trim())
      .filter((s) => GUID_RE.test(s))
      .slice(0, 200);
    const users = ids.length ? await listUsersByIdsInTenant(ids, req.user!.tenantId) : [];
    return res.json({ users });
  } catch (err) {
    next(err);
  }
});

// GET /users/:id — a single user's public profile, only within the caller's org.
router.get("/:id", requireAuth(), async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!GUID_RE.test(req.params.id)) return res.status(404).json({ message: "User not found" });
    const [u] = await listUsersByIdsInTenant([req.params.id], req.user!.tenantId);
    if (!u) return res.status(404).json({ message: "User not found" });
    return res.json(u);
  } catch (err) {
    next(err);
  }
});

export default router;
