import jwt from "jsonwebtoken";
import type { Request, Response, NextFunction } from "express";
import config from "../config/index.js";

export interface AuthUser {
  userId: string;
  tenantId: string;
  workspaceId: string;
  role: "owner" | "member";
  orgRole: "owner" | "admin" | "member";
  sessionId: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

// ChronoProof verifies its OWN access tokens locally with its own public key.
// (The five product services instead install @chronoproof/auth-kit, which
// fetches the key via JWKS.) req.user matches auth-kit's AuthContext shape.
export function requireAuth() {
  return (req: Request, res: Response, next: NextFunction) => {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Missing or malformed Authorization header" });
    }
    try {
      const payload = jwt.verify(header.slice(7), config.jwt.publicKey as string, {
        algorithms: ["RS256"],
        issuer: config.issuer,
        audience: config.audience,
      }) as jwt.JwtPayload;
      if (payload.typ !== "access") {
        return res.status(401).json({ message: "Wrong token type" });
      }
      req.user = {
        userId: payload.sub as string,
        tenantId: payload.tid as string,
        workspaceId: payload.wsid as string,
        role: payload.role as "owner" | "member",
        orgRole: payload.orole as "owner" | "admin" | "member",
        sessionId: payload.sid as string,
      };
      next();
    } catch {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
  };
}

export function requireOrgRole(...allowed: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) return res.status(401).json({ message: "Not authenticated" });
    if (!allowed.includes(req.user.orgRole)) {
      return res.status(403).json({ message: "Insufficient org role" });
    }
    next();
  };
}

export function requireWorkspaceRole(...allowed: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) return res.status(401).json({ message: "Not authenticated" });
    if (!allowed.includes(req.user.role)) {
      return res.status(403).json({ message: "Insufficient workspace role" });
    }
    next();
  };
}
