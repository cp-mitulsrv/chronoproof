import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";
import config from "../config/index.js";

export interface TokenPayload {
  userId: string;
  tenantId: string;
  workspaceId: string;
  role: "owner" | "member";
  orgRole: "owner" | "admin" | "member";
  sessionId: string;
  username?: string | null;
  email?: string | null;
  name?: string | null;
}

// Signs a short-lived RS256 access token. The claim shape MUST match what
// @chronoproof/auth-kit verifies: sub, tid, wsid, role, orole, sid, typ, jti,
// plus iss/aud/iat/exp. ChronoProof is the ONLY signer.
export function signAccessToken(payload: TokenPayload): string {
  if (!config.jwt.privateKey) {
    throw new Error("JWT private key not configured (set JWT_PRIVATE_KEY or keys/private.pem)");
  }
  const opts: jwt.SignOptions = {
    algorithm: "RS256",
    issuer: config.issuer,
    audience: config.audience,
    subject: payload.userId,
    expiresIn: config.accessTokenTtl as jwt.SignOptions["expiresIn"],
    keyid: config.jwt.keyId,
  };
  const claims: Record<string, unknown> = {
    tid: payload.tenantId,
    wsid: payload.workspaceId,
    role: payload.role,
    orole: payload.orgRole,
    sid: payload.sessionId,
    typ: "access",
    jti: randomUUID(),
  };
  // uname/email/name: every service reads the central identity straight from the
  // token — no runtime call back to ChronoProof needed to render "who am I".
  if (payload.username) claims.uname = payload.username;
  if (payload.email) claims.email = payload.email;
  if (payload.name) claims.name = payload.name;
  return jwt.sign(claims, config.jwt.privateKey, opts);
}
