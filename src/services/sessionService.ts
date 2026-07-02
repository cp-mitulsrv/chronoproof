import crypto from "crypto";
import { getPool, sql } from "../db/pool.js";
import config from "../config/index.js";

export interface CreateSessionInput {
  userId: string;
  activeWorkspaceId: string;
  deviceLabel: string | null;
  ipAddress: string | null;
}

export interface SessionResult {
  sessionId: string;
  refreshToken: string;
}

export interface RotatedSession {
  sessionId: string;
  userId: string;
  activeWorkspaceId: string;
  refreshToken: string;
}

interface LoginSessionRow {
  id: string;
  user_id: string;
  refresh_token_hash: string;
  device_label: string | null;
  ip_address: string | null;
  active_workspace_id: string;
  expires_at: Date;
  revoked_at: Date | null;
  created_at: Date;
  last_used_at: Date | null;
}

function generateRefreshToken(): string {
  return crypto.randomBytes(48).toString("base64url");
}
function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}
function expiryDate(): Date {
  return new Date(Date.now() + config.refreshTokenTtlDays * 24 * 60 * 60 * 1000);
}

export async function createSession(input: CreateSessionInput): Promise<SessionResult> {
  const { userId, activeWorkspaceId, deviceLabel, ipAddress } = input;
  const refreshToken = generateRefreshToken();
  const pool = await getPool();
  const r = await pool
    .request()
    .input("user_id", sql.UniqueIdentifier, userId)
    .input("hash", sql.NVarChar(128), hashToken(refreshToken))
    .input("device", sql.NVarChar(200), deviceLabel || null)
    .input("ip", sql.NVarChar(45), ipAddress || null)
    .input("ws", sql.UniqueIdentifier, activeWorkspaceId)
    .input("exp", sql.DateTime2, expiryDate())
    .query<{ id: string }>(
      `INSERT INTO dbo.login_session (user_id, refresh_token_hash, device_label, ip_address, active_workspace_id, expires_at)
       OUTPUT INSERTED.id
       VALUES (@user_id, @hash, @device, @ip, @ws, @exp)`
    );
  return { sessionId: r.recordset[0].id, refreshToken };
}

async function findByToken(refreshToken: string): Promise<LoginSessionRow | null> {
  const pool = await getPool();
  const r = await pool
    .request()
    .input("hash", sql.NVarChar(128), hashToken(refreshToken))
    .query<LoginSessionRow>(`SELECT * FROM dbo.login_session WHERE refresh_token_hash = @hash`);
  return r.recordset[0] ?? null;
}

// Rotates the refresh token. Reuse of an already-revoked token revokes the whole
// session family for that user (reuse detection).
export async function rotateSession(refreshToken: string): Promise<RotatedSession | null> {
  const session = await findByToken(refreshToken);
  const pool = await getPool();

  if (!session || session.revoked_at || new Date(session.expires_at) < new Date()) {
    if (session && session.revoked_at) {
      await pool
        .request()
        .input("uid", sql.UniqueIdentifier, session.user_id)
        .query(
          `UPDATE dbo.login_session SET revoked_at = SYSUTCDATETIME()
           WHERE user_id = @uid AND revoked_at IS NULL`
        );
    }
    return null;
  }

  const newToken = generateRefreshToken();
  await pool
    .request()
    .input("id", sql.UniqueIdentifier, session.id)
    .query(`UPDATE dbo.login_session SET revoked_at = SYSUTCDATETIME() WHERE id = @id`);

  const r = await pool
    .request()
    .input("user_id", sql.UniqueIdentifier, session.user_id)
    .input("hash", sql.NVarChar(128), hashToken(newToken))
    .input("device", sql.NVarChar(200), session.device_label)
    .input("ip", sql.NVarChar(45), session.ip_address)
    .input("ws", sql.UniqueIdentifier, session.active_workspace_id)
    .input("exp", sql.DateTime2, expiryDate())
    .query<{ id: string }>(
      `INSERT INTO dbo.login_session (user_id, refresh_token_hash, device_label, ip_address, active_workspace_id, expires_at)
       OUTPUT INSERTED.id
       VALUES (@user_id, @hash, @device, @ip, @ws, @exp)`
    );

  return {
    sessionId: r.recordset[0].id,
    userId: session.user_id,
    activeWorkspaceId: session.active_workspace_id,
    refreshToken: newToken,
  };
}

export async function setActiveWorkspace(sessionId: string, workspaceId: string): Promise<void> {
  const pool = await getPool();
  await pool
    .request()
    .input("id", sql.UniqueIdentifier, sessionId)
    .input("ws", sql.UniqueIdentifier, workspaceId)
    .query(
      `UPDATE dbo.login_session SET active_workspace_id = @ws, last_used_at = SYSUTCDATETIME() WHERE id = @id`
    );
}

export async function revokeSession(sessionId: string): Promise<void> {
  const pool = await getPool();
  await pool
    .request()
    .input("id", sql.UniqueIdentifier, sessionId)
    .query(`UPDATE dbo.login_session SET revoked_at = SYSUTCDATETIME() WHERE id = @id`);
}

export async function revokeAllSessions(userId: string): Promise<void> {
  const pool = await getPool();
  await pool
    .request()
    .input("uid", sql.UniqueIdentifier, userId)
    .query(
      `UPDATE dbo.login_session SET revoked_at = SYSUTCDATETIME() WHERE user_id = @uid AND revoked_at IS NULL`
    );
}
