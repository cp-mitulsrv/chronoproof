import { getPool, sql } from "./pool.js";

export interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  name: string;
  created_at: Date;
}

export interface WorkspaceRow {
  id: string;
  name: string;
  tenant_id: string;
  role: string;
}

export interface MembershipRow {
  workspace_id: string;
  tenant_id: string;
  ws_role: "owner" | "member";
  org_role: "owner" | "admin" | "member";
}

export async function findUserByEmail(email: string): Promise<UserRow | null> {
  const pool = await getPool();
  const r = await pool
    .request()
    .input("email", sql.NVarChar(320), email)
    .query<UserRow>(`SELECT * FROM dbo.users WHERE email = @email`);
  return r.recordset[0] ?? null;
}

export async function listUserWorkspaces(userId: string): Promise<WorkspaceRow[]> {
  const pool = await getPool();
  const r = await pool
    .request()
    .input("uid", sql.UniqueIdentifier, userId)
    .query<WorkspaceRow>(
      `SELECT w.id, w.name, w.tenant_id, uw.role
       FROM dbo.user_workspace uw
       JOIN dbo.workspaces w ON w.id = uw.workspace_id
       WHERE uw.user_id = @uid
       ORDER BY w.name`
    );
  return r.recordset;
}

// Returns { workspace_id, tenant_id, ws_role, org_role } for a user's membership
// in a workspace, or null if they aren't a member.
export async function getWorkspaceMembership(userId: string, workspaceId: string): Promise<MembershipRow | null> {
  const pool = await getPool();
  const r = await pool
    .request()
    .input("uid", sql.UniqueIdentifier, userId)
    .input("ws", sql.UniqueIdentifier, workspaceId)
    .query<MembershipRow>(
      `SELECT w.id AS workspace_id, w.tenant_id, uw.role AS ws_role, uor.org_role
       FROM dbo.user_workspace uw
       JOIN dbo.workspaces w ON w.id = uw.workspace_id
       JOIN dbo.user_org_roles uor ON uor.user_id = uw.user_id AND uor.tenant_id = w.tenant_id
       WHERE uw.user_id = @uid AND uw.workspace_id = @ws`
    );
  return r.recordset[0] ?? null;
}
