import { getPool, sql } from "./pool.js";

export interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  name: string;
  username: string | null;
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
  org_name: string;
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

export async function findUserById(userId: string): Promise<UserRow | null> {
  const pool = await getPool();
  const r = await pool
    .request()
    .input("id", sql.UniqueIdentifier, userId)
    .query<UserRow>(`SELECT * FROM dbo.users WHERE id = @id`);
  return r.recordset[0] ?? null;
}

export async function findUserByUsername(username: string): Promise<UserRow | null> {
  const pool = await getPool();
  const r = await pool
    .request()
    .input("u", sql.NVarChar(50), username)
    .query<UserRow>(`SELECT * FROM dbo.users WHERE username = @u`);
  return r.recordset[0] ?? null;
}

// Login lookup: matches an email (exact) OR a username (case-insensitive).
export async function findUserByIdentifier(identifier: string): Promise<UserRow | null> {
  const pool = await getPool();
  const r = await pool
    .request()
    .input("id", sql.NVarChar(320), identifier)
    .query<UserRow>(`SELECT * FROM dbo.users WHERE email = @id OR username = LOWER(@id)`);
  return r.recordset[0] ?? null;
}

// Public (non-secret) user profile — what other services are allowed to see.
export interface PublicUser {
  id: string;
  email: string;
  name: string;
  username: string | null;
}

// Resolve public profiles for a set of user ids, RESTRICTED to users who belong
// to the caller's tenant (org). This is how product services turn a `user_id`
// stored in their own DB into a name/email — without a local user table — while
// preventing cross-tenant user enumeration.
export async function listUsersByIdsInTenant(ids: string[], tenantId: string): Promise<PublicUser[]> {
  if (ids.length === 0) return [];
  const pool = await getPool();
  const request = pool.request().input("tid", sql.UniqueIdentifier, tenantId);
  const placeholders = ids.map((id, i) => {
    request.input(`id${i}`, sql.UniqueIdentifier, id);
    return `@id${i}`;
  });
  const r = await request.query<PublicUser>(
    `SELECT DISTINCT u.id, u.email, u.name, u.username
     FROM dbo.users u
     JOIN dbo.user_org_roles r ON r.user_id = u.id
     WHERE r.tenant_id = @tid AND u.id IN (${placeholders.join(", ")})`
  );
  return r.recordset;
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
      `SELECT w.id AS workspace_id, w.tenant_id, t.name AS org_name, uw.role AS ws_role, uor.org_role
       FROM dbo.user_workspace uw
       JOIN dbo.workspaces w ON w.id = uw.workspace_id
       JOIN dbo.tenants t ON t.id = w.tenant_id
       JOIN dbo.user_org_roles uor ON uor.user_id = uw.user_id AND uor.tenant_id = w.tenant_id
       WHERE uw.user_id = @uid AND uw.workspace_id = @ws`
    );
  return r.recordset[0] ?? null;
}
