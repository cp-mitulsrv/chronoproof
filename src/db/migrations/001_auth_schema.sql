-- ChronoProof identity schema — Azure SQL / SQL Server (T-SQL).
-- Organization = Tenant. One global users table. Users belong to an org
-- (user_org_roles) and to workspaces within it (user_workspace). Sessions
-- (login_session) store only the HASH of the refresh token. RS256 signing
-- keys live in Azure Key Vault (NOT a DB table), so there is no signing_keys
-- table here. Idempotent via IF OBJECT_ID guards.

IF OBJECT_ID('dbo.users', 'U') IS NULL
CREATE TABLE dbo.users (
  id              UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID() PRIMARY KEY,
  email           NVARCHAR(320)    NOT NULL UNIQUE,
  password_hash   NVARCHAR(MAX)    NOT NULL,
  name            NVARCHAR(200)    NOT NULL,
  created_at      DATETIME2        NOT NULL DEFAULT SYSUTCDATETIME()
);

IF OBJECT_ID('dbo.tenants', 'U') IS NULL
CREATE TABLE dbo.tenants (
  id              UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID() PRIMARY KEY,
  name            NVARCHAR(200)    NOT NULL,
  slug            NVARCHAR(200)    NOT NULL UNIQUE,
  created_at      DATETIME2        NOT NULL DEFAULT SYSUTCDATETIME()
);

IF OBJECT_ID('dbo.workspaces', 'U') IS NULL
CREATE TABLE dbo.workspaces (
  id              UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID() PRIMARY KEY,
  tenant_id       UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.tenants(id),
  name            NVARCHAR(200)    NOT NULL,
  created_at      DATETIME2        NOT NULL DEFAULT SYSUTCDATETIME()
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_workspaces_tenant')
  CREATE INDEX idx_workspaces_tenant ON dbo.workspaces(tenant_id);

IF OBJECT_ID('dbo.user_org_roles', 'U') IS NULL
CREATE TABLE dbo.user_org_roles (
  user_id         UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.users(id),
  tenant_id       UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.tenants(id),
  org_role        NVARCHAR(20)     NOT NULL CONSTRAINT ck_user_org_role CHECK (org_role IN ('owner','admin','member')),
  CONSTRAINT pk_user_org_roles PRIMARY KEY (user_id, tenant_id)
);

IF OBJECT_ID('dbo.user_workspace', 'U') IS NULL
CREATE TABLE dbo.user_workspace (
  user_id         UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.users(id),
  workspace_id    UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.workspaces(id),
  role            NVARCHAR(20)     NOT NULL CONSTRAINT ck_user_workspace_role CHECK (role IN ('owner','member')),
  CONSTRAINT pk_user_workspace PRIMARY KEY (user_id, workspace_id)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_user_workspace_user')
  CREATE INDEX idx_user_workspace_user ON dbo.user_workspace(user_id);

IF OBJECT_ID('dbo.login_session', 'U') IS NULL
CREATE TABLE dbo.login_session (
  id                   UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID() PRIMARY KEY,
  user_id              UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.users(id),
  refresh_token_hash   NVARCHAR(128)    NOT NULL,
  device_label         NVARCHAR(200)    NULL,
  ip_address           NVARCHAR(45)     NULL,
  active_workspace_id  UNIQUEIDENTIFIER NULL REFERENCES dbo.workspaces(id),
  created_at           DATETIME2        NOT NULL DEFAULT SYSUTCDATETIME(),
  last_used_at         DATETIME2        NOT NULL DEFAULT SYSUTCDATETIME(),
  expires_at           DATETIME2        NOT NULL,
  revoked_at           DATETIME2        NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_login_session_user')
  CREATE INDEX idx_login_session_user ON dbo.login_session(user_id);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_login_session_token_hash')
  CREATE INDEX idx_login_session_token_hash ON dbo.login_session(refresh_token_hash);

IF OBJECT_ID('dbo.invitations', 'U') IS NULL
CREATE TABLE dbo.invitations (
  id              UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID() PRIMARY KEY,
  workspace_id    UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.workspaces(id),
  email           NVARCHAR(320)    NOT NULL,
  role            NVARCHAR(20)     NOT NULL CONSTRAINT ck_invitation_role CHECK (role IN ('owner','member')),
  token_hash      NVARCHAR(128)    NOT NULL,
  status          NVARCHAR(20)     NOT NULL DEFAULT 'pending'
                  CONSTRAINT ck_invitation_status CHECK (status IN ('pending','accepted','expired','revoked')),
  expires_at      DATETIME2        NOT NULL,
  created_at      DATETIME2        NOT NULL DEFAULT SYSUTCDATETIME()
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_invitations_token_hash')
  CREATE INDEX idx_invitations_token_hash ON dbo.invitations(token_hash);
