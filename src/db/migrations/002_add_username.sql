-- 002_add_username.sql
-- Adds a unique login handle `username` to users.
--   * NULLABLE so this is safe on a live table with existing rows (they keep NULL
--     until they set one; new signups require it at the app layer).
--   * Uniqueness enforced by a FILTERED unique index (allows many NULLs, unique
--     on real values).
-- Batch-safe: NO GO (migrate.ts runs each file as one .batch()); the index is made
-- via EXEC so it parses AFTER the column exists within the same batch.

IF COL_LENGTH('dbo.users', 'username') IS NULL
  ALTER TABLE dbo.users ADD username NVARCHAR(50) NULL;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'uq_users_username')
  EXEC('CREATE UNIQUE INDEX uq_users_username ON dbo.users(username) WHERE username IS NOT NULL');
