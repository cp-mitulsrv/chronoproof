import dotenv from "dotenv";
dotenv.config();

import fs from "fs";
import path from "path";

export interface DbConfig {
  server: string;
  port: number;
  database: string;
  user: string;
  password: string;
  options: { encrypt: boolean; trustServerCertificate: boolean };
}

export interface AppConfig {
  port: number;
  issuer: string;
  audience: string;
  accessTokenTtl: string;
  refreshTokenTtlDays: number;
  db: DbConfig;
  jwt: { keyId: string; privateKey: string | null; publicKey: string | null };
  cookieDomain: string | undefined;
  corsAllowedOrigins: string[];
  smtp: { host: string; port: number; secure: boolean; user: string; password: string; from: string };
  appBaseUrl: string;
}

// .env stores PEMs single-line with literal "\n"; restore real newlines here.
function normalizePem(value: string): string {
  return value.includes("\\n") ? value.replace(/\\n/g, "\n") : value;
}

function readKey(envValue: string | undefined, envPath: string | undefined): string | null {
  if (envValue && envValue.trim()) return normalizePem(envValue);
  if (envPath && fs.existsSync(envPath)) return fs.readFileSync(envPath, "utf8");
  return null;
}

// Parse an ADO.NET-style Azure SQL connection string, e.g.
// "Server=tcp:host.database.windows.net,1433;Database=db;Uid=user;Pwd=pw;Encrypt=True".
function parseSqlConnectionString(str: string): DbConfig {
  const map: Record<string, string> = {};
  for (const part of str.split(";").map((s) => s.trim()).filter(Boolean)) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    map[part.slice(0, idx).trim().toLowerCase()] = part.slice(idx + 1).trim();
  }
  let server = (map["server"] || map["data source"] || "localhost").replace(/^tcp:/i, "");
  let port = 1433;
  const comma = server.indexOf(",");
  if (comma !== -1) {
    port = Number(server.slice(comma + 1)) || 1433;
    server = server.slice(0, comma);
  }
  const encrypt = (map["encrypt"] ?? "true").toLowerCase();
  const trust = (map["trustservercertificate"] || map["trust server certificate"] || "false").toLowerCase();
  return {
    server,
    port,
    database: map["database"] || map["initial catalog"] || "chronoproof",
    user: map["uid"] || map["user id"] || map["user"] || "",
    password: map["pwd"] || map["password"] || "",
    options: {
      encrypt: encrypt !== "false" && encrypt !== "no",
      trustServerCertificate: trust === "true",
    },
  };
}

const db: DbConfig = process.env.AZURE_SQL_CONNECTION_STRING
  ? parseSqlConnectionString(process.env.AZURE_SQL_CONNECTION_STRING)
  : {
      server: process.env.DB_SERVER || "localhost",
      port: Number(process.env.DB_PORT || 1433),
      database: process.env.DB_NAME || "chronoproof",
      user: process.env.DB_USER || "",
      password: process.env.DB_PASSWORD || "",
      options: {
        encrypt: (process.env.DB_ENCRYPT || "true") === "true",
        trustServerCertificate: process.env.DB_TRUST_CERT === "true",
      },
    };

// Dev fallback: generated PEMs in keys/ (gitignored). In production the key
// material comes from JWT_PRIVATE_KEY / JWT_PUBLIC_KEY (or a Key Vault reference).
const DEV_PRIVATE_PEM = path.join(import.meta.dir, "..", "..", "keys", "private.pem");
const DEV_PUBLIC_PEM = path.join(import.meta.dir, "..", "..", "keys", "public.pem");

const config: AppConfig = {
  port: Number(process.env.PORT || 3000),
  issuer: process.env.ISSUER || "https://auth.chronoproof.com",
  audience: process.env.AUDIENCE || "chrono-services",
  accessTokenTtl: process.env.ACCESS_TOKEN_TTL || "15m",
  refreshTokenTtlDays: Number(process.env.REFRESH_TOKEN_TTL_DAYS || 30),

  db,

  jwt: {
    keyId: process.env.JWT_KEY_ID || "chronoproof-key-1",
    privateKey: readKey(process.env.JWT_PRIVATE_KEY, process.env.JWT_PRIVATE_KEY_PATH || DEV_PRIVATE_PEM),
    publicKey: readKey(process.env.JWT_PUBLIC_KEY, process.env.JWT_PUBLIC_KEY_PATH || DEV_PUBLIC_PEM),
  },

  cookieDomain: process.env.COOKIE_DOMAIN || undefined,
  corsAllowedOrigins: (process.env.CORS_ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),

  smtp: {
    host: process.env.SMTP_HOST || "",
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT || 587) === 465, // 465=implicit TLS, 587=STARTTLS
    user: process.env.SMTP_USERNAME || "",
    password: process.env.SMTP_PASSWORD || "",
    from: process.env.EMAIL_FROM || "ChronoProof <noreply@chronoproof.com>",
  },
  // Frontend base for the invite accept link. Falls back to the email-verification URL.
  appBaseUrl:
    process.env.APP_BASE_URL || process.env.EMAIL_VERIFICATION_FRONTEND_URL || "http://localhost:3000",
};

export default config;
