import { password } from "bun";
import { scrypt, timingSafeEqual } from "crypto";
import { promisify } from "util";

// Password hashing: new hashes use argon2id (via Bun.password).
// Legacy hashes use scrypt (Node crypto, format: "scrypt$saltHex$hashHex").
//
// Migration path: on successful login with a legacy scrypt hash, verifyPassword
// returns true and needsRehash returns true — the login handler then upgrades
// the stored hash to argon2id. This avoids forcing all users to reset passwords.

const scryptAsync = promisify(scrypt);
const KEYLEN = 64;

/** Private: verify a legacy scrypt hash (format: "scrypt$saltHex$hashHex"). */
async function verifyLegacyScrypt(plain: string, stored: string): Promise<boolean> {
  const [, salt, hashHex] = stored.split("$");
  if (!salt || !hashHex) return false;
  const expected = Buffer.from(hashHex, "hex");
  const derived = (await scryptAsync(plain, salt, KEYLEN)) as Buffer;
  return expected.length === derived.length && timingSafeEqual(expected, derived);
}

/** Hash a password using argon2id (Bun native). */
export async function hashPassword(plain: string): Promise<string> {
  return password.hash(plain, "argon2id");
}

/**
 * Verify a password against a stored hash.
 * Handles both legacy scrypt hashes and current argon2id hashes.
 */
export async function verifyPassword(plain: string, stored: string): Promise<boolean> {
  if (typeof stored !== "string") return false;
  if (stored.startsWith("scrypt$")) {
    return verifyLegacyScrypt(plain, stored);
  }
  return password.verify(plain, stored);
}

/**
 * Returns true if the hash is a legacy scrypt hash that should be upgraded.
 * Use after a successful verifyPassword to trigger rehashing on next login.
 */
export function needsRehash(stored: string): boolean {
  return typeof stored === "string" && stored.startsWith("scrypt$");
}
