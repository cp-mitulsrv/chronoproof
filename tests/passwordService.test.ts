import { test, expect } from "bun:test";
import { hashPassword, verifyPassword, needsRehash } from "../src/services/passwordService";

test("hash then verify succeeds (argon2id); wrong password fails", async () => {
  const hash = await hashPassword("s3cret-pw");
  expect(hash).not.toBe("s3cret-pw");
  expect(await verifyPassword("s3cret-pw", hash)).toBe(true);
  expect(await verifyPassword("wrong", hash)).toBe(false);
  expect(needsRehash(hash)).toBe(false);
});

test("legacy scrypt hash verifies correctly and flags needsRehash", async () => {
  // Build a legacy scrypt hash using node:crypto directly
  const { scrypt, randomBytes } = await import("crypto");
  const { promisify } = await import("util");
  const scryptAsync = promisify(scrypt);
  const salt = randomBytes(16).toString("hex");
  const derived = (await scryptAsync("s3cret-pw", salt, 64)) as Buffer;
  const legacyHash = `scrypt$${salt}$${derived.toString("hex")}`;

  expect(needsRehash(legacyHash)).toBe(true);
  expect(await verifyPassword("s3cret-pw", legacyHash)).toBe(true);
  expect(await verifyPassword("wrong", legacyHash)).toBe(false);
});
