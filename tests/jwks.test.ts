import { test, expect } from "bun:test";
import request from "supertest";
import jwt from "jsonwebtoken";
import { buildApp } from "../src/app";
import { signAccessToken } from "../src/services/tokenService";
import { createPublicKey } from "crypto";

test("GET /.well-known/jwks.json returns a public-only JWK", async () => {
  const app = buildApp();
  const res = await request(app).get("/.well-known/jwks.json");
  expect(res.status).toBe(200);
  const key = res.body.keys[0] as { kty: string; use: string; alg: string; kid: string; d?: string };
  expect(key.kty).toBe("RSA");
  expect(key.use).toBe("sig");
  expect(key.alg).toBe("RS256");
  expect(key.kid).toBeTruthy();
  expect(key.d).toBeUndefined(); // no private exponent
});

test("a token signed by tokenService verifies against the served JWKS public key", async () => {
  const app = buildApp();
  const res = await request(app).get("/.well-known/jwks.json");
  const jwk = res.body.keys[0] as JsonWebKey;
  const publicKey = createPublicKey({ key: jwk, format: "jwk" });

  const token = signAccessToken({
    userId: "u1", tenantId: "t1", workspaceId: "w1",
    role: "member", orgRole: "member", sessionId: "s1",
  });
  const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] }) as jwt.JwtPayload;
  expect(decoded.tid).toBe("t1");
});
