import { test, expect } from "bun:test";
import jwt from "jsonwebtoken";
import { signAccessToken } from "../src/services/tokenService";
import config from "../src/config";

test("signAccessToken issues a verifiable RS256 token with the exact claim contract", () => {
  const token = signAccessToken({
    userId: "u1", tenantId: "t1", workspaceId: "w1",
    role: "owner", orgRole: "owner", sessionId: "s1",
  });

  const decoded = jwt.verify(token, config.jwt.publicKey as string, {
    algorithms: ["RS256"],
    issuer: config.issuer,
    audience: config.audience,
  }) as jwt.JwtPayload;

  expect(decoded.sub).toBe("u1");
  expect(decoded.tid).toBe("t1");
  expect(decoded.wsid).toBe("w1");
  expect(decoded.role).toBe("owner");
  expect(decoded.orole).toBe("owner");
  expect(decoded.sid).toBe("s1");
  expect(decoded.typ).toBe("access");
  expect(decoded.jti).toBeTruthy();

  const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString()) as { alg: string; kid: string };
  expect(header.alg).toBe("RS256");
  expect(header.kid).toBe(config.jwt.keyId);
});
