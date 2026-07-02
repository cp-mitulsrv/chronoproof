import express from "express";
import crypto from "crypto";
import config from "../config/index.js";

// Exposes ChronoProof's PUBLIC signing key as a JWK set. This is the single
// endpoint the five product services call anonymously to verify tokens — it
// never contains private key material.
function publicJwk(): object {
  if (!config.jwt.publicKey) {
    throw new Error("JWT public key not configured (set JWT_PUBLIC_KEY or keys/public.pem)");
  }
  const keyObject = crypto.createPublicKey(config.jwt.publicKey);
  const jwk = keyObject.export({ format: "jwk" }); // { kty, n, e } — public only
  return { ...jwk, kid: config.jwt.keyId, use: "sig", alg: "RS256" };
}

const router = express.Router();

router.get("/.well-known/jwks.json", (req, res) => {
  res.json({ keys: [publicJwk()] });
});

export { router, publicJwk };
