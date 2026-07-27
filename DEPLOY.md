# Deploying ChronoProof to Azure App Service (no Docker)

This service deploys as a Bun app directly to an Azure App Service
(Web App) — no container image, matching the existing Chrono product services.

> **Note:** Azure App Service does not ship Bun natively. You must either use a
> startup script that installs Bun first, or use a custom container image that
> includes Bun. See the startup command note below.

## App Service settings
- **Runtime stack:** Node 20 LTS (used as the base; Bun is installed via startup script).
- **Startup Command:** `bun run src/server.ts`
  - Bun must be available in PATH. If not pre-installed, prepend:
    `curl -fsSL https://bun.sh/install | bash && ~/.bun/bin/bun run src/server.ts`
  - On the **Linux** stack, set this and DELETE `web.config`.
  - On the **Windows** stack, `web.config` (iisnode) drives it instead — update accordingly.
- **Build:** `.deployment` sets `SCM_DO_BUILD_DURING_DEPLOYMENT=true` so Kudu runs `bun install`.
- **Port:** App Service injects `PORT`; the app binds to `process.env.PORT`.

## Application Settings (env)
Set these as App Settings; secrets via **Azure Key Vault references**, never plaintext:
- `DB_SERVER`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_ENCRYPT`
- `DB_PASSWORD` → `@Microsoft.KeyVault(SecretUri=.../chronoproof-db-password/)`
- `JWT_PRIVATE_KEY` → `@Microsoft.KeyVault(SecretUri=.../chronoproof-jwt-private-key/)` (resolved value is the PEM string)
- `JWT_PUBLIC_KEY` (public; may be an App Setting or Key Vault ref)
- `JWT_KEY_ID`, `ISSUER`, `AUDIENCE`, `COOKIE_DOMAIN`, `CORS_ALLOWED_ORIGINS`

The App Service's **system-assigned managed identity** must have `get` on the Key Vault's secrets.

## Rollout (live service)
Deploy to a **staging slot**, run the validation checklist against it, then **swap** to production.
Never run a destructive migration (dropping old auth tables / removing old login routes) against
production before the service is validated end-to-end in staging.

## One-time key generation (manual, not in code)
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```
Upload `private.pem` to Key Vault as `chronoproof-jwt-private-key`. `public.pem` is served via JWKS.
Never commit keys — `keys/*.pem` is gitignored.
