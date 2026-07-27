#!/usr/bin/env bash
# Azure App Service (Linux) startup script for the Bun runtime — no Docker.
# Installs Bun ONCE into the persistent /home/.bun (App Service persists /home
# across restarts and shares it across instances), then runs the app.
# Set the App Service "Startup Command" to:  bash startup.sh
set -euo pipefail

export BUN_INSTALL="/home/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"

if ! command -v bun >/dev/null 2>&1; then
  echo "[startup] Bun not found — installing to $BUN_INSTALL ..."
  curl -fsSL https://bun.sh/install | bash
fi

echo "[startup] bun $(bun --version) — starting ChronoProof"
# App Service injects PORT; src/server.ts binds to process.env.PORT.
exec bun run src/server.ts
