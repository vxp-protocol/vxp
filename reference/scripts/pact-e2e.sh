#!/usr/bin/env bash
# Runs the official PACT Identity suite and the SOVRAS delegated test against the live gateway.
# The delegated test stores the outcome-proof packages (and the PACT receipt of the turn that
# proposed) in .prueba/paquetes/ so the independent verifier can check them afterwards
# (scripts/verificar-vivo.sh).
#
# The official clone is read-only: the delegated test is copied into e2e/ only while it
# runs (vitest resolves the official client from there) and is removed on exit, whatever happens
# (validation round 2, m7).
# Usage: scripts/pact-e2e.sh <path to the openpactprotocol clone (commit 838c6bd, with pnpm install)>
set -euo pipefail
PACT_REPO="$1"
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
# Stress sandbox: its own ports (3600–3699) so it does not clash with the public sandbox (:3500).
PUERTO="${PUERTO:-3620}"; PA_PUERTO="${PA_PUERTO:-3622}"; SERVER_LOG="${SERVER_LOG:-$RAIZ/.prueba/server.log}"
LLAVE="$(grep -o 'llave interna: [^ ]*' "$SERVER_LOG" | tail -1 | cut -d' ' -f3)"
COPIA="$PACT_REPO/e2e/sovras-delegada.test.ts"
trap 'rm -f "$COPIA"' EXIT
cp "$RAIZ/test-pact/sovras-delegada.test.ts" "$COPIA"
cd "$PACT_REPO/e2e"
export E2E_PROVIDER=any PROVIDER_URL=http://localhost:$PUERTO CUSTOMER_ID=t_ferreteria_demo OTHER_CUSTOMER_ID=t_libreria_demo \
  PA_ISSUER=http://localhost:$PA_PUERTO PA_AUDIENCE=http://localhost:$PUERTO/a2a PA_PRIVATE_JWK="$(cat "$RAIZ/.prueba/pa-private.jwk")" LLAVE_INTERNA="$LLAVE" \
  PAQUETES_DIR="$RAIZ/.prueba/paquetes"
npx vitest run --sequence.concurrent=false pact.test.ts sovras-delegada.test.ts
