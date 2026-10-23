#!/usr/bin/env bash
# Full VXP run against the repository (repo/vxp), evening of 22 Oct 2026. Every log starts with
# "== <name> · <UTC time> · <command>" and ends with "exit <code>". Usage: bash correr.sh <logs dir>
L="$1"; R=<local>/Desktop/VXP-LANZAMIENTO/repo/vxp; CLON=<openpactprotocol clone>
KEYS=<private keys dir>
OUT=native-run-2026-10-22-evening
export PYTHONIOENCODING=utf-8
run() { n="$1"; shift; echo "== $n · $(date -u +%FT%TZ) · $*" | tee "$L/$n.log"; ( "$@" ) >> "$L/$n.log" 2>&1; echo "exit $?" | tee -a "$L/$n.log"; tail -4 "$L/$n.log"; }
cd $R/reference
run 01-npm-test npm test
run 02-red npm run test:network
run 03-mutar-vxp node scripts/mutar-vxp.mjs
run 04-mutar-nativo node scripts/mutar-nativo.mjs
run 05-mutar-exigencia node scripts/mutar-exigencia.mjs
run 06-mutar-prueba python scripts/mutar-prueba.py
cd $R
run 07-vectores-verificar python verifier/verificar.py vectors/vectores-0.1.json
run 08-vectores-paquete python verifier/verificar_paquete.py vectores vectors/vectores-0.1.json
run 09-vectores-pact python verifier/verificar_paquete.py pact vectors/vectores-pact-0.1.json
cd $R/reference
run 10-cruce python scripts/cruce-verificadores.py
run 11-fuzz python scripts/fuzz-diferencial.py 20000
run 12-recorrido-nativo env VXP_RECORRIDO_DIR=$OUT VXP_KEYS_DIR=$KEYS node --test scripts/recorrido-nativo.test.ts
# PACT: official Identity suite and SOVRAS's own delegated test, against the repository's gateway (neutral data).
rm -rf .prueba/paquetes; mkdir -p .prueba/paquetes
PORT=3620 PA_PORT=3622 VXP_DATOS_NEUTROS=1 VXP_KEYS_DIR=$KEYS PA_PUBLIC_JWK="$(cat .prueba/pa-public.jwk)" node src/main.ts > .prueba/server.log 2>&1 &
SRV=$!; sleep 6
run 13-pact-ferreteria bash scripts/pact-e2e.sh $CLON
run 14-pact-hotel-identity bash -c "cd $CLON/e2e && E2E_PROVIDER=any PROVIDER_URL=http://localhost:3620 CUSTOMER_ID=t_hotel_demo OTHER_CUSTOMER_ID=t_libreria_demo PA_ISSUER=http://localhost:3622 PA_AUDIENCE=http://localhost:3620/a2a PA_PRIVATE_JWK=\"\$(cat $R/reference/.prueba/pa-private.jwk)\" npx vitest run pact.test.ts"
run 15-verificar-vivo bash scripts/verificar-vivo.sh
for p in .prueba/paquetes/pact-op_*.json; do case "$p" in *.recibo.json|*.op.json|*.material.json) continue;; esac
  python scripts/capturar-material.py ../verifier/verificar_paquete.py http://localhost:3620 http://localhost:3620/e/ferreteria-demo $p ${p%.json}.material.json > /dev/null 2>&1; done
kill $SRV 2>/dev/null
cd $R/verifier/tests
run 16-verificador-web node test-vxp-verify.mjs
run 17-fuzz-web node fuzz-vxp-verify.mjs
