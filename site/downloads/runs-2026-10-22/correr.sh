#!/usr/bin/env bash
# Corre la batería completa de VXP y guarda cada registro con fecha. Uso: bash correr.sh <carpeta de logs>
L="$1"; cd reference
run() { n="$1"; shift; echo "== $n · $(date -u +%FT%TZ) · $*" | tee "$L/$n.log"; ( "$@" ) >> "$L/$n.log" 2>&1; echo "exit $?" | tee -a "$L/$n.log"; tail -4 "$L/$n.log"; }
run 01-npm-test npm test
run 02-red node --test test-red/vxp-red.test.ts test-red/exigencia-red.test.ts
run 03-mutar-vxp node scripts/mutar-vxp.mjs
run 04-mutar-nativo node scripts/mutar-nativo.mjs
run 05-mutar-exigencia node scripts/mutar-exigencia.mjs
run 06-mutar-prueba python scripts/mutar-prueba.py
run 07-vectores-verificar python verifier/verificar.py vectors/vectores-0.1.json
run 08-vectores-paquete python verifier/verificar_paquete.py vectores vectors/vectores-0.1.json
run 09-vectores-pact python verifier/verificar_paquete.py pact vectors/vectores-pact-0.1.json
run 10-cruce python scripts/cruce-verificadores.py
run 11-fuzz python scripts/fuzz-diferencial.py 20000
