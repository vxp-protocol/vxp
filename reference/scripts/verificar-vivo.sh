#!/usr/bin/env bash
# The independent verifier (Python, no code from src/) against the packages the live server
# issued. It starts from an anchor an agent obtains through the protocol (SPEC §9.9.1), never from
# a hand-written issuer (validation round 2, M1):
#   - Poppy profile: the company's domain (poppy.json → issuer → RFC 8414 metadata);
#   - PACT profile, via the brand: its domain (PACT §2.1: Card at /.well-known/agent-card.json, which
#     redirects to the provider) → company → the company lists that domain and that interface;
#   - PACT profile, via the authorization server the agent learned when delegating (PACT §5.1), which
#     comes from the Agent Card itself (oauth2MetadataUrl).
# With the PACT anchors it also cross-checks the chain against the PACT receipt of the turn that
# proposed (SPEC §9.9 step 4 bis). It cross-checks every chain with the other verifier
# (verifier/verificar.py) and runs live negatives.
# Usage: scripts/verificar-vivo.sh   (with the server on :$PUERTO, default 3620, and packages in .prueba/paquetes/)
set -uo pipefail
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
V="$RAIZ/../verifier/verificar_paquete.py"
PUERTO="${PUERTO:-3620}"; PA_PUERTO="${PA_PUERTO:-3622}"
MARCA=localhost:$PUERTO
CARD_URL="http://$MARCA/.well-known/agent-card.json"
# The PACT authorization server's issuer, as the agent obtains it: from the domain's Card.
AS_PACT="$(curl -sL "$CARD_URL" | python -c 'import json,sys; c=json.load(sys.stdin); u=c["securitySchemes"]["userDelegation"]["oauth2SecurityScheme"]["oauth2MetadataUrl"]; import urllib.request; print(json.load(urllib.request.urlopen(u))["issuer"])')"
echo "issuer del AS de PACT, leído de la Card: $AS_PACT"
POR_MARCA="--marca $MARCA"
POR_AS="--as-pact $AS_PACT"
POR_DOMINIO="--dominio $MARCA"
TMP="$(mktemp -d)"
total=0; fallas=0
ok() { total=$((total+1)); echo "$1 -> $2"; }
mal() { total=$((total+1)); fallas=$((fallas+1)); echo "FALLA $1 -> $2"; }
# A negative MUST exit with code 1 and the expected error in the JSON.
negativo() { local nombre="$1" esperado="$2"; shift 2; local out; out="$(python "$V" vivo --http-local "$@" 2>&1)"; local rc=$?
  if [ $rc -eq 1 ] && echo "$out" | grep -q "\"error\": \"$esperado\""; then ok "$nombre" "$out"; else mal "$nombre" "$out"; fi; }
for p in "$RAIZ"/.prueba/paquetes/pact-*.json; do
  case "$p" in *.op.json|*.recibo.json) continue;; esac
  b="$(basename "$p")"
  op="${p%.json}.op.json"; recibo="${p%.json}.recibo.json"
  extra=(); [ -f "$op" ] && extra+=(--operacion "$op")
  for ancla in "$POR_MARCA" "$POR_AS" "$POR_DOMINIO"; do
    con=(); [ "$ancla" != "$POR_DOMINIO" ] && [ -f "$recibo" ] && con=(--recibo-pact "$recibo")
    # shellcheck disable=SC2086
    out="$(python "$V" vivo --http-local $ancla --paquete "$p" --aud http://localhost:$PA_PUERTO "${extra[@]}" "${con[@]}" 2>&1)"
    if [ $? -eq 0 ]; then ok "$b [$ancla]" "$out"; else mal "$b [$ancla]" "$out"; fi
    if [ ${#con[@]} -gt 0 ] && ! echo "$out" | grep -q '"pact_receipt": "verified"'; then mal "$b [$ancla] recibo" "no quedó verified"; fi
  done
  out="$(python "$RAIZ/scripts/cruce-verificador-arquitecto.py" "$p" 2>&1)"
  if [ $? -eq 0 ]; then ok "$b [verificar.py del arquitecto]" "$out"; else mal "$b [verificar.py del arquitecto]" "$out"; fi
  negativo "$b [aud de otro agente]" aud_mismatch $POR_MARCA --paquete "$p" --aud https://otro-agente.example
  # The outcome tampered with (succeeded → failed) without re-signing.
  python - "$p" "$TMP/alt.json" <<'PY'
import base64, json, sys
p = json.load(open(sys.argv[1], encoding="utf-8"))
h, pl, s = p["statements"][-1].split("~")[0].split(".")
d = json.loads(base64.urlsafe_b64decode(pl + "=" * (-len(pl) % 4)))
d["body"]["state"] = "failed"
nuevo = base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()).rstrip(b"=").decode()
p["statements"][-1] = h + "." + nuevo + "." + s + "~"
json.dump(p, open(sys.argv[2], "w", encoding="utf-8"))
PY
  negativo "$b [resultado alterado]" signature_invalid $POR_MARCA --paquete "$TMP/alt.json"
  if [ -f "$recibo" ]; then
    # A PACT receipt from another turn, or tampered with, does not match the chain's citation.
    python - "$recibo" "$TMP/rec-alt.json" <<'PY'
import base64, json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
h, pl, s = r["jws"].split(".")
c = json.loads(base64.urlsafe_b64decode(pl + "=" * (-len(pl) % 4)))
c["grantId"] = "a2agrant_OTRO"
r["jws"] = h + "." + base64.urlsafe_b64encode(json.dumps(c, separators=(",", ":")).encode()).rstrip(b"=").decode() + "." + s
json.dump(r, open(sys.argv[2], "w", encoding="utf-8"))
PY
    negativo "$b [recibo PACT alterado]" pact_receipt_invalid $POR_MARCA --paquete "$p" --recibo-pact "$TMP/rec-alt.json"
  fi
done
# Anchors that do not come from the protocol or do not exist: the verifier responds, it does not crash (m4).
negativo "issuer sin metadata (404)" issuer_not_anchored --issuer http://localhost:$PUERTO/e/no-existe --paquete "$p"
negativo "AS de PACT de otra marca" issuer_not_anchored --as-pact http://localhost:$PUERTO/a2a/t_libreria_demo/oauth --paquete "$p"
rm -rf "$TMP"
echo "verificaciones: $total, fallas: $fallas"
[ "$fallas" -eq 0 ]
