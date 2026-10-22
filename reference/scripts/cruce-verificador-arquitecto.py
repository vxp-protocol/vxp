"""Cross-check: the chain issued by the live server, verified with the other verifier
(verifier/verificar.py). Fetches over HTTP the public material the anchor names (SPEC 9.9.1):
the provider's Agent Card, the RFC 8414 metadata of the company's issuer and the JWKS it
names; then uses that verifier's `anclar` and `verificar_cadena`.

Usage: python scripts/cruce-verificador-arquitecto.py <paquete.json> [issuer] [Agent Card URL]

This cross-check verifies the chain rules with the second verifier. The PACT anchor (brand
domain or PACT authorization server, SPEC 9.9.1) is checked by verificar_paquete.py in
verificar-vivo.sh; verificar.py does not implement those two paths yet (SPEC appendix A.9).
"""
import importlib.util
import json
import os
import sys
import urllib.request
from urllib.parse import urlsplit

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("verificar_arquitecto", os.path.join(RAIZ, "..", "verifier", "verificar.py"))
arq = importlib.util.module_from_spec(spec)
spec.loader.exec_module(arq)


def traer(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())


def main(ruta, issuer, card_url):
    paquete = json.load(open(ruta, encoding="utf-8"))
    docs = {card_url: traer(card_url)}
    s = urlsplit(issuer)
    meta_url = s.scheme + "://" + s.netloc + "/.well-known/oauth-authorization-server" + s.path.rstrip("/")
    docs[meta_url] = traer(meta_url)
    t = docs[meta_url].get("vxp_proof") or {}
    for u in (t.get("jwks_uri"), (t.get("operator") or {}).get("jwks_uri")):
        if u:
            docs[u] = traer(u)
    try:
        iss, llaves, custodia = arq.anclar(docs, {"issuer": issuer, "card": card_url})
        v, _ = arq.verificar_cadena(paquete["statements"], llaves, iss, custodia)
    except arq.Falla as e:
        print(json.dumps({"valid": False, "error": e.code, "seq": e.seq}))
        return 1
    print(json.dumps(v, ensure_ascii=False))
    return 0 if v.get("valid") else 1


if __name__ == "__main__":
    sys.exit(main(
        sys.argv[1],
        sys.argv[2] if len(sys.argv) > 2 else f"http://localhost:{os.environ.get('PUERTO', '3620')}/e/ferreteria-demo",
        sys.argv[3] if len(sys.argv) > 3 else f"http://localhost:{os.environ.get('PUERTO', '3620')}/a2a/t_ferreteria_demo/.well-known/agent-card.json",
    ))
