"""Differential fuzzing of the two verifiers (round 1, M3): random chains, properly signed with the
vectors' TEST keys, mixing valid and invalid steps. If the two verifiers disagree on a single
chain, the SPEC (or one of them) leaves a case without a single verdict.

Usage: python scripts/fuzz-diferencial.py [iterations] [seed]
"""
import importlib.util
import json
import os
import random
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cargar(nombre, ruta):
    spec = importlib.util.spec_from_file_location(nombre, os.path.join(RAIZ, ruta))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


C = cargar("construccion", "../verifier/verificar_paquete.py")
A = cargar("arquitecto", "../verifier/verificar.py")
V = json.load(open(os.path.join(RAIZ, "..", "vectors", "vectores-0.1.json"), encoding="utf-8"))
EMP, OPE = V["keys"]["company"]["issuer"], V["keys"]["operator"]["issuer"]
LLAVES = {"company": V["keys"]["company"], "operator": V["keys"]["operator"]}
PRIV = {r: ec.derive_private_key(int.from_bytes(C.b64d(V["keys"][r]["d_TEST_ONLY"]), "big"), ec.SECP256R1()) for r in ("company", "operator")}
KID = {r: V["keys"][r]["jwks"]["keys"][0]["kid"] for r in ("company", "operator")}
TD = [V["inputs"]["terms_digest_1"], V["inputs"]["terms_digest_2"], "sha-256:OTRA"]
ROL = {k: r for r, ks in C.ROLES.items() for k in ks}


def firmar(rol, payload, discl=()):
    h = C.b64e(C.jcs({"alg": "ES256", "kid": KID[rol], "typ": "vxp-stmt+sd-jwt"}).encode())
    p = C.b64e(C.jcs(payload).encode())
    r, s = decode_dss_signature(PRIV[rol].sign((h + "." + p).encode(), ec.ECDSA(hashes.SHA256())))
    return h + "." + p + "." + C.b64e(r.to_bytes(32, "big") + s.to_bytes(32, "big")) + "~" + "".join(d + "~" for d in discl)


def cuerpo(k, rnd, st):
    """Plausible body for `k`, sometimes with a misplaced field."""
    rev = st["rev"] if rnd.random() < 0.85 else rnd.choice([st["rev"] + 1, 1, 2])
    td = st["td"] if rnd.random() < 0.85 else rnd.choice(TD)
    if k == "request":
        return {"channel": "poppy", "client_id": "x", "request_digest": TD[2]}
    if k == "terms":
        b = {"revision": rnd.choice([st["rev"] + 1, st["rev"] + 1, st["rev"]]), "terms_digest": rnd.choice(TD[:2]), "capability": "c", "expires_at": None, "user_approval_required": True,
             # Round 3: what the company requires and what the read-back must observe, sometimes malformed or missing.
             "company_review_required": rnd.choice([False] * 12 + [True] * 4 + ["no"]),
             "read_back_terms": rnd.choice([["pedido", "despacho_nuevo"]] * 10 + [["pedido"]] * 4 + [[], ["pedido", "pedido"], "pedido"])}
        if rnd.random() < 0.02:
            del b["company_review_required"]
        return b
    if k == "counter":
        return {"base_revision": rnd.choice([st["rev"], st["rev"], 0]), "counter_digest": TD[2], "from": "personal_agent"}
    if k == "user_approval":
        m = rnd.choice(["agent_asserted", "company_channel", "company_channel", "otro"])
        b = {"revision": rev, "terms_digest": td, "method": m, "evidence": {}}
        if m == "company_channel" and isinstance(td, str):
            b["display_code"] = rnd.choice([C.codigo_visible(td), "000000"])
        return b
    if k == "company_review":
        return {"revision": rev, "terms_digest": td, "decision": rnd.choice(["approved", "denied", "quizas"]), "role": "r"}
    if k == "execution":
        return {"revision": rev, "terms_digest": td, "capability": "c", "release": TD[2], "attempt": 1}
    if k == "read_back":
        return {"method": rnd.choice(["system_read_back", "system_read_back", "manual", "none", "x"]), "source": "company_system",
                "matches_terms": rnd.choice([True, True, False, "si"]),
                "observed": rnd.choice([{"pedido": "P", "despacho_nuevo": "d"}] * 6 + [{"pedido": "P"}, {}, {"despacho": "d"}])}
    if k == "outcome":
        return {"state": rnd.choice(["succeeded", "succeeded", "failed", "cancelled", "unknown", "raro"]), "revision": rev, "terms_digest": td,
                "result_summary_digest": TD[2], "claimed_assurance": [], "third_party": []}
    ref = st["finales"][-1] if st["finales"] and rnd.random() < 0.85 else (rnd.choice(st["huellas"]) if st["huellas"] else "sha-256:nada")
    if k == "correction":
        b = {"corrects": ref, "state": rnd.choice(["succeeded", "failed", "unknown", "raro"]), "reason": "r"}
        if rnd.random() < 0.7:
            b["read_back"] = st["lecturas"][-1] if st["lecturas"] and rnd.random() < 0.85 else (rnd.choice(st["huellas"]) if st["huellas"] else "sha-256:nada")
        return b
    return {"revokes": ref, "reason": "r"}


def guion(rnd):
    """A plausible SPEC ordering, with an ordering mutation in some of the cases."""
    g = ["request", "terms"]
    for _ in range(rnd.choice([0, 0, 1, 2])):
        g += ["counter", "terms"]
    if rnd.random() < 0.8:
        g.append("user_approval")
        if rnd.random() < 0.3:
            g.append("company_review")
        if rnd.random() < 0.85:
            g.append("execution")
            g += ["read_back"] * rnd.choice([0, 1, 1, 1, 2])
    g.append("outcome")
    for _ in range(rnd.choice([0, 0, 1, 2])):
        g += ["read_back"] * rnd.choice([0, 1]) + ["correction"]
    if rnd.random() < 0.1:
        g.append("revocation")
    kinds = ["request", "terms", "counter", "user_approval", "company_review", "execution", "read_back", "outcome", "correction", "revocation"]
    for _ in range(rnd.choice([0, 0, 0, 1, 2])):
        op = rnd.random()
        i = rnd.randrange(len(g))
        if op < 0.33 and len(g) > 1:
            del g[i]
        elif op < 0.66:
            g.insert(i, rnd.choice(kinds))
        else:
            j = rnd.randrange(len(g))
            g[i], g[j] = g[j], g[i]
    return g


def cadena(rnd):
    st = {"rev": 0, "td": TD[0], "huellas": [], "finales": [], "lecturas": []}
    c, prev = [], None
    for i, k in enumerate(guion(rnd)):
        b = cuerpo(k, rnd, st)
        if k == "terms" and isinstance(b["revision"], int):
            st["rev"], st["td"] = b["revision"], b["terms_digest"]
        p = {"v": "0.1", "kind": k, "iss": EMP if ROL[k] == "company" else OPE, "company": EMP, "op": "op_f", "seq": i, "prev": prev,
             "iat": 1, "aud": "a", "user": rnd.choice(["u"] * 30 + ["v"]), "body": b}
        sd = firmar(ROL[k] if rnd.random() < 0.98 else ("operator" if ROL[k] == "company" else "company"), p)
        h = C.huella_declaracion(sd.split("~")[0])
        st["huellas"].append(h)
        if k in ("outcome", "correction", "revocation"):
            st["finales"].append(h)
        if k == "read_back":
            st["lecturas"].append(h)
        c.append(sd)
        prev = h
    return c


def resultado(m, c):
    try:
        r = m.verificar_cadena(c, LLAVES, EMP, "operator_hosted")
        return json.dumps(r[0], sort_keys=True)
    except m.Falla as e:
        return "RECHAZA %s seq=%s" % (e.code, e.seq)


def main(n, semilla):
    rnd = random.Random(semilla)
    discrepan = validas = 0
    codigos = {}
    for it in range(n):
        c = cadena(rnd)
        rc, ra = resultado(C, c), resultado(A, c)
        if rc != ra:
            discrepan += 1
            if discrepan <= 5:
                print("DISCREPA en la iteracion %d:\n  construccion: %s\n  arquitecto:   %s\n  kinds: %s" % (it, rc, ra, [json.loads(C.b64d(s.split(".")[1]))["kind"] for s in c]))
        if rc.startswith("{"):
            validas += 1
            estado = json.loads(rc)["final_state"]
            codigos["valida:" + estado] = codigos.get("valida:" + estado, 0) + 1
        else:
            k = rc.split()[1]
            codigos[k] = codigos.get(k, 0) + 1
    print("cadenas: %d, validas: %d, discrepancias: %d" % (n, validas, discrepan))
    print("veredictos: " + json.dumps(dict(sorted(codigos.items(), key=lambda x: -x[1]))))
    return 1 if discrepan else 0


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 5000, int(sys.argv[2]) if len(sys.argv) > 2 else 20261020))
