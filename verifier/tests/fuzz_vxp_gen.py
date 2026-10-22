"""Generator for the differential fuzz of vxp-verify.js against the Python reference.

Reuses the chain generator of reference/scripts/fuzz-diferencial.py (random chains,
correctly signed with the TEST keys of the vectors, mixing valid and invalid steps) and adds
mutations that reach the parsers: selective disclosures (valid and broken), re-signed payloads
and headers with non-canonical JSON, duplicate members, floats, big integers, lone surrogates,
other text encodings, and raw character edits of the compact form.

For each chain it runs the reference `verificar_cadena` and writes one JSON line:
  {"chain": [...], "ref": <verdict JSON line> | {"valid": false, "error": code, "seq": s} | "PYTHON_EXCEPTION"}

Usage: python fuzz_vxp_gen.py <iterations> <seed> <out.jsonl>
"""
import base64
import hashlib
import importlib.util
import json
import os
import random
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

REFERENCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "reference")


def cargar(nombre, ruta):
    spec = importlib.util.spec_from_file_location(nombre, ruta)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


F = cargar("fuzz_diferencial", os.path.join(REFERENCE, "scripts", "fuzz-diferencial.py"))
C = F.C  # the reference verifier, verifier/verificar_paquete.py


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def firmar_bytes(rol, hbytes, pbytes, discl=()):
    h, p = b64e(hbytes), b64e(pbytes)
    r, s = decode_dss_signature(F.PRIV[rol].sign((h + "." + p).encode(), ec.ECDSA(hashes.SHA256())))
    return h + "." + p + "." + b64e(r.to_bytes(32, "big") + s.to_bytes(32, "big")) + "~" + "".join(d + "~" for d in discl)


def header_ok(rol):
    return C.jcs({"alg": "ES256", "kid": F.KID[rol], "typ": "vxp-stmt+sd-jwt"}).encode()


def disclose(rnd, p, limpio=False):
    """Moves one or more body members (or array elements) into disclosures, sometimes broken."""
    if limpio:
        rnd = Limpio(rnd)
    b = p["body"]
    discl = []
    claves = [k for k in b if k not in ("_sd",)]
    rnd.shuffle(claves)
    for k in claves[: rnd.choice([1, 1, 2, 3])]:
        sal = b64e(os.urandom(rnd.choice([16] * 8 + [8, 32]) if not limpio else 16))
        r = rnd.random()
        if r < 0.05:
            sal = "!!" + sal  # non-validating base64 of the salt
        elif r < 0.08:
            sal = 12345
        nombre = k if limpio or rnd.random() < 0.95 else rnd.choice(["_sd", "...", list(b)[0]])
        contenido = [sal, nombre, b[k]]
        if rnd.random() < 0.03:
            contenido = contenido[:2]
        txt = json.dumps(contenido, ensure_ascii=rnd.random() < 0.5)
        if rnd.random() < 0.03:
            txt = '["%s", "%s", 1, "x"]' % (sal if isinstance(sal, str) else "s", nombre) if rnd.random() < 0.5 else '{"a": 1, "a": 2}'
        d = b64e(txt.encode("utf-8"))
        if rnd.random() < 0.02:
            d = d + "="  # padded: non canonical
        h = b64e(hashlib.sha256(d.encode()).digest())
        if nombre == k:
            del b[k]
        b.setdefault("_sd", []).append(h)
        discl.append(d)
        if rnd.random() < 0.03:
            discl.append(d)  # repeated disclosure
    if rnd.random() < 0.05:
        b.setdefault("_sd", []).append(b64e(os.urandom(32)))  # decoy digest
    if rnd.random() < 0.03 and b.get("_sd"):
        b["_sd"].append(b["_sd"][0])  # repeated digest
    if rnd.random() < 0.03:
        discl.append(b64e(json.dumps([b64e(os.urandom(16)), "huerfana", 1]).encode()))  # unused
    if rnd.random() < 0.03:
        p["_sd_alg"] = rnd.choice(["sha-256", "sha-512"])
    if rnd.random() < 0.02:
        b["_sd_alg"] = "sha-256"
    # array element disclosure inside observed / read_back_terms
    for k in ("read_back_terms", "claimed_assurance"):
        if isinstance(b.get(k), list) and b[k] and rnd.random() < 0.3:
            sal = b64e(os.urandom(16))
            d = b64e(json.dumps([sal, b[k][0]]).encode())
            b[k][0] = {"...": b64e(hashlib.sha256(d.encode()).digest())}
            discl.append(d)
    return discl


class Limpio:
    """A random source whose random() never triggers a breaking branch (always >= 0.999)."""

    def __init__(self, rnd):
        self.r = rnd

    def random(self):
        return 0.9995

    def __getattr__(self, n):
        return getattr(self.r, n)


def cadena_valida(rnd):
    """A chain that follows the protocol, with varied approval, review, read-back, outcome,
    corrections and revocation; valid selective disclosures in part of the statements."""
    TD1 = F.TD[0]
    crr = rnd.random() < 0.3
    rbt = rnd.choice([["pedido", "despacho_nuevo"], ["pedido"], []])
    metodo = rnd.choice(["agent_asserted", "company_channel"])
    g = [("request", {"channel": "poppy", "client_id": "x", "request_digest": F.TD[2]}),
         ("terms", {"revision": 1, "terms_digest": TD1, "capability": "c", "expires_at": None, "user_approval_required": True, "company_review_required": crr, "read_back_terms": rbt})]
    rev, td = 1, TD1
    if rnd.random() < 0.3:
        g.append(("counter", {"base_revision": 1, "counter_digest": F.TD[2], "from": "personal_agent"}))
        rev, td = 2, F.TD[1]
        g.append(("terms", {"revision": 2, "terms_digest": td, "capability": "c", "expires_at": None, "user_approval_required": True, "company_review_required": crr, "read_back_terms": rbt}))
    estado_final = rnd.choice(["succeeded"] * 3 + ["failed", "cancelled", "expired", "unknown"])
    aprobado = rnd.random() < 0.9 or estado_final == "succeeded"
    ejecutado = False
    if aprobado:
        ua = {"revision": rev, "terms_digest": td, "method": metodo, "evidence": {}}
        if metodo == "company_channel":
            ua["display_code"] = C.codigo_visible(td)
        g.append(("user_approval", ua))
        negado = False
        if crr or rnd.random() < 0.2:
            negado = (not crr and rnd.random() < 0.3) or (crr and rnd.random() < 0.15)
            g.append(("company_review", {"revision": rev, "terms_digest": td, "decision": "denied" if negado else "approved", "role": "r"}))
        if negado:
            estado_final = "failed"
        elif estado_final == "succeeded" or rnd.random() < 0.6:
            ejecutado = True
            g.append(("execution", {"revision": rev, "terms_digest": td, "capability": "c", "release": F.TD[2], "attempt": 1}))
            for _ in range(1 if estado_final == "succeeded" else rnd.choice([0, 1, 2])):
                ok = estado_final == "succeeded" or rnd.random() < 0.5
                # 15% of matching read-backs miss a required term: the reference says read_back_incomplete
                obs = {"pedido": "P", "despacho_nuevo": "d"} if (ok and rnd.random() < 0.85) or (not ok and rnd.random() < 0.5) else {"pedido": "P"}
                g.append(("read_back", {"method": "system_read_back" if ok else rnd.choice(["manual", "none", "system_read_back"]), "source": "company_system", "matches_terms": ok, "observed": obs}))
    if not ejecutado and estado_final == "succeeded":
        estado_final = "unknown"
    if not rbt and estado_final == "succeeded":
        estado_final = "unknown"  # an empty read_back_terms can never be complete
    g.append(("outcome", {"state": estado_final, "revision": rev, "terms_digest": td, "result_summary_digest": F.TD[2], "claimed_assurance": ["x"], "third_party": []}))
    finales = ["outcome"]
    for _ in range(rnd.choice([0, 0, 1, 2])):
        st = rnd.choice(["failed", "unknown", "succeeded"] if ejecutado and rbt else ["failed", "unknown"])
        if st == "succeeded":
            g.append(("read_back", {"method": "system_read_back", "source": "company_system", "matches_terms": True, "observed": {"pedido": "P", "despacho_nuevo": "d"} if rnd.random() < 0.85 else {"despacho_nuevo": "d"}}))
        g.append(("correction", {"state": st, "reason": "r", "_cita": st == "succeeded"}))
    if rnd.random() < 0.15:
        g.append(("revocation", {"reason": "r"}))
    c, prev, ultimo_final, ultima_lectura = [], None, None, None
    for i, (k, b) in enumerate(g):
        b = json.loads(json.dumps(b))
        if k == "correction":
            b["corrects"] = ultimo_final
            if b.pop("_cita"):
                b["read_back"] = ultima_lectura
        if k == "revocation":
            b["revokes"] = ultimo_final
        p = {"v": "0.1", "kind": k, "iss": F.EMP if F.ROL[k] == "company" else F.OPE, "company": F.EMP, "op": "op_f", "seq": i, "prev": prev,
             "iat": 1, "aud": "a", "user": "u", "body": b}
        discl = disclose(rnd, p, limpio=True) if rnd.random() < 0.25 else []
        sd = firmar_bytes(F.ROL[k], header_ok(F.ROL[k]), C.jcs(p).encode("utf-8"), discl)
        h = C.huella_declaracion(sd.split("~")[0])
        if k in ("outcome", "correction", "revocation"):
            ultimo_final = h
        if k == "read_back":
            ultima_lectura = h
        c.append(sd)
        prev = h
    return c


def payload_text(rnd, p):
    """The payload bytes: canonical most of the time, otherwise one of the parser edge cases."""
    canon = C.jcs(p)
    r = rnd.random()
    if r < 0.80:
        return canon.encode("utf-8")
    m = rnd.choice(["ws", "dup", "float", "bool_seq", "bigint", "lone", "pair_escape", "order", "bom", "utf16", "nan", "ctrl", "nonascii_key", "lone_key", "escape_slash", "trailing"])
    if m == "ws":
        return json.dumps(p, sort_keys=True).encode()
    if m == "dup":
        return ('{"kind":"x",' + canon[1:]).encode()
    if m == "float":
        return canon.replace('"seq":%d' % p["seq"], '"seq":%d.0' % p["seq"]).encode()
    if m == "bool_seq":
        return canon.replace('"seq":1,', '"seq":true,').encode()
    if m == "bigint":
        return canon.replace('"iat":1', '"iat":%d' % (2 ** 60)).encode()
    if m == "lone":
        return canon.replace('"aud":"a"', '"aud":"a\\ud800"').encode()
    if m == "pair_escape":
        return canon.replace('"aud":"a"', '"aud":"\\ud83d\\ude00"').encode()
    if m == "order":
        return json.dumps(p, separators=(",", ":"), ensure_ascii=False).encode()
    if m == "bom":
        return b"\xef\xbb\xbf" + canon.encode()
    if m == "utf16":
        return canon.encode("utf-16-le")
    if m == "nan":
        return canon.replace('"iat":1', '"iat":NaN').encode()
    if m == "ctrl":
        return canon.replace('"aud":"a"', '"aud":"a\tb"').encode()
    if m == "nonascii_key":
        q = dict(p)
        q["ñandú"] = "€"
        return C.jcs(q).encode("utf-8")
    if m == "lone_key":
        return canon.replace('"aud":"a"', '"aud":"a","\\udc00":1').encode()
    if m == "escape_slash":
        return canon.replace('"aud":"a"', '"aud":"a\\/"').encode()
    return (canon + " ").encode()


def header_bytes(rnd, rol):
    r = rnd.random()
    if r < 0.93:
        return header_ok(rol)
    m = rnd.choice(["utf16", "dup", "crit", "legacy", "nokid", "bom", "alg"])
    base = {"alg": "ES256", "kid": F.KID[rol], "typ": "vxp-stmt+sd-jwt"}
    if m == "utf16":
        return C.jcs(base).encode("utf-16-be")
    if m == "dup":
        return ('{"alg":"none",' + C.jcs(base)[1:]).encode()
    if m == "crit":
        return C.jcs(dict(base, crit=["x"])).encode()
    if m == "legacy":
        return C.jcs(dict(base, typ="sovras-stmt+sd-jwt")).encode()
    if m == "nokid":
        return C.jcs({"alg": "ES256", "typ": "vxp-stmt+sd-jwt"}).encode()
    if m == "bom":
        return b"\xef\xbb\xbf" + C.jcs(base).encode()
    return C.jcs(dict(base, alg="ES384")).encode()


def editar_crudo(rnd, sd):
    s = list(sd)
    for _ in range(rnd.choice([1, 1, 2])):
        i = rnd.randrange(len(s))
        op = rnd.random()
        ch = rnd.choice(list("A_-=~.+/ \u00e9") + ["\x00"])
        if op < 0.4:
            s[i] = ch
        elif op < 0.7:
            s.insert(i, ch)
        else:
            del s[i]
    return "".join(s)


def cadena_mutada(rnd, intensidad):
    st = {"rev": 0, "td": F.TD[0], "huellas": [], "finales": [], "lecturas": []}
    c, prev = [], None
    for i, k in enumerate(F.guion(rnd)):
        b = F.cuerpo(k, rnd, st)
        if k == "terms" and isinstance(b["revision"], int):
            st["rev"], st["td"] = b["revision"], b["terms_digest"]
        p = {"v": "0.1", "kind": k, "iss": F.EMP if F.ROL[k] == "company" else F.OPE, "company": F.EMP, "op": "op_f", "seq": i, "prev": prev,
             "iat": 1, "aud": "a", "user": rnd.choice(["u"] * 30 + ["v"]), "body": b}
        rol = F.ROL[k] if rnd.random() < 0.98 else ("operator" if F.ROL[k] == "company" else "company")
        discl = disclose(rnd, p) if rnd.random() < intensidad else []
        if rnd.random() < intensidad * 0.4:
            hb, pb = header_bytes(rnd, rol), payload_text(rnd, p)
        else:
            hb, pb = header_ok(rol), C.jcs(p).encode("utf-8")
        sd = firmar_bytes(rol, hb, pb, discl)
        if rnd.random() < intensidad * 0.08:
            sd = editar_crudo(rnd, sd)
        jwt = sd.split("~")[0]
        h = "sha-256:" + b64e(hashlib.sha256(jwt.rsplit(".", 1)[0].encode("ascii", "replace")).digest())
        st["huellas"].append(h)
        if k in ("outcome", "correction", "revocation"):
            st["finales"].append(h)
        if k == "read_back":
            st["lecturas"].append(h)
        c.append(sd)
        prev = h
    return c


def referencia(c):
    try:
        r = C.verificar_cadena(c, F.LLAVES, F.EMP, "operator_hosted")
        return json.dumps(r[0], ensure_ascii=False)
    except C.Falla as e:
        # the verdict object exactly as the reference main() builds it (verificar_paquete.py:1101-1103)
        salida = {"valid": False, "error": e.code, "seq": e.seq}
        if e.code == "no_outcome":
            salida["final_state"] = "unknown"
        return json.dumps(salida, ensure_ascii=False)
    except Exception:
        return "PYTHON_EXCEPTION"


def tagged(v):
    """Type-exact view of a parsed value, comparable across languages."""
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, int):
        return ["int", str(v)]
    if isinstance(v, float):
        return ["float", repr(v)]
    if isinstance(v, str):
        return ["str", [ord(c) for c in v]]
    if isinstance(v, list):
        return ["list", [tagged(x) for x in v]]
    return ["dict", [[tagged(k), tagged(x)] for k, x in v.items()]]


PIEZAS = ['{', '}', '[', ']', ',', ':', '"a"', '"a"', '1', '-0', '1.0', '1e5', '1E-2', '01', 'true', 'null', 'NaN', '-Infinity',
          r'"\ud800"', r'"😀"', r'"\udc00\ud800"', r'"é"', r'"\x"', '"\t"', ' ', '\n', '"é"',
          '9007199254740993', r'"\/"', '"\ud800"', r'"\ud83d', '\ude00"']


def primitivas(rnd, n):
    """Inputs for the two Python primitives the verdicts depend on most: b64d and leer_json."""
    out = []
    alfabeto = list("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/=") + ["!", " ", ".", "é", "\n"]
    for _ in range(n):
        s = "".join(rnd.choice(alfabeto) for _ in range(rnd.randrange(0, 12)))
        try:
            ref = C.b64d(s).hex()
        except C.Falla as e:
            ref = "FALLA:" + e.code
        except Exception:
            ref = "EXC"
        out.append({"prim": "b64d", "in": s, "ref": ref})
    for _ in range(n):
        if rnd.random() < 0.5:
            v = rnd.choice([{"a": [1, 2.5, None, True, "é\U0001F600"]}, [1, {"b": "c"}], "x", 1, {"k": {"k2": [{}]}}, {"a": 1, "b": -0}])
            txt = json.dumps(v, ensure_ascii=rnd.random() < 0.5)
        else:
            txt = "".join(rnd.choice(PIEZAS) for _ in range(rnd.randrange(1, 9)))
        enc = rnd.choice(["utf-8"] * 6 + ["utf-8-sig", "utf-16-le", "utf-16-be", "utf-16", "utf-32-le", "utf-32", "raw"])
        if enc == "raw":
            b = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 8)))
        else:
            b = txt.encode(enc, "surrogatepass")
        try:
            ref = tagged(C.leer_json(b))
        except C.Falla as e:
            ref = "FALLA:" + e.code
        except Exception:
            ref = "EXC"
        out.append({"prim": "json", "in_hex": b.hex(), "ref": ref})
    return out


def main(n, semilla, ruta):
    rnd = random.Random(semilla)
    with open(ruta, "w", encoding="utf-8") as f:
        for it in range(n):
            # first half: the original fuzz-diferencial generator untouched; second half: mutated
            # 40%: the original fuzz-diferencial generator untouched; 25%: guided chains that follow
            # the protocol; 35%: mutated chains that reach the parsers
            if it < n * 40 // 100:
                c = F.cadena(rnd)
            elif it < n * 65 // 100:
                c = cadena_valida(rnd)
            else:
                c = cadena_mutada(rnd, rnd.choice([0.3, 0.6, 1.0]))
            f.write(json.dumps({"it": it, "chain": c, "ref": referencia(c)}, ensure_ascii=True) + "\n")
        for x in primitivas(rnd, n):
            f.write(json.dumps(x, ensure_ascii=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]))
