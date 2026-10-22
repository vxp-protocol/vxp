"""Verificador independiente de VXP Proof 0.1 (especificacion VXP, anexo normativo, seccion 9).

No comparte codigo con el emisor: Python + la libreria `cryptography`, frente a un emisor en
Node con node:crypto. Lee vectores-0.1.json y comprueba:
  - las huellas recalculadas desde los insumos en claro (SPEC 9.3: siempre JCS),
  - las cadenas V1, V2 y V3 (deben ser validas y dar el veredicto esperado),
  - el registro Merkle (RFC 9162),
  - que cada vector negativo falle con el codigo esperado,
  - el anclaje del issuer (SPEC 9.9.1) en cada caso de descubrimiento.
Uso: python verificar.py vectores-0.1.json

Historia: se escribio antes de que existiera el emisor de reference/src/. En la correccion de
la ronda 1 de revision (20-oct-2026) se reescribio para cerrar M1-M6 y B1; desde
entonces no es independiente en autor de verificar_paquete.py.
"""
import base64
import hashlib
import hmac
import json
import re
import sys
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ROLES = {
    "company": {"terms", "company_review", "outcome", "correction", "revocation"},
    "operator": {"request", "counter", "user_approval", "execution", "read_back"},
}
FINALES = {"succeeded", "failed", "cancelled", "expired", "unknown"}
B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


class Falla(Exception):
    def __init__(self, code, seq=None):
        super().__init__(code)
        self.code = code
        self.seq = seq


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64_estricto(s, idx):
    """Decodifica solo si `s` es la codificacion base64url canonica de sus bytes (SPEC 9.2)."""
    if not isinstance(s, str) or not B64URL.match(s) or len(s) % 4 == 1:
        raise Falla("non_canonical_encoding", idx)
    b = b64d(s)
    if b64e(b) != s:
        raise Falla("non_canonical_encoding", idx)
    return b


def sha(b):
    return hashlib.sha256(b).digest()


def dig(b):
    return "sha-256:" + b64e(sha(b))


def jcs(v):
    """RFC 8785 restringido al perfil 0.1 (sin numeros no enteros, sin surrogates sueltos)."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > 2**53 - 1:
            raise Falla("number_out_of_profile")
        return str(v)
    if isinstance(v, float):
        raise Falla("number_out_of_profile")
    if isinstance(v, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
            raise Falla("lone_surrogate")
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in keys) + "}"
    raise Falla("not_json")


def huella(x):
    """Huella de un valor JSON cualquiera: la de su JCS (SPEC 9.3)."""
    return dig(jcs(x).encode("utf-8"))


def id_declaracion(jwt):
    """Huella de una declaracion: SHA-256 de `encabezado.payload` (SPEC 9.2), sin la firma."""
    h64, p64, _ = jwt.split(".")
    return dig((h64 + "." + p64).encode("ascii"))


def sin_duplicados(pares):
    d = {}
    for k, val in pares:
        if k in d:
            raise Falla("duplicate_member")
        d[k] = val
    return d


def clave_publica(jwk):
    x = int.from_bytes(b64d(jwk["x"]), "big")
    y = int.from_bytes(b64d(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def thumbprint(jwk):
    return b64e(sha(jcs({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}).encode("utf-8")))


class Divulgaciones:
    """RFC 9901 seccion 7.1, pasos 3 a 5, con el perfil 0.1 (sha-256, sal >= 128 bits)."""

    def __init__(self, crudas, idx):
        self.idx = idx
        self.tabla = {}
        for d in crudas:
            h = b64e(sha(d.encode("ascii")))
            if h in self.tabla:
                raise Falla("disclosure_repeated", idx)
            try:
                self.tabla[h] = json.loads(b64_estricto(d, idx), object_pairs_hook=sin_duplicados)
            except Falla as e:
                if e.code == "non_canonical_encoding":
                    raise
                raise Falla("disclosure_malformed", idx)
            except ValueError:
                raise Falla("disclosure_malformed", idx)
        self.encontradas = set()
        self.usadas = set()

    def _registrar(self, h):
        if h in self.encontradas:
            raise Falla("sd_digest_repeated", self.idx)
        self.encontradas.add(h)
        return self.tabla.get(h)

    def _sal(self, s):
        if not isinstance(s, str):
            raise Falla("disclosure_malformed", self.idx)
        if len(b64d(s)) < 16:
            raise Falla("weak_salt", self.idx)

    def objeto(self, o, nivel_superior=False):
        if "_sd_alg" in o and (not nivel_superior or o["_sd_alg"] != "sha-256"):
            raise Falla("bad_sd_alg", self.idx)
        out = {}
        for k, v in o.items():
            if k != "_sd" and k != "_sd_alg":
                out[k] = self.valor(v)
        sd = o.get("_sd", [])
        if not isinstance(sd, list) or not all(isinstance(x, str) for x in sd):
            raise Falla("bad_sd", self.idx)
        for h in sd:
            d = self._registrar(h)
            if d is None:
                continue
            if not (isinstance(d, list) and len(d) == 3 and isinstance(d[1], str)):
                raise Falla("disclosure_malformed", self.idx)
            self._sal(d[0])
            if d[1] == "_sd" or d[1] == "...":
                raise Falla("disclosure_bad_name", self.idx)
            if d[1] in out:
                raise Falla("disclosure_claim_exists", self.idx)
            self.usadas.add(h)
            out[d[1]] = self.valor(d[2])
        return out

    def arreglo(self, a):
        out = []
        for x in a:
            if isinstance(x, dict) and "..." in x:
                if set(x) != {"..."} or not isinstance(x["..."], str):
                    raise Falla("bad_sd", self.idx)
                d = self._registrar(x["..."])
                if d is None:
                    continue
                if not (isinstance(d, list) and len(d) == 2):
                    raise Falla("disclosure_malformed", self.idx)
                self._sal(d[0])
                self.usadas.add(x["..."])
                out.append(self.valor(d[1]))
            else:
                out.append(self.valor(x))
        return out

    def valor(self, v):
        if isinstance(v, dict):
            return self.objeto(v)
        if isinstance(v, list):
            return self.arreglo(v)
        return v

    def procesar(self, payload):
        r = self.objeto(payload, nivel_superior=True)
        if set(self.tabla) != self.usadas:
            raise Falla("disclosure_digest_mismatch", self.idx)
        return r


def abrir(sdjwt, llaves, idx):
    partes = sdjwt.split("~")
    if len(partes) < 2 or partes[-1] != "":
        raise Falla("not_sd_jwt", idx)
    jwt, discl = partes[0], partes[1:-1]
    seg = jwt.split(".")
    if len(seg) != 3:
        raise Falla("not_sd_jwt", idx)
    h64, p64, s64 = seg
    hb, pbytes, sig = b64_estricto(h64, idx), b64_estricto(p64, idx), b64_estricto(s64, idx)
    header = json.loads(hb, object_pairs_hook=sin_duplicados)
    if header.get("typ") != "vxp-stmt+sd-jwt" or header.get("alg") != "ES256" or "crit" in header:
        raise Falla("bad_header", idx)
    payload = json.loads(pbytes, object_pairs_hook=sin_duplicados)
    iss = payload.get("iss")
    rol = next((r for r, k in llaves.items() if k["issuer"] == iss), None)
    if rol is None:
        raise Falla("unknown_issuer", idx)
    jwk = next((k for k in llaves[rol]["jwks"]["keys"] if k["kid"] == header.get("kid")), None)
    if jwk is None or thumbprint(jwk) != jwk["kid"]:
        raise Falla("unknown_key", idx)
    if len(sig) != 64:
        raise Falla("signature_invalid", idx)
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        clave_publica(jwk).verify(der, (h64 + "." + p64).encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Falla("signature_invalid", idx)
    if jcs(payload).encode("utf-8") != pbytes:
        raise Falla("non_canonical_payload", idx)
    if payload.get("kind") not in ROLES[rol]:
        raise Falla("role_mismatch", idx)
    return jwt, Divulgaciones(discl, idx).procesar(payload), rol


class Cadena:
    """Las reglas 5 a 9 de SPEC 9.5 como una maquina de estados."""

    def __init__(self, empresa):
        self.empresa = empresa
        self.fijos = None  # (op, aud, user) de seq 0
        self.prev = None
        self.rev = 0
        self.td = None
        self.terminos = None  # cuerpo de la ultima terms (ronda 3)
        self.aprobacion = None
        self.decision = None
        self.ejecucion = None
        self.lectura = None
        self.lectura_ok_alguna = False
        self.estado = None
        self.final = None
        self.lecturas_tras_final = {}

    def paso(self, i, jwt, p):
        if p.get("v") != "0.1":
            raise Falla("bad_version", i)
        if p.get("company") != self.empresa:
            raise Falla("company_mismatch", i)
        actual = (p.get("op"), p.get("aud"), p.get("user"))
        if self.fijos is None:
            self.fijos = actual
        if actual[0] != self.fijos[0]:
            raise Falla("op_mismatch", i)
        if actual[1] != self.fijos[1]:
            raise Falla("aud_mismatch", i)
        if actual[2] != self.fijos[2]:
            raise Falla("user_mismatch", i)
        if p.get("seq") != i:
            raise Falla("seq_error", i)
        if p.get("prev") != self.prev:
            raise Falla("chain_broken", i)
        b = p.get("body")
        if not isinstance(b, dict):
            raise Falla("bad_body", i)
        k = p["kind"]
        yo = id_declaracion(jwt)
        if self.estado is not None and k not in ("read_back", "correction", "revocation"):
            raise Falla("after_final", i)
        if (i == 0) != (k == "request"):
            raise Falla("order_violation", i)
        getattr(self, "k_" + k)(i, b, yo)
        self.prev = yo

    def k_request(self, i, b, yo):
        pass

    def k_terms(self, i, b, yo):
        if self.aprobacion is not None or b.get("revision") != self.rev + 1:
            raise Falla("revision_error", i)
        campos = b.get("read_back_terms")
        if type(b.get("company_review_required")) is not bool or type(campos) is not list:
            raise Falla("bad_terms", i)
        if any(type(c) is not str for c in campos) or len(campos) != len(set(campos)):
            raise Falla("bad_terms", i)
        self.rev, self.td, self.terminos = b["revision"], b.get("terms_digest"), b

    def k_counter(self, i, b, yo):
        if self.aprobacion is not None:
            raise Falla("order_violation", i)
        if self.rev == 0 or b.get("base_revision") != self.rev:
            raise Falla("revision_error", i)

    def k_user_approval(self, i, b, yo):
        if self.aprobacion is not None or self.rev == 0:
            raise Falla("order_violation", i)
        if b.get("revision") != self.rev:
            raise Falla("approval_not_latest_revision", i)
        if b.get("terms_digest") != self.td:
            raise Falla("approval_terms_mismatch", i)
        metodo = b.get("method")
        if metodo not in ("agent_asserted", "company_channel"):
            raise Falla("bad_approval_method", i)
        if metodo == "company_channel":
            codigo = str(int.from_bytes(sha(self.td.encode("utf-8"))[:4], "big") % 1000000).zfill(6)
            if b.get("display_code") != codigo:
                raise Falla("display_code_mismatch", i)
        self.aprobacion = b

    def k_company_review(self, i, b, yo):
        a = self.aprobacion
        if a is None or self.ejecucion is not None or self.decision is not None:
            raise Falla("order_violation", i)
        if (b.get("revision"), b.get("terms_digest")) != (a["revision"], a["terms_digest"]):
            raise Falla("order_violation", i)
        if b.get("decision") not in ("approved", "denied"):
            raise Falla("bad_decision", i)
        self.decision = b["decision"]

    def k_execution(self, i, b, yo):
        a = self.aprobacion
        if a is None or self.ejecucion is not None or self.decision == "denied":
            raise Falla("order_violation", i)
        if self.terminos["company_review_required"] and self.decision != "approved":
            raise Falla("order_violation", i)
        if (b.get("revision"), b.get("terms_digest")) != (a["revision"], a["terms_digest"]):
            raise Falla("execution_terms_mismatch", i)
        self.ejecucion = b

    def k_read_back(self, i, b, yo):
        if self.ejecucion is None:
            raise Falla("order_violation", i)
        if b.get("method") not in ("system_read_back", "manual", "none") or type(b.get("matches_terms")) is not bool:
            raise Falla("bad_read_back", i)
        ok = b["method"] == "system_read_back" and b["matches_terms"]
        self.lectura_ok_alguna |= ok
        if self.estado is None:
            self.lectura = b
        else:
            self.lecturas_tras_final[yo] = (ok, b)

    def k_outcome(self, i, b, yo):
        if self.rev == 0:
            raise Falla("order_violation", i)
        if (b.get("revision"), b.get("terms_digest")) != (self.rev, self.td):
            raise Falla("outcome_terms_mismatch", i)
        st = b.get("state")
        if st not in FINALES:
            raise Falla("bad_state", i)
        if self.decision == "denied" and st != "failed":
            raise Falla("outcome_after_denial", i)
        if st == "succeeded":
            l = self.lectura
            if self.ejecucion is None or l is None or l.get("method") != "system_read_back" or l.get("matches_terms") is not True:
                raise Falla("succeeded_without_matching_read_back", i)
            if not self.observa_el_efecto(l):
                raise Falla("read_back_incomplete", i)
        self.estado, self.final, self.lecturas_tras_final = st, yo, {}

    def k_correction(self, i, b, yo):
        if self.estado is None or b.get("corrects") != self.final:
            raise Falla("order_violation", i)
        st = b.get("state")
        if st not in FINALES:
            raise Falla("bad_state", i)
        if st == "succeeded":
            ok, lectura = self.lecturas_tras_final.get(b.get("read_back"), (False, None))
            if ok is not True:
                raise Falla("correction_without_read_back", i)
            if not self.observa_el_efecto(lectura):
                raise Falla("read_back_incomplete", i)
        self.estado, self.final, self.lecturas_tras_final = st, yo, {}

    def observa_el_efecto(self, lectura):
        """SPEC 9.4.7, ronda 3: cada nombre de read_back_terms esta en observed (ya procesado)."""
        nombres = (self.terminos or {}).get("read_back_terms") or []
        obs = (lectura or {}).get("observed")
        return len(nombres) > 0 and type(obs) is dict and set(nombres) <= set(obs)

    def k_revocation(self, i, b, yo):
        if self.estado is None or b.get("revokes") != self.final:
            raise Falla("order_violation", i)
        self.estado, self.final, self.lecturas_tras_final = "revoked", yo, {}


def verificar_cadena(cadena, llaves, empresa, custodia):
    c = Cadena(empresa)
    procesados = []
    for i, sdjwt in enumerate(cadena):
        jwt, p, _ = abrir(sdjwt, llaves, i)
        c.paso(i, jwt, p)
        procesados.append(p)
    if c.estado is None:
        raise Falla("no_outcome")
    vigente = c.aprobacion if c.decision != "denied" else None
    asegura = ["issuer_key_attested"]
    if c.ejecucion is not None:
        asegura.append("operator_observed")
    if c.lectura_ok_alguna:
        asegura.append("operator_reported_read_back")
    if vigente is not None:
        asegura.append({"company_channel": "operator_reported_channel_approval", "agent_asserted": "operator_reported_agent_approval"}[vigente["method"]])
    veredicto = {
        "valid": True,
        "final_state": c.estado,
        "revision": vigente["revision"] if vigente else None,
        "approval": vigente["method"] if vigente else None,
        "derived_assurance": asegura,
        "single_root": "operator",  # SPEC 9.6: la 0.1 no define evidencia de una segunda raiz
        "custody_declared": custodia,
        "logged": False,
    }
    return veredicto, procesados


# ---------- anclaje del issuer (SPEC 9.9.1) ----------

def _bajo(base, url):
    if not isinstance(base, str) or not isinstance(url, str):
        return False
    b, u = urlsplit(base), urlsplit(url)
    raiz = b.path[:-1] if b.path.endswith("/") else b.path
    return (b.scheme, b.netloc.lower()) == (u.scheme, u.netloc.lower()) and u.path.startswith(raiz + "/") and not u.query and not u.fragment


def anclar(docs, ancla):
    """Devuelve (issuer, llaves, custodia) o levanta issuer_not_anchored."""
    def doc(url):
        if url not in docs:
            raise Falla("issuer_not_anchored")
        return docs[url]

    copia = None
    if "domain" in ancla:
        d = ancla["domain"]
        pj = doc("https://" + d + "/.well-known/poppy.json")
        if str(pj.get("organization", {}).get("domain", "")).lower() != d.lower():
            raise Falla("issuer_not_anchored")
        iss = pj.get("auth", {}).get("issuer")
        copia = pj.get("extensions", {}).get("vxpprotocol.org/proof")
    else:
        iss = ancla["issuer"]
        if "card" in ancla:
            exts = doc(ancla["card"]).get("capabilities", {}).get("extensions", [])
            copia = next((e.get("params") for e in exts if e.get("uri") == "https://vxpprotocol.org/ext/proof/v0.1"), None)
            if copia is None:
                raise Falla("discovery_without_extension")
    s = urlsplit(iss)
    meta = doc(s.scheme + "://" + s.netloc + "/.well-known/oauth-authorization-server" + s.path.rstrip("/"))
    if meta.get("issuer") != iss:
        raise Falla("issuer_not_anchored")
    if "domain" in ancla and ancla["domain"].lower() not in [x.lower() for x in meta.get("poppy_domains", [])]:
        raise Falla("issuer_not_anchored")
    t = meta.get("vxp_proof")
    if not isinstance(t, dict) or t.get("company") != iss:
        raise Falla("issuer_not_anchored")
    if not _bajo(iss, t.get("jwks_uri")) or not _bajo(t.get("operator", {}).get("issuer"), t.get("operator", {}).get("jwks_uri")):
        raise Falla("issuer_not_anchored")
    if copia is not None and any(jcs(copia.get(m)) != jcs(t.get(m)) for m in ("version", "company", "jwks_uri", "operator", "custody", "log", "domains", "pact")):
        raise Falla("issuer_not_anchored")
    llaves = {
        "company": {"issuer": iss, "jwks": doc(t["jwks_uri"])},
        "operator": {"issuer": t["operator"]["issuer"], "jwks": doc(t["operator"]["jwks_uri"])},
    }
    return iss, llaves, t.get("custody")


# ---------- registro ----------

def hoja(d):
    return sha(b"\x00" + d)


def nodo(l, r):
    return sha(b"\x01" + l + r)


def mth(D):
    if len(D) == 1:
        return hoja(D[0])
    k = 1
    while k * 2 < len(D):
        k *= 2
    return nodo(mth(D[:k]), mth(D[k:]))


def inclusion(indice, tam, h, camino, raiz):
    """RFC 9162 seccion 2.1.3.2."""
    if indice >= tam:
        return False
    fn, sn, r = indice, tam - 1, h
    for p in camino:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = nodo(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = nodo(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == raiz


def con_reemplazos(cadena, n):
    if "chain" in n:
        return list(n["chain"])
    c = list(cadena)
    for r in ([n["replace"]] if "replace" in n else []) + n.get("replace_many", []):
        orig = c[r["seq"]].split("~")
        c[r["seq"]] = "~".join([r["jwt"]] + orig[1:])
    if "replace_disclosure" in n:
        r = n["replace_disclosure"]
        partes = c[r["seq"]].split("~")
        partes[1 + r["index"]] = r["disclosure"]
        c[r["seq"]] = "~".join(partes)
    return c


def main(ruta):
    v = json.load(open(ruta, encoding="utf-8"))
    llaves = {"company": v["keys"]["company"], "operator": v["keys"]["operator"]}
    empresa = v["keys"]["company"]["issuer"]
    custodia = v["keys"]["company"]["custody"]
    cadena = [s["sdjwt"] for s in v["chain_v1"]]
    cuerpos = [json.loads(s["payload_jcs"])["body"] for s in v["chain_v1"]]
    ins = v["inputs"]
    fallas = 0

    def informe(nombre, ok, detalle=""):
        nonlocal fallas
        fallas += 0 if ok else 1
        print(("OK   " if ok else "FALLA") + " " + nombre + (" - " + detalle if detalle else ""))

    informe("terms_digest_2 recalculado", huella(ins["terminos2"]) == ins["terms_digest_2"])
    informe("jcs(terminos2) identico al del emisor", jcs(ins["terminos2"]) == ins["jcs_terms2"])
    td = ins["terms_digest_2"]
    codigo = str(int.from_bytes(sha(td.encode("utf-8"))[:4], "big") % 1000000).zfill(6)
    informe("display_code recalculado", codigo == ins["display_code_2"], codigo)
    for nombre, valor, insumo in (
        ("request_digest", cuerpos[0]["request_digest"], ins["solicitud"]),
        ("idempotency_key_digest", cuerpos[0]["idempotency_key_digest"], ins["idempotency_key"]),
        ("counter_digest", cuerpos[2]["counter_digest"], ins["contra"]),
        ("release", cuerpos[5]["release"], ins["release_closure"]),
        ("result_summary_digest", cuerpos[7]["result_summary_digest"], ins["resumenResultado"]),
    ):
        informe(nombre + " = huella JCS del insumo", valor == huella(insumo))

    veredicto, procesados = verificar_cadena(cadena, llaves, empresa, custodia)
    informe("cadena V1 valida y veredicto esperado", veredicto == v["expected_v1"], json.dumps(veredicto, ensure_ascii=False))
    for s in v["chain_v1"]:
        informe("huella seq %d" % s["seq"], id_declaracion(s["sdjwt"].split("~")[0]) == s["digest"])
    informe("divulgacion de la direccion, en su objeto", procesados[6]["body"]["observed"] == v["expected_processed_observed_seq6"])
    informe("firma maleada: misma huella", id_declaracion(v["malleated_outcome"]["jwt"]) == v["chain_v1"][7]["digest"])
    for nombre in ("v2", "v3"):
        x = v["chain_" + nombre]
        r, _ = verificar_cadena(cadena + x["extra"], llaves, empresa, custodia)
        informe("cadena " + nombre.upper(), r == x["expected"], json.dumps(r, ensure_ascii=False))

    # Ronda 3: V4, con la revision de la empresa exigida y aprobada antes de ejecutar.
    x = v["chain_v4"]
    r, _ = verificar_cadena(x["chain"], llaves, empresa, custodia)
    informe("cadena V4", r == x["expected"], json.dumps(r, ensure_ascii=False))
    for i, (s4, d4) in enumerate(zip(x["chain"], x["digests"])):
        informe("huella V4 seq %d" % i, id_declaracion(s4.split("~")[0]) == d4)

    log = v["log"]
    D = [b64d(x["leaf_input"]) for x in log["leaves"]]
    raiz = mth(D)
    informe("raiz Merkle", b64e(raiz) == log["root_hash"])
    k_tag = b64d(log["tag_key_TEST_ONLY"])
    op = json.loads(v["chain_v1"][0]["payload_jcs"])["op"]
    for x in log["leaves"]:
        s = cadena[x["seq"]].split("~")[0]
        commit = sha(b64d(x["salt"]) + s.encode("ascii"))
        tag = hmac.new(k_tag, (op + "|" + str(x["seq"])).encode("utf-8"), hashlib.sha256).digest()
        informe("hoja seq %d = compromiso + etiqueta" % x["seq"], commit + tag == b64d(x["leaf_input"]))
    for seq, clave in ((7, "inclusion_of_seq7"), (3, "inclusion_of_seq3")):
        camino = [b64d(p) for p in log[clave]]
        informe("inclusion seq %d" % seq, inclusion(seq, log["tree_size"], hoja(D[seq]), camino, raiz))
    camino = [b64d(p) for p in log["inclusion_of_seq7"]]
    informe("inclusion falla con otra hoja", not inclusion(7, log["tree_size"], hoja(D[6]), camino, raiz))

    for n in v["negative"]:
        try:
            verificar_cadena(con_reemplazos(cadena, n), llaves, empresa, custodia)
            informe(n["id"], False, "acepto una cadena que debia fallar con " + n["expect"])
        except Falla as e:
            informe(n["id"], e.code == n["expect"], "obtuvo %s en seq %s; esperado %s" % (e.code, e.seq, n["expect"]))

    for caso in v["discovery"]["cases"]:
        try:
            iss, ll, cust = anclar(v["discovery"]["docs"], caso["anchor"])
            r, _ = verificar_cadena(cadena, ll, iss, cust)
            informe(caso["id"], caso["expect"] == "valid" and iss == empresa and r["final_state"] == "succeeded", iss)
        except Falla as e:
            informe(caso["id"], e.code == caso["expect"], "obtuvo %s; esperado %s" % (e.code, caso["expect"]))

    print("\n%d fallas" % fallas)
    return 1 if fallas else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
