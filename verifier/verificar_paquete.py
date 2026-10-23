"""Independent verifier for VXP Proof 0.1 (VXP specification, normative annex, 9.5 and 9.9).

Shares no code with the issuer (reference/src/prueba.ts, TypeScript with node:crypto): Python with the
`cryptography` library. Uses only public material and anchors it to the company (SPEC 9.9.1): it starts
from a domain or an issuer the verifier already knows, never from a document supplied by whoever
presents the package; the keys come from the issuer's RFC 8414 metadata.

Modes:
  python verificar_paquete.py vectores <vectores-0.1.json>
      Conformance (SPEC 15): must yield exactly the verdicts and codes of appendix A.
  python verificar_paquete.py vivo (--dominio D | --marca D | --as-pact I | --issuer I [--card URL])
                                   --paquete <file> [--aud URL] [--operacion file]
                                   [--recibo-pact file] [--http-local]
      --marca: the brand domain (PACT 2.1: its Agent Card at /.well-known/agent-card.json).
      --as-pact: issuer of the PACT authorization server the agent learned when delegating.
  python verificar_paquete.py pact <vectores-pact-0.1.json>
      Conformance of the PACT anchoring and of the cross-check with the PACT receipt (SPEC appendix A.9).
      Fetches the public material over HTTP(S) and verifies a package.
  python verificar_paquete.py material --material <file> --paquete <file> [--aud URL]
                                       [--operacion file]
      Same, but with the public material already fetched:
      {"anchor": {"domain": D} | {"issuer": I, "card"?: URL}, "docs": {URL: content}}.

Output: one JSON line with the verdict. Exit code 0 if valid, 1 if not.
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys
import urllib.parse
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

EXT_POPPY = "vxpprotocol.org/proof"
EXT_A2A = "https://vxpprotocol.org/ext/proof/v0.1"
META_PRUEBA = "vxp_proof"
MIEMBROS_DE_CONFIANZA = ("version", "company", "jwks_uri", "operator", "custody", "log", "domains", "pact")
ROLES = {
    "company": {"terms", "company_review", "outcome", "correction", "revocation"},
    "operator": {"request", "counter", "user_approval", "execution", "read_back"},
}
ESTADO_POPPY = {"succeeded": "succeeded", "failed": "failed", "cancelled": "cancelled", "expired": "expired"}
ESTADOS = ("succeeded", "failed", "cancelled", "expired", "unknown")
METODOS_LECTURA = ("system_read_back", "manual", "none")
B64_ALFABETO = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


class Falla(Exception):
    def __init__(self, code, seq=None):
        super().__init__(code)
        self.code = code
        self.seq = seq


# ---------- primitives ----------

def b64d(s):
    if not isinstance(s, str):
        raise Falla("not_sd_jwt")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64_canonico(seg, idx):
    """SPEC 9.2: unpadded, canonical base64url (leftover bits set to 0), or it is rejected."""
    if not isinstance(seg, str) or any(c not in B64_ALFABETO for c in seg) or len(seg) % 4 == 1:
        raise Falla("non_canonical_encoding", idx)
    try:
        crudo = b64d(seg)
    except Exception:
        raise Falla("non_canonical_encoding", idx)
    if b64e(crudo) != seg:
        raise Falla("non_canonical_encoding", idx)
    return crudo


def sha(b):
    return hashlib.sha256(b).digest()


def dig(b):
    return "sha-256:" + b64e(sha(b))


def jcs(v):
    """RFC 8785 with the 0.1 profile of SPEC 9.3 (safe integers only)."""
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
        for ch in v:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise Falla("lone_surrogate")
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        claves = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in claves) + "}"
    raise Falla("not_json")


def dig_jcs(x):
    """SPEC 9.3: the digest of any JSON value (object or string) is that of its JCS."""
    return dig(jcs(x).encode("utf-8"))


def huella_declaracion(jwt):
    """SPEC 9.2: the digest covers what is signed (header.payload), not the signature, which is malleable."""
    return dig(jwt.rsplit(".", 1)[0].encode("ascii"))


def sin_duplicados(pares):
    d = {}
    for k, val in pares:
        if k in d:
            raise Falla("duplicate_member")
        d[k] = val
    return d


def leer_json(b):
    return json.loads(b, object_pairs_hook=sin_duplicados)


def thumbprint(jwk):
    return b64e(sha(jcs({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}).encode("utf-8")))


def verificar_es256(jwk, entrada, firma):
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk or len(firma) != 64:
        return False
    try:
        pub = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64d(jwk["x"]), "big"), int.from_bytes(b64d(jwk["y"]), "big"), ec.SECP256R1()
        ).public_key()
        der = encode_dss_signature(int.from_bytes(firma[:32], "big"), int.from_bytes(firma[32:], "big"))
        pub.verify(der, entrada, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


def codigo_visible(terms_digest):
    return str(int.from_bytes(sha(terms_digest.encode("utf-8"))[:4], "big") % 1000000).zfill(6)


# ---------- log (RFC 9162) ----------

def hoja(d):
    return sha(b"\x00" + d)


def nodo(l, r):
    return sha(b"\x01" + l + r)


def mth(D):
    if len(D) == 0:
        return sha(b"")
    if len(D) == 1:
        return hoja(D[0])
    k = 1
    while k * 2 < len(D):
        k *= 2
    return nodo(mth(D[:k]), mth(D[k:]))


def inclusion(indice, tam, h, camino, raiz):
    """RFC 9162 section 2.1.3.2."""
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


def consistencia(primero, segundo, raiz1, raiz2, camino):
    """RFC 9162 section 2.1.4.2."""
    if primero == segundo:
        return not camino and raiz1 == raiz2
    if primero < 1 or primero > segundo:
        return False
    c = list(camino)
    if primero & (primero - 1) == 0:
        c = [raiz1] + c
    if not c:
        return False
    fn, sn = primero - 1, segundo - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = c[0]
    for x in c[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = nodo(x, fr)
            sr = nodo(x, sr)
            if not fn & 1:
                while not (fn & 1 or fn == 0):
                    fn >>= 1
                    sn >>= 1
        else:
            sr = nodo(sr, x)
        fn >>= 1
        sn >>= 1
    return fr == raiz1 and sr == raiz2 and sn == 0


# ---------- SD-JWT (RFC 9901 section 7.1) ----------

def procesar_sd(payload, discl, idx):
    """RFC 9901 7.1 steps 2.d to 5, with the 0.1 profile (salt of at least 128 bits, sha-256 only).
    Returns the processed payload: each disclosed value in its object, without `_sd` or `_sd_alg`."""
    if "_sd_alg" in payload and payload["_sd_alg"] != "sha-256":
        raise Falla("bad_sd_alg", idx)
    por_huella = {}
    for d in discl:
        h = b64e(sha(d.encode("ascii")))
        if h in por_huella:
            raise Falla("disclosure_repeated", idx)
        crudo = b64_canonico(d, idx)
        try:
            por_huella[h] = leer_json(crudo)
        except Exception:
            raise Falla("disclosure_malformed", idx)
    vistas = set()
    usadas = set()

    def sal_ok(sal):
        if not isinstance(sal, str):
            raise Falla("disclosure_malformed", idx)
        try:
            n = len(b64d(sal))
        except Exception:
            raise Falla("disclosure_malformed", idx)
        if n < 16:
            raise Falla("weak_salt", idx)

    def huella_nueva(h):
        if h in vistas:
            raise Falla("sd_digest_repeated", idx)
        vistas.add(h)

    def recorrer(v, raiz=False):
        if isinstance(v, dict):
            if not raiz and "_sd_alg" in v:
                raise Falla("bad_sd_alg", idx)
            salida = {k: recorrer(x) for k, x in v.items() if k not in ("_sd", "_sd_alg")}
            if "_sd" in v:
                lista = v["_sd"]
                if not isinstance(lista, list) or any(not isinstance(h, str) for h in lista):
                    raise Falla("bad_sd", idx)
                for h in lista:
                    huella_nueva(h)
                    if h not in por_huella:
                        continue  # decoy digest or disclosure not presented: ignored
                    c = por_huella[h]
                    if not isinstance(c, list) or len(c) != 3 or not isinstance(c[1], str):
                        raise Falla("disclosure_malformed", idx)
                    sal_ok(c[0])
                    if c[1] in ("_sd", "..."):
                        raise Falla("disclosure_bad_name", idx)
                    if c[1] in salida:
                        raise Falla("disclosure_claim_exists", idx)
                    usadas.add(h)
                    salida[c[1]] = recorrer(c[2])
            return salida
        if isinstance(v, list):
            salida = []
            for x in v:
                if isinstance(x, dict) and "..." in x:
                    if len(x) != 1 or not isinstance(x["..."], str):
                        raise Falla("bad_sd", idx)
                    h = x["..."]
                    huella_nueva(h)
                    if h not in por_huella:
                        continue
                    c = por_huella[h]
                    if not isinstance(c, list) or len(c) != 2:
                        raise Falla("disclosure_malformed", idx)
                    sal_ok(c[0])
                    usadas.add(h)
                    salida.append(recorrer(c[1]))
                else:
                    salida.append(recorrer(x))
            return salida
        return v

    procesado = recorrer(payload, raiz=True)
    if set(por_huella) - usadas:
        raise Falla("disclosure_digest_mismatch", idx)
    return procesado


# ---------- chain (SPEC 9.5) ----------

def abrir(sdjwt, llaves, idx):
    """Steps 1 to 4 of SPEC 9.5 for one statement. `llaves`: {role: {issuer, jwks}}.
    Returns (jwt, payload processed per RFC 9901 7.1, role)."""
    if not isinstance(sdjwt, str):
        raise Falla("not_sd_jwt", idx)
    partes = sdjwt.split("~")
    if len(partes) < 2 or partes[-1] != "":
        raise Falla("not_sd_jwt", idx)
    jwt, discl = partes[0], partes[1:-1]
    trozos = jwt.split(".")
    if len(trozos) != 3:
        raise Falla("not_sd_jwt", idx)
    h64, p64, _ = trozos
    hbytes, pbytes, firma = (b64_canonico(x, idx) for x in trozos)
    try:
        header = leer_json(hbytes)
        payload = leer_json(pbytes)
    except Falla:
        raise
    except Exception:
        raise Falla("not_sd_jwt", idx)
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise Falla("not_sd_jwt", idx)
    if header.get("typ") != "vxp-stmt+sd-jwt" or header.get("alg") != "ES256" or "crit" in header:
        raise Falla("bad_header", idx)
    iss = payload.get("iss")
    rol = next((r for r, k in llaves.items() if k["issuer"] == iss), None)
    if rol is None:
        raise Falla("unknown_issuer", idx)
    jwk = next((k for k in llaves[rol]["jwks"].get("keys", []) if k.get("kid") == header.get("kid")), None)
    if jwk is None or thumbprint(jwk) != jwk["kid"]:
        raise Falla("unknown_key", idx)
    if not verificar_es256(jwk, (h64 + "." + p64).encode("ascii"), firma):
        raise Falla("signature_invalid", idx)
    if jcs(payload).encode("utf-8") != pbytes:
        raise Falla("non_canonical_payload", idx)
    if payload.get("kind") not in ROLES[rol]:
        raise Falla("role_mismatch", idx)
    return jwt, procesar_sd(payload, discl, idx), rol


def lectura_completa(lectura, terms):
    """SPEC 9.4.7 (round 3, M1): the read-back observes, under the same name, every term of the effect."""
    campos = terms.get("read_back_terms") if terms else None
    obs = lectura.get("observed") if isinstance(lectura, dict) else None
    return bool(campos) and isinstance(obs, dict) and all(c in obs for c in campos)


def verificar_cadena(cadena, llaves, empresa, custodia, aud_esperado=None):
    """SPEC 9.5 rules 5 to 9 and 9.7. Returns (verdict, jwts, processed payloads)."""
    prev = None
    op = aud = user = None
    ultima_rev = 0
    ultimos_terminos = None
    ultimo_terms = None  # body of the latest `terms` (round 3: what the company requires and what to observe)
    aprobada = None
    revision_empresa = None  # None | "approved" | "denied"
    ejecutada = None
    lectura = None  # the latest read_back before the outcome
    lecturas_post = {}  # read_backs issued after the latest final statement: digest -> matches
    hubo_lectura_ok = False
    estado = None
    ultimo_final = None
    jwts = []
    payloads = []
    for i, sdjwt in enumerate(cadena):
        jwt, p, rol = abrir(sdjwt, llaves, i)
        if p.get("v") != "0.1":
            raise Falla("bad_version", i)
        if p.get("company") != empresa:
            raise Falla("company_mismatch", i)
        if i == 0:
            op, aud, user = p.get("op"), p.get("aud"), p.get("user")
        if p.get("op") != op:
            raise Falla("op_mismatch", i)
        # Replay across agents or users (SPEC 9.5 rule 5): aud and user fixed across the whole chain.
        if p.get("aud") != aud or (aud_esperado is not None and aud != aud_esperado):
            raise Falla("aud_mismatch", i)
        if p.get("user") != user:
            raise Falla("user_mismatch", i)
        if p.get("seq") != i:
            raise Falla("seq_error", i)
        if p.get("prev") != prev:
            raise Falla("chain_broken", i)
        b = p.get("body")
        if not isinstance(b, dict):
            raise Falla("bad_body", i)
        k = p["kind"]
        h = huella_declaracion(jwt)
        if estado is not None and k not in ("read_back", "correction", "revocation"):
            raise Falla("after_final", i)
        if (k == "request") != (i == 0):
            raise Falla("order_violation", i)
        if k == "terms":
            if b.get("revision") != ultima_rev + 1 or aprobada is not None:
                raise Falla("revision_error", i)
            # Round 3 (M1, m3): the company declares, signed, whether it requires its own review and which
            # terms the read-back must observe.
            rbt = b.get("read_back_terms")
            if (not isinstance(b.get("company_review_required"), bool) or not isinstance(rbt, list)
                    or not all(isinstance(x, str) for x in rbt) or len(set(rbt)) != len(rbt)):
                raise Falla("bad_terms", i)
            ultima_rev, ultimos_terminos, ultimo_terms = b["revision"], b.get("terms_digest"), b
        elif k == "counter":
            if aprobada is not None:
                raise Falla("order_violation", i)
            if ultima_rev < 1 or b.get("base_revision") != ultima_rev:
                raise Falla("revision_error", i)
        elif k == "user_approval":
            if aprobada is not None or ultima_rev < 1:
                raise Falla("order_violation", i)
            if b.get("revision") != ultima_rev:
                raise Falla("approval_not_latest_revision", i)
            if b.get("terms_digest") != ultimos_terminos:
                raise Falla("approval_terms_mismatch", i)
            if b.get("method") not in ("agent_asserted", "company_channel"):
                raise Falla("bad_approval_method", i)
            if b.get("method") == "company_channel" and b.get("display_code") != codigo_visible(b["terms_digest"]):
                raise Falla("display_code_mismatch", i)
            aprobada = b
        elif k == "company_review":
            # SPEC 6.5 and 9.5.7: exactly one, between user_approval and execution, on the approved revision.
            if aprobada is None or ejecutada is not None or revision_empresa is not None:
                raise Falla("order_violation", i)
            if b.get("terms_digest") != aprobada["terms_digest"] or b.get("revision") != aprobada["revision"]:
                raise Falla("order_violation", i)
            if b.get("decision") not in ("approved", "denied"):
                raise Falla("bad_decision", i)
            revision_empresa = b["decision"]
        elif k == "execution":
            if aprobada is None or ejecutada is not None or revision_empresa == "denied":
                raise Falla("order_violation", i)
            # Round 3 (m3): if the approved revision requires the company review, there is no execution without it.
            if ultimo_terms["company_review_required"] and revision_empresa != "approved":
                raise Falla("order_violation", i)
            if b.get("terms_digest") != aprobada["terms_digest"] or b.get("revision") != aprobada["revision"]:
                raise Falla("execution_terms_mismatch", i)
            ejecutada = b
        elif k == "read_back":
            if ejecutada is None:
                raise Falla("order_violation", i)
            if b.get("method") not in METODOS_LECTURA or not isinstance(b.get("matches_terms"), bool):
                raise Falla("bad_read_back", i)
            coincide = b["method"] == "system_read_back" and b["matches_terms"] is True
            hubo_lectura_ok = hubo_lectura_ok or coincide
            if estado is None:
                lectura = b
            else:
                lecturas_post[h] = (coincide, b)
        elif k == "outcome":
            if ultima_rev < 1:
                raise Falla("order_violation", i)
            # SPEC 9.5.7: the outcome always names the latest issued revision, with or without approval.
            if b.get("terms_digest") != ultimos_terminos or b.get("revision") != ultima_rev:
                raise Falla("outcome_terms_mismatch", i)
            if b.get("state") not in ESTADOS:
                raise Falla("bad_state", i)
            if revision_empresa == "denied" and b["state"] != "failed":
                raise Falla("outcome_after_denial", i)
            if b["state"] == "succeeded" and (
                ejecutada is None
                or lectura is None
                or lectura.get("matches_terms") is not True
                or lectura.get("method") != "system_read_back"
            ):
                raise Falla("succeeded_without_matching_read_back", i)
            if b["state"] == "succeeded" and not lectura_completa(lectura, ultimo_terms):
                raise Falla("read_back_incomplete", i)
            estado = b["state"]
            ultimo_final = h
            lecturas_post = {}
        elif k in ("correction", "revocation"):
            ref = b.get("corrects") if k == "correction" else b.get("revokes")
            # SPEC 11.1: always on the latest final statement (outcome, correction or revocation).
            if estado is None or ref != ultimo_final:
                raise Falla("order_violation", i)
            if k == "correction":
                if b.get("state") not in ESTADOS:
                    raise Falla("bad_state", i)
                # SPEC 8.3 and 11.1: a correction to succeeded cites a later matching read_back.
                citada = lecturas_post.get(b.get("read_back"))
                if b["state"] == "succeeded" and (citada is None or citada[0] is not True):
                    raise Falla("correction_without_read_back", i)
                if b["state"] == "succeeded" and not lectura_completa(citada[1], ultimo_terms):
                    raise Falla("read_back_incomplete", i)
                estado = b["state"]
            else:
                estado = "revoked"
            ultimo_final = h
            lecturas_post = {}
        prev = h
        jwts.append(jwt)
        payloads.append(p)
    if estado is None:
        raise Falla("no_outcome")
    vigente = aprobada if revision_empresa != "denied" else None
    # SPEC 9.7: each level carries the name of its actual root.
    asegura = ["issuer_key_attested"]
    if ejecutada is not None:
        asegura.append("operator_observed")
    if hubo_lectura_ok:
        asegura.append("operator_reported_read_back")
    if vigente is not None:
        asegura.append(
            "operator_reported_channel_approval" if vigente.get("method") == "company_channel" else "operator_reported_agent_approval"
        )
    veredicto = {
        "valid": True,
        "final_state": estado,
        "revision": vigente["revision"] if vigente else None,
        "approval": vigente.get("method") if vigente else None,
        "derived_assurance": asegura,
        # SPEC 9.6: `custody` is declared by the issuer; without verifiable evidence of another root (0.1
        # defines none), the single root is the operator.
        "single_root": "operator",
        "custody_declared": custodia,
        "logged": False,
    }
    return veredicto, jwts, payloads


# ---------- public material and anchoring (SPEC 9.9.1) ----------

class Material:
    """Fetches (or reads from a file) the public material a third party needs. Nothing comes from the package."""

    def __init__(self, docs=None, http_local=False):
        self.docs = docs
        self.http_local = http_local

    def esquema(self, host):
        local = host.split(":")[0] in ("localhost", "127.0.0.1")
        return "http" if self.http_local and local else "https"

    def seguro(self, url):
        u = urllib.parse.urlparse(url)
        local = u.hostname in ("localhost", "127.0.0.1")
        return u.scheme == "https" or (self.http_local and local and u.scheme == "http")

    def traer(self, url, crudo=False, redirecciones=False):
        """On any failure (missing, HTTP, network, JSON) answers issuer_not_anchored (SPEC 9.9.1 point 5).
        Follows redirects only when asked (the Agent Card on the brand domain, PACT 2.1), and only to
        secure URLs."""
        NA = "issuer_not_anchored"
        if self.docs is not None:
            if url not in self.docs:
                raise Falla(NA)
            v = self.docs[url]
            try:
                return v if crudo or not isinstance(v, str) else leer_json(v)
            except Falla:
                raise
            except Exception:
                raise Falla(NA)
        if not self.seguro(url):
            raise Falla("insecure_url:" + url)
        material = self

        class Redireccion(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, nueva):
                if not redirecciones or not material.seguro(nueva):
                    return None
                return super().redirect_request(req, fp, code, msg, headers, nueva)

        abre = urllib.request.build_opener(Redireccion)
        try:
            with abre.open(urllib.request.Request(url, headers={"accept": "application/json"}), timeout=10) as r:
                cuerpo = r.read()
            return cuerpo.decode("utf-8") if crudo else leer_json(cuerpo)
        except Falla:
            raise
        except Exception:
            raise Falla(NA)


def bajo(base, url):
    """`url` is under `base`: same scheme and host, and its path starts with that of `base` + "/"."""
    if not isinstance(base, str) or not isinstance(url, str):
        return False
    b, u = urllib.parse.urlparse(base), urllib.parse.urlparse(url)
    return (
        b.scheme == u.scheme
        and b.netloc.lower() == u.netloc.lower()
        and u.path.startswith(b.path.rstrip("/") + "/")
        and not u.query
        and not u.fragment
    )


def url_metadata(issuer):
    """RFC 8414 section 3.1: the well-known goes between the host and the issuer path."""
    u = urllib.parse.urlparse(issuer)
    return "%s://%s/.well-known/oauth-authorization-server%s" % (u.scheme, u.netloc, u.path.rstrip("/"))


def anclar(material, ancla):
    """SPEC 9.9.1. Returns (trust block, issuer, profile, anchor type)."""
    return anclar_ext(material, ancla)[:4]


def interfaz_http_json(card):
    for i in card.get("supportedInterfaces") or []:
        if isinstance(i, dict) and i.get("protocolBinding") == "HTTP+JSON" and i.get("protocolVersion") == "1.0":
            return i.get("url")
    return None


def confianza_de(material, issuer):
    """The issuer's RFC 8414 metadata (3.1), with an identical issuer (3.3), and its trust block."""
    if not isinstance(issuer, str) or not issuer.startswith(("https://", "http://")):
        raise Falla("issuer_not_anchored")
    meta = material.traer(url_metadata(issuer))
    if not isinstance(meta, dict) or meta.get("issuer") != issuer:
        raise Falla("issuer_not_anchored")
    return meta, meta.get(META_PRUEBA)


def anclar_pact(material, ancla):
    """PACT profile (SPEC 9.9.1, point 1). Binds in both directions, like Poppy 3: the PACT authorization
    server (or the Agent Card of the brand domain) names the company, and the company's metadata names
    that server and that interface (and the brand domain). Returns
    (company issuer, profile copy, {interface, authorization_server, jwks_uri}, type)."""
    NA = "issuer_not_anchored"
    if ancla.get("brand_domain"):
        marca = ancla["brand_domain"]
        card = material.traer("%s://%s/.well-known/agent-card.json" % (material.esquema(marca), marca), redirecciones=True)
        if not isinstance(card, dict):
            raise Falla(NA)
        exts = (card.get("capabilities") or {}).get("extensions") or []
        ext = next((x for x in exts if isinstance(x, dict) and x.get("uri") == EXT_A2A), None)
        if ext is None:
            raise Falla("discovery_without_extension")
        copia = ext.get("params") or {}
        empresa = copia.get("company")
        interfaz = interfaz_http_json(card)
        as_pact = None
        meta_as = None
        tipo = "brand_domain"
    else:
        as_pact = ancla["pact_issuer"]
        meta_as, copia = confianza_de(material, as_pact)
        if not isinstance(copia, dict):
            raise Falla(NA)
        empresa = copia.get("company")
        interfaz = None
        tipo = "pact_issuer"
    _, confianza = confianza_de(material, empresa)
    if not isinstance(confianza, dict) or confianza.get("company") != empresa:
        raise Falla(NA)
    vinculos = [x for x in confianza.get("pact") or [] if isinstance(x, dict)]
    if tipo == "brand_domain":
        # The company recognizes that brand domain and that interface: the Card alone is not enough (round 2, M1).
        if marca.lower() not in [str(x).lower() for x in confianza.get("domains") or []]:
            raise Falla(NA)
        v = next((x for x in vinculos if x.get("interface") == interfaz), None)
        if v is None:
            raise Falla(NA)
        as_pact = v.get("authorization_server")
        meta_as, copia_as = confianza_de(material, as_pact)
        if not isinstance(copia_as, dict):
            raise Falla(NA)
        for m in MIEMBROS_DE_CONFIANZA:
            if jcs(copia_as.get(m)) != jcs(confianza.get(m)):
                raise Falla(NA)
    else:
        v = next((x for x in vinculos if x.get("authorization_server") == as_pact), None)
        if v is None:
            raise Falla(NA)
        interfaz = v.get("interface")
    if not bajo(as_pact, meta_as.get("jwks_uri")):
        raise Falla(NA)
    return empresa, copia, {"interface": interfaz, "authorization_server": as_pact, "jwks_uri": meta_as["jwks_uri"]}, tipo


def anclar_ext(material, ancla):
    """SPEC 9.9.1. `ancla`: {"domain": D} (Poppy), {"brand_domain": D} or {"pact_issuer": I} (PACT), or
    {"issuer": I, "card"?: URL} (standalone). Returns (block, issuer, profile, type, pact or None)."""
    NA = "issuer_not_anchored"
    dominio = ancla.get("domain")
    bloque_perfil = None
    pact = None
    if ancla.get("brand_domain") or ancla.get("pact_issuer"):
        issuer, bloque_perfil, pact, tipo = anclar_pact(material, ancla)
        perfil = "pact"
    elif dominio:
        doc = material.traer("%s://%s/.well-known/poppy.json" % (material.esquema(dominio), dominio))
        org = (doc.get("organization") or {}).get("domain")
        if not isinstance(org, str) or org.lower() != dominio.lower():
            raise Falla(NA)  # Poppy 3, rule 1: the document speaks for the host that served it
        issuer = (doc.get("auth") or {}).get("issuer")
        if ancla.get("issuer") is not None and ancla["issuer"] != issuer:
            raise Falla(NA)
        bloque_perfil = (doc.get("extensions") or {}).get(EXT_POPPY)
        perfil, tipo = "poppy", "poppy_domain"
    elif ancla.get("issuer"):
        issuer = ancla["issuer"]
        perfil, tipo = "issuer", "issuer"
        if ancla.get("card"):
            card = material.traer(ancla["card"])
            ext = next((x for x in (card.get("capabilities") or {}).get("extensions") or [] if x.get("uri") == EXT_A2A), None)
            if ext is None:
                raise Falla("discovery_without_extension")
            bloque_perfil = ext.get("params") or {}
            perfil = "a2a"
    else:
        raise Falla("no_anchor")
    if not isinstance(issuer, str) or not issuer.startswith(("https://", "http://")):
        raise Falla(NA)
    meta = material.traer(url_metadata(issuer))
    if meta.get("issuer") != issuer:
        raise Falla(NA)  # RFC 8414 section 3.3
    if dominio and dominio.lower() not in [str(x).lower() for x in meta.get("poppy_domains") or []]:
        raise Falla(NA)  # Poppy 3, rule 2
    confianza = meta.get(META_PRUEBA)
    if not isinstance(confianza, dict) or confianza.get("company") != issuer:
        raise Falla(NA)
    operador = confianza.get("operator") or {}
    if not bajo(issuer, confianza.get("jwks_uri")) or not bajo(operador.get("issuer"), operador.get("jwks_uri")):
        raise Falla(NA)
    if bloque_perfil is not None:
        for m in MIEMBROS_DE_CONFIANZA:
            if jcs(bloque_perfil.get(m)) != jcs(confianza.get(m)):
                raise Falla(NA)  # the profile copy (poppy.json or Agent Card) is not the issuer's
    return confianza, issuer, perfil, tipo, pact


def verificar_recibo_pact(material, pact, recibo):
    """PACT receipt (PACT 5.6) with the keys of the anchored PACT authorization server."""
    if not isinstance(recibo, dict) or not isinstance(recibo.get("jws"), str) or recibo["jws"].count(".") != 2:
        raise Falla("pact_receipt_invalid", 0)
    h64, p64, s64 = recibo["jws"].split(".")
    try:
        header = leer_json(b64d(h64))
        claims = leer_json(b64d(p64))
        firma = b64d(s64)
    except Exception:
        raise Falla("pact_receipt_invalid", 0)
    if header.get("alg") != "ES256":
        raise Falla("pact_receipt_invalid", 0)  # 0.1 only verifies ES256; PACT also allows RS256
    jwks = material.traer(pact["jwks_uri"])
    jwk = next((k for k in (jwks or {}).get("keys", []) if k.get("kid") == header.get("kid")), None)
    if jwk is None or not verificar_es256(jwk, (h64 + "." + p64).encode("ascii"), firma):
        raise Falla("pact_receipt_invalid", 0)
    return claims


def cruzar_recibo_pact(payloads, material, pact, recibo):
    """SPEC 9.9, step 4 bis: the `request.body.pact_proposal_receipt` citation against the PACT receipt."""
    cita = payloads[0]["body"].get("pact_proposal_receipt")
    if cita is None:
        if recibo is not None:
            raise Falla("pact_receipt_mismatch", 0)  # a receipt was presented that the chain does not cite
        return {}
    if not isinstance(cita, dict) or cita.get("argsHash") != payloads[0]["body"].get("request_digest"):
        raise Falla("pact_receipt_mismatch", 0)  # argsHash MUST be the digest of the request (SPEC 9.4.1)
    if recibo is None:
        return {"pact_receipt": "not_presented"}
    if pact is None:
        raise Falla("pact_receipt_not_anchored", 0)
    claims = verificar_recibo_pact(material, pact, recibo)
    acciones = claims.get("actions") if isinstance(claims.get("actions"), list) else []
    if (
        claims.get("grantId") != cita.get("grantId")
        or claims.get("brand") != pact["interface"]
        or claims.get("pa") != payloads[0].get("aud")
        or not any(isinstance(a, dict) and a.get("argsHash") == cita.get("argsHash") for a in acciones)
    ):
        raise Falla("pact_receipt_mismatch", 0)
    return {"pact_receipt": "verified"}


def llaves_ancladas(material, confianza, issuer):
    return {
        "company": {"issuer": issuer, "jwks": material.traer(confianza["jwks_uri"])},
        "operator": {"issuer": confianza["operator"]["issuer"], "jwks": material.traer(confianza["operator"]["jwks_uri"])},
    }


def verificar_jws(jws, jwks, typ):
    h64, p64, s64 = jws.split(".")
    header = leer_json(b64d(h64))
    if header.get("alg") != "ES256" or header.get("typ") != typ:
        return None
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    if jwk is None or thumbprint(jwk) != jwk["kid"]:
        return None
    if not verificar_es256(jwk, (h64 + "." + p64).encode("ascii"), b64d(s64)):
        return None
    return leer_json(b64d(p64))


def verificar_registro(paquete, jwts, bloque, material):
    """SPEC 9.8 and 9.9 step 3. Returns a report; raises Falla if anything does not match."""
    log = paquete.get("log")
    if not log:
        return {"log_inclusion": "absent"}
    jwks_log = material.traer(bloque["log"]["jwks_uri"])
    cp = verificar_jws(log["checkpoint"], jwks_log, "vxp-checkpoint+jwt")
    if cp is None:
        raise Falla("checkpoint_signature_invalid")
    if cp.get("origin") != bloque["log"]["origin"] or log.get("origin") != bloque["log"]["origin"]:
        raise Falla("log_origin_mismatch")
    tam, raiz = cp["tree_size"], b64d(cp["root_hash"])
    por_seq = {x["seq"]: x for x in log.get("inclusion", [])}
    for seq, jwt in enumerate(jwts):
        x = por_seq.get(seq)
        if x is None:
            raise Falla("log_inclusion_missing", seq)
        entrada = sha(b64d(x["salt"]) + jwt.encode("ascii")) + b64d(x["tag"])
        if len(b64d(x["salt"])) != 32 or len(b64d(x["tag"])) != 32:
            raise Falla("log_bad_leaf", seq)
        if not inclusion(x["leaf_index"], tam, hoja(entrada), [b64d(p) for p in x["path"]], raiz):
            raise Falla("log_inclusion_failed", seq)
    # The checkpoint the verifier sees on its own must be the same tree or one that extends it.
    vivo = verificar_jws(material.traer(bloque["log"]["checkpoint_url"], crudo=True).strip(), jwks_log, "vxp-checkpoint+jwt")
    if vivo is None:
        raise Falla("checkpoint_signature_invalid")
    t2, r2 = vivo["tree_size"], b64d(vivo["root_hash"])
    if t2 < tam:
        raise Falla("equivocation_detected")
    if t2 == tam and r2 != raiz:
        raise Falla("equivocation_detected")
    if t2 > tam:
        url = bloque["log"]["consistency_url"] + "?" + urllib.parse.urlencode({"first": tam, "second": t2})
        prueba = material.traer(url)
        if not consistencia(tam, t2, raiz, r2, [b64d(p) for p in prueba.get("path", [])]):
            raise Falla("equivocation_detected")
    testigos = bloque["log"].get("witnesses") or []
    return {
        "log_inclusion": "ok",
        "tree_size": tam,
        "live_tree_size": t2,
        "consistency": "ok",
        # Without a witness independent of the operator that cosigns, there is no `logged` (SPEC 9.7);
        # cosigning is not implemented in 0.1.
        "witnesses": len(testigos),
    }


def cruzar_operacion(operacion, empresa, payloads, veredicto):
    """Binds the chain to the Poppy operation (or PACT's `vxpprotocol.org/operation`) the agent saw."""
    if operacion.get("operation_id") != payloads[0]["op"]:
        raise Falla("operation_id_mismatch")
    terms = [p for p in payloads if p["kind"] == "terms" and p["body"]["revision"] == operacion.get("revision")]
    if not terms:
        raise Falla("operation_revision_unknown")
    calculada = dig_jcs({
        "company": empresa,
        "operation_id": operacion["operation_id"],
        "revision": operacion["revision"],
        "summary": operacion["summary"],
        "terms": operacion.get("terms"),
        "expires_at": operacion.get("expires_at"),
        "user_approval_required": operacion["user_approval_required"],
    })
    if calculada != terms[-1]["body"]["terms_digest"]:
        raise Falla("operation_terms_mismatch")
    # SPEC 9.3 (round 3, m2): the terms carry a salt of 128 bits or more, so the digest does not
    # confirm personal data to someone who guesses its value.
    sal = (operacion.get("terms") or {}).get("vxp_salt") if isinstance(operacion.get("terms"), dict) else None
    try:
        sal_ok = isinstance(sal, str) and b64e(b64d(sal)) == sal and len(b64d(sal)) >= 16
    except Exception:
        sal_ok = False
    if not sal_ok:
        raise Falla("weak_terms_salt")
    # SPEC 9.4.7: what was observed (with disclosures already in place) matches the terms of the same name.
    terminos = operacion.get("terms") or {}
    for p in payloads:
        if p["kind"] != "read_back" or p["body"].get("matches_terms") is not True:
            continue
        for nombre, valor in (p["body"].get("observed") or {}).items():
            if nombre in terminos and jcs(terminos[nombre]) != jcs(valor):
                raise Falla("read_back_terms_mismatch", p["seq"])
    estado = operacion.get("state")
    finales = [p for p in payloads if p["kind"] in ("outcome", "correction")]
    # VXP Proof: what stands is the LATEST final (outcome or correction, SPEC 11.1), not the first outcome.
    # An open operation (in_progress) only matches a latest final `unknown`, or none.
    if estado in ESTADO_POPPY:
        if not finales or finales[-1]["body"]["state"] != ESTADO_POPPY[estado]:
            raise Falla("operation_state_mismatch")
        resumen = (operacion.get("result") or {}).get("summary", "")
        if finales[-1]["body"].get("result_summary_digest") != dig_jcs(resumen):
            raise Falla("operation_result_mismatch")
    elif finales and finales[-1]["body"]["state"] != "unknown":
        raise Falla("operation_state_mismatch")
    return {"operation": "matches"}


def verificar_paquete(paquete, material, ancla, aud=None, operacion=None, recibo_pact=None):
    bloque, empresa, perfil, tipo, pact = anclar_ext(material, ancla)
    llaves = llaves_ancladas(material, bloque, empresa)
    if paquete.get("v") != "0.1":
        raise Falla("bad_version")
    if paquete.get("company") != empresa:
        raise Falla("company_mismatch")
    estados = paquete.get("statements") or []
    if not estados:
        raise Falla("no_outcome")
    # No outcome is treated as `unknown` (SPEC 9.5 rule 9): `main` reports it that way.
    veredicto, jwts, payloads = verificar_cadena(estados, llaves, empresa, bloque.get("custody"), aud)
    if paquete.get("op") != payloads[0]["op"]:
        raise Falla("op_mismatch")
    veredicto["company"] = empresa
    veredicto["anchor"] = tipo
    # The keys come from the jwks_uri named by the issuer metadata: anchored to the issuer, not to its
    # history (SPEC 9.6: key leaves in the log do not exist in 0.1). Fetched now, or read from material
    # saved earlier, which the verdict says (spec §10, key rotation and historical verification).
    veredicto["key_source"] = "issuer_metadata_live" if material.docs is None else "issuer_metadata_saved"
    veredicto["profile"] = perfil
    veredicto["statements"] = len(estados)
    veredicto.update(verificar_registro(paquete, jwts, bloque, material))
    if operacion is not None:
        veredicto.update(cruzar_operacion(operacion, empresa, payloads, veredicto))
    veredicto.update(cruzar_recibo_pact(payloads, material, pact, recibo_pact))
    if pact is not None:
        veredicto["pact_interface"] = pact["interface"]
    return veredicto


# ---------- vectors mode (SPEC appendix A) ----------

CLAVES_VEREDICTO = ("valid", "final_state", "revision", "approval", "derived_assurance", "single_root", "custody_declared", "logged")


def aplicar(cadena, n):
    if "chain" in n:
        return list(n["chain"])
    c = list(cadena)
    for r in ([n["replace"]] if "replace" in n else []) + n.get("replace_many", []):
        c[r["seq"]] = "~".join([r["jwt"]] + c[r["seq"]].split("~")[1:])
    if "replace_disclosure" in n:
        r = n["replace_disclosure"]
        partes = c[r["seq"]].split("~")
        partes[1 + r["index"]] = r["disclosure"]
        c[r["seq"]] = "~".join(partes)
    return c


def modo_vectores(ruta):
    v = json.load(open(ruta, encoding="utf-8"))
    llaves = {"company": v["keys"]["company"], "operator": v["keys"]["operator"]}
    empresa = v["keys"]["company"]["issuer"]
    custodia = v["keys"]["company"]["custody"]
    cadena = [s["sdjwt"] for s in v["chain_v1"]]
    pay = [json.loads(s["payload_jcs"]) for s in v["chain_v1"]]
    ins = v["inputs"]
    resultados = []

    def informe(nombre, ok, detalle=""):
        resultados.append(ok)
        print(("OK   " if ok else "FALLA") + " " + nombre + (" - " + detalle if detalle else ""))

    # Digests recomputed from the cleartext inputs (SPEC 9.3: always JCS, strings included).
    informe("terms_digest_1", dig_jcs(ins["terminos1"]) == ins["terms_digest_1"])
    informe("terms_digest_2", dig_jcs(ins["terminos2"]) == ins["terms_digest_2"])
    informe("display_code_2", codigo_visible(ins["terms_digest_2"]) == ins["display_code_2"])
    informe("request_digest", pay[0]["body"]["request_digest"] == dig_jcs(ins["solicitud"]))
    informe("idempotency_key_digest", pay[0]["body"]["idempotency_key_digest"] == dig_jcs(ins["idempotency_key"]))
    informe("counter_digest", pay[2]["body"]["counter_digest"] == dig_jcs(ins["contra"]))
    informe("release", pay[5]["body"]["release"] == dig_jcs(ins["release_closure"]))
    informe("result_summary_digest", pay[7]["body"]["result_summary_digest"] == dig_jcs(ins["resumenResultado"]))
    for s in v["chain_v1"]:
        informe("huella seq %d" % s["seq"], huella_declaracion(s["sdjwt"].split("~")[0]) == s["digest"])
    m = v["malleated_outcome"]
    informe("firma maleada (s -> n-s): misma huella", huella_declaracion(m["jwt"]) == v["chain_v1"][7]["digest"])
    ver, _, procesados = verificar_cadena(cadena, llaves, empresa, custodia)
    informe("V1", {k: ver[k] for k in CLAVES_VEREDICTO} == v["expected_v1"], json.dumps({k: ver[k] for k in CLAVES_VEREDICTO}))
    informe("V1 divulgacion procesada en su lugar", procesados[6]["body"]["observed"] == v["expected_processed_observed_seq6"])
    ver_m, _, _ = verificar_cadena(cadena[:7] + [m["jwt"] + "~"], llaves, empresa, custodia)
    informe("V1 con la firma maleada sigue valida", ver_m["final_state"] == "succeeded")
    for nombre in ("v2", "v3"):
        x = v["chain_" + nombre]
        ver2, _, _ = verificar_cadena(cadena + x["extra"], llaves, empresa, custodia)
        informe(nombre.upper(), {k: ver2[k] for k in CLAVES_VEREDICTO} == x["expected"], json.dumps({k: ver2[k] for k in CLAVES_VEREDICTO}))
    # Round 3: V4, with the company review required (company_review_required) and approved.
    x = v["chain_v4"]
    ver4, _, _ = verificar_cadena(x["chain"], llaves, empresa, custodia)
    informe("V4", {k: ver4[k] for k in CLAVES_VEREDICTO} == x["expected"], json.dumps({k: ver4[k] for k in CLAVES_VEREDICTO}))
    for s4, d4 in zip(x["chain"], x["digests"]):
        informe("V4 huella seq %d" % x["chain"].index(s4), huella_declaracion(s4.split("~")[0]) == d4)
    # Round 3: the chain together with the operation the agent saw (SPEC 9.9 step 4).
    for caso in v.get("operation_cases", []):
        try:
            ver5, _, procesados5 = verificar_cadena(caso["chain"], llaves, empresa, custodia)
            r5 = cruzar_operacion(caso["operation"], empresa, procesados5, ver5)
            informe(caso["id"], caso["expect"] == "valid" and r5.get("operation") == "matches", json.dumps(r5))
        except Falla as e:
            informe(caso["id"], e.code == caso["expect"] and (caso.get("seq") is None or e.seq == caso["seq"]), "%s en seq %s; esperado %s" % (e.code, e.seq, caso["expect"]))
    D = [b64d(x["leaf_input"]) for x in v["log"]["leaves"]]
    raiz = mth(D)
    informe("raiz", b64e(raiz) == v["log"]["root_hash"])
    k_tag = b64d(v["log"]["tag_key_TEST_ONLY"])
    for x in v["log"]["leaves"]:
        jwt = cadena[x["seq"]].split("~")[0]
        tag = hmac.new(k_tag, (pay[0]["op"] + "|" + str(x["seq"])).encode(), hashlib.sha256).digest()
        informe("hoja %d" % x["seq"], sha(b64d(x["salt"]) + jwt.encode("ascii")) + tag == b64d(x["leaf_input"]))
    for seq in (7, 3):
        informe("inclusion %d" % seq, inclusion(seq, len(D), hoja(D[seq]), [b64d(p) for p in v["log"]["inclusion_of_seq%d" % seq]], raiz))
    informe("inclusion falla con otra hoja", not inclusion(7, len(D), hoja(D[6]), [b64d(p) for p in v["log"]["inclusion_of_seq7"]], raiz))
    for n in v["negative"]:
        try:
            verificar_cadena(aplicar(cadena, n), llaves, empresa, custodia)
            informe(n["id"], False, "acepto lo que debia fallar con " + n["expect"])
        except Falla as e:
            informe(n["id"], e.code == n["expect"], "%s en seq %s; esperado %s" % (e.code, e.seq, n["expect"]))
    mat = Material(docs=v["discovery"]["docs"])
    for caso in v["discovery"]["cases"]:
        try:
            bloque, issuer, _, _ = anclar(mat, caso["anchor"])
            ll = llaves_ancladas(mat, bloque, issuer)
            ver3, _, _ = verificar_cadena(cadena, ll, issuer, bloque.get("custody"))
            ok = caso["expect"] == "valid" and ver3["final_state"] == "succeeded" and issuer == empresa
            informe(caso["id"], ok, "anclado a " + issuer)
        except Falla as e:
            informe(caso["id"], e.code == caso["expect"], "%s; esperado %s" % (e.code, caso["expect"]))
    fallas = resultados.count(False)
    print("\n%d comprobaciones, %d fallas" % (len(resultados), fallas))
    return 1 if fallas else 0


def modo_pact(ruta):
    """SPEC appendix A.9: PACT anchoring and cross-check with the PACT receipt, with material already fetched."""
    v = json.load(open(ruta, encoding="utf-8"))
    fallas = 0
    for caso in v["cases"]:
        mat = Material(docs=dict(v["docs"], **(caso.get("docs_override") or {})))
        try:
            r = verificar_paquete(caso.get("package") or v["package"], mat, caso["anchor"], v.get("aud"), None, caso.get("receipt"))
            ok = caso["expect"] == "valid" and all(r.get(k) == x for k, x in (caso.get("expect_fields") or {}).items())
            detalle = json.dumps({k: r.get(k) for k in ("valid", "company", "anchor", "final_state", "pact_receipt")}, ensure_ascii=False)
        except Falla as e:
            ok = e.code == caso["expect"] and (caso.get("seq") is None or e.seq == caso["seq"])
            detalle = "%s en seq %s; esperado %s" % (e.code, e.seq, caso["expect"])
        fallas += 0 if ok else 1
        print(("OK   " if ok else "FALLA") + " " + caso["id"] + " - " + detalle)
    print("\n%d comprobaciones, %d fallas" % (len(v["cases"]), fallas))
    return 1 if fallas else 0


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("modo", choices=["vectores", "vivo", "material", "pact"])
    ap.add_argument("ruta", nargs="?")
    ap.add_argument("--dominio")
    ap.add_argument("--issuer")
    ap.add_argument("--card")
    ap.add_argument("--marca")
    ap.add_argument("--as-pact")
    ap.add_argument("--recibo-pact")
    ap.add_argument("--material")
    ap.add_argument("--paquete")
    ap.add_argument("--aud")
    ap.add_argument("--operacion")
    ap.add_argument("--http-local", action="store_true")
    a = ap.parse_args(argv)
    if a.modo == "vectores":
        return modo_vectores(a.ruta)
    if a.modo == "pact":
        return modo_pact(a.ruta)
    paquete = json.load(open(a.paquete, encoding="utf-8"))
    operacion = json.load(open(a.operacion, encoding="utf-8")) if a.operacion else None
    recibo = json.load(open(a.recibo_pact, encoding="utf-8")) if a.recibo_pact else None
    if a.modo == "material":
        m = json.load(open(a.material, encoding="utf-8"))
        material, ancla = Material(docs=m["docs"]), m.get("anchor") or {}
    else:
        material = Material(http_local=a.http_local)
        ancla = {k: x for k, x in (("domain", a.dominio), ("issuer", a.issuer), ("card", a.card),
                                   ("brand_domain", a.marca), ("pact_issuer", a.as_pact)) if x}
    try:
        veredicto = verificar_paquete(paquete, material, ancla, a.aud, operacion, recibo)
    except Falla as e:
        salida = {"valid": False, "error": e.code, "seq": e.seq}
        if e.code == "no_outcome":
            salida["final_state"] = "unknown"
        print(json.dumps(salida, ensure_ascii=False))
        return 1
    print(json.dumps(veredicto, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
