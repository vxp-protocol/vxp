"""Cross-check of the two verifiers over ALL appendix A cases (SPEC 15, round 1 M3).

Runs every chain (V1, V2, V3, the malleated signature and each negative) and every anchoring case
through verifier/verificar_paquete.py and verifier/verificar.py, and fails if the two do not
return exactly the same verdict (or the same rejection code and seq).

Usage: python scripts/cruce-verificadores.py [../vectors/vectores-0.1.json]
"""
import importlib.util
import json
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cargar(nombre, ruta):
    spec = importlib.util.spec_from_file_location(nombre, os.path.join(RAIZ, ruta))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


C = cargar("construccion", "../verifier/verificar_paquete.py")
A = cargar("arquitecto", "../verifier/verificar.py")


def resultado(m, fn):
    try:
        r = fn()
        r = r[0] if isinstance(r, tuple) else r
        return json.dumps(r, sort_keys=True)
    except m.Falla as e:
        return "RECHAZA %s seq=%s" % (e.code, e.seq)


def main(ruta):
    v = json.load(open(ruta, encoding="utf-8"))
    llaves = {"company": v["keys"]["company"], "operator": v["keys"]["operator"]}
    emp, cust = v["keys"]["company"]["issuer"], v["keys"]["company"]["custody"]
    base = [s["sdjwt"] for s in v["chain_v1"]]
    casos = [("V1", base), ("V2", base + v["chain_v2"]["extra"]), ("V3", base + v["chain_v3"]["extra"]),
             ("V1 firma maleada", base[:7] + [v["malleated_outcome"]["jwt"] + "~"]), ("V4", v["chain_v4"]["chain"])]
    casos += [(n["id"], C.aplicar(base, n)) for n in v["negative"]]
    total = discrepan = 0
    for nombre, cadena in casos:
        rc = resultado(C, lambda: C.verificar_cadena(cadena, llaves, emp, cust))
        ra = resultado(A, lambda: A.verificar_cadena(cadena, llaves, emp, cust))
        total += 1
        if rc != ra:
            discrepan += 1
        print(("IGUAL    " if rc == ra else "DISCREPA ") + nombre + " -> " + rc + ("" if rc == ra else "  |  arquitecto: " + ra))
    mat = C.Material(docs=v["discovery"]["docs"])
    for caso in v["discovery"]["cases"]:
        def por_c():
            bloque, iss, _, _ = C.anclar(mat, caso["anchor"])
            return C.verificar_cadena(base, C.llaves_ancladas(mat, bloque, iss), iss, bloque.get("custody"))

        def por_a():
            iss, ll, cu = A.anclar(v["discovery"]["docs"], caso["anchor"])
            return A.verificar_cadena(base, ll, iss, cu)

        rc, ra = resultado(C, por_c), resultado(A, por_a)
        total += 1
        if rc != ra:
            discrepan += 1
        print(("IGUAL    " if rc == ra else "DISCREPA ") + caso["id"] + " -> " + rc + ("" if rc == ra else "  |  arquitecto: " + ra))
    print("\ncasos: %d, discrepancias: %d" % (total, discrepan))
    return 1 if discrepan else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(RAIZ, "..", "vectors", "vectores-0.1.json")))
