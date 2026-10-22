"""Saves the public material a verifier needs to check a proof without the server.

Runs the independent verifier in `material` mode; every public document it asks for that is not yet in the
material is fetched once from the live server (local HTTP) and kept. At the end it verifies again with the
saved material only, which is what anyone can repeat.

Usage: python capturar-material.py <verifier> <server http://host:port> <issuer http(s)://… | anchor domain> <package> <out.json> [operation.json]
An issuer anchors the company by its RFC 8414 metadata alone (native profile); a bare domain uses the
adapter-domain anchor.
"""
import contextlib, importlib.util, io, json, sys, urllib.parse, urllib.request

ver_path, servidor, ancla, paquete, salida = sys.argv[1:6]
operacion = sys.argv[6] if len(sys.argv) > 6 else None
spec = importlib.util.spec_from_file_location("verificador", ver_path)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

material = {"anchor": {"issuer": ancla} if ancla.startswith("http") else {"domain": ancla}, "docs": {}}
json.dump(material, open(salida, "w", encoding="utf8"))
original = v.Material.traer
bajados = []


def traer(self, url, crudo=False, redirecciones=False):
    if self.docs is not None and url not in self.docs:
        u = urllib.parse.urlparse(url)
        if u.netloc == urllib.parse.urlparse(servidor).netloc or u.netloc == ancla:
            cuerpo = urllib.request.urlopen(servidor + u.path + (f"?{u.query}" if u.query else ""), timeout=10).read().decode("utf-8")
            self.docs[url] = cuerpo
            material["docs"][url] = cuerpo
            bajados.append(url)
    return original(self, url, crudo, redirecciones)


v.Material.traer = traer
args = ["material", "--material", salida, "--paquete", paquete] + (["--operacion", operacion] if operacion else [])
for _ in range(20):
    antes = len(bajados)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            v.main(args)
        except SystemExit:
            pass
    json.dump(material, open(salida, "w", encoding="utf8"), indent=1)
    if len(bajados) == antes:
        break
v.Material.traer = original
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    try:
        v.main(args)
    except SystemExit:
        pass
print("documents:", len(material["docs"]))
print(buf.getvalue().strip())
