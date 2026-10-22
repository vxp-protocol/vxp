"""Builds site/spec/index.html from spec/spec.tpl.html.

The template is the normative text. Each <!--J:name--> marker is replaced by a JSON object captured from the
reference implementation (site/assets/recorrido-data.js), so the examples in the specification are the
objects the implementation actually produced. Usage, from the repository root: python spec/build.py
"""
import html
import json
import pathlib

RAIZ = pathlib.Path(__file__).resolve().parent.parent
src = (RAIZ / "site" / "assets" / "recorrido-data.js").read_text(encoding="utf-8")
data = json.loads(src[src.index("{"):src.rindex("}") + 1])
st = {s["id"]: s for s in data["steps"]}
blocks = {
    "discover": st["discover"]["response"],
    "authreq": st["authority"]["response"],
    "token": st["authority"]["token"],
    "proposal": st["operate"]["proposal"],
    "chain": st["prove"]["chain"],
    "verdict": st["prove"]["verdict"],
    "relate": {"relationship": st["relate"]["relationship"], "delivery": st["relate"]["outbox"]},
}
t = (RAIZ / "spec" / "spec.tpl.html").read_text(encoding="utf-8")
for k, v in blocks.items():
    t = t.replace(f"<!--J:{k}-->", html.escape(json.dumps(v, indent=2, ensure_ascii=False), quote=False))
assert "<!--J:" not in t, "a marker has no captured object"
(RAIZ / "site" / "spec" / "index.html").write_text(t, encoding="utf-8")
print("ok", RAIZ / "site" / "spec" / "index.html")
