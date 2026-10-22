# VXP Proof verifiers

| File | What it is |
|---|---|
| `verificar_paquete.py` | Reference verifier (Python, `cryptography`). Modes: `vectores`, `pact`, `material` (public material downloaded beforehand) and `vivo` (fetches the anchored material over HTTP). |
| `verificar.py` | Second Python verifier over the vectors, used for cross-checks. |
| `vxp-verify.js` | Independent verifier for the browser and Node 20 or newer, no dependencies. The same file is served by `site/verify/`. |
| `CHECKS.md` | What each control proves and does not prove, with line references to `verificar_paquete.py`. |
| `tests/` | Differential tests of `vxp-verify.js` against the Python reference. |

```sh
python verifier/verificar_paquete.py vectores vectors/vectores-0.1.json
python verifier/verificar_paquete.py material --material <material.json> --paquete <package.json> [--operacion <op.json>]
node verifier/tests/test-vxp-verify.mjs
node verifier/tests/fuzz-vxp-verify.mjs [chains] [seed]
```

`tests/test-vxp-verify.mjs` compares verdicts on the vectors and on the signed proofs in
`site/downloads/`, intact and altered. The checks for proofs issued before the 22 October 2026
rename (`legacy-0.1` naming) need the pre-rename reference verifier, which is not published here;
point `VXP_PY_LEGACY` at it to include them, otherwise they are skipped.

These test scripts used to live in `site/verify/`; they were moved here because they are not part
of the site. Only comments differ from the copies in `site/downloads/verifier/`.
