# VXP Proof 0.1 test vectors

- `vectores-0.1.json`: chains, negative cases, discovery and anchoring cases, operation cases.
- `vectores-pact-0.1.json`: the PACT profile (anchoring by brand domain or PACT authorization
  server, and the cross-check with the PACT receipt).
- `generar.mjs`, `generar-pact.mjs`: the generators (`node vectors/generar.mjs > vectors/vectores-0.1.json`).

The committed JSON files are byte-identical to `site/downloads/vectors/`. ECDSA signatures and
salts are random, so a new run of a generator gives different bytes with the same verdicts.
The one unsigned disclosure of negative case N7 was edited to neutral test data (`Calle Ejemplo 200`);
its verdict, `disclosure_digest_mismatch`, is unchanged.

All keys are TEST keys derived from public phrases. The private scalars appear as `d_TEST_ONLY`
on purpose, so anyone can re-sign; never use them for anything else. Identifier strings such as
`SOVRAS-PROOF-0.1 PRUEBA ...` are those phrases, and the `perfil` field keeps the protocol's name
before the 22 October 2026 rename.
