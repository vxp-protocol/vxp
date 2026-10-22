# VXP, Verifiable eXchange Protocol

**Status: draft 0.1. The native profile is experimental.** Adapters exist for Poppy draft 0.2 and PACT 1.0.

VXP is an open protocol for work that agents do for people inside companies. It comes from building
agents that change orders, deliveries and reservations in companies' own systems: after every one
of those operations someone asks who asked and for whom, which exact terms the person approved, and
what the company's system recorded afterwards. When the request comes from a person's own agent,
the company did not build that agent and cannot see its conversation, so those answers have to
travel with the operation.

VXP has two public components:

- **VXP Proof**: a signed chain that binds the request, the exact terms of each revision, the approval
  given on them, the execution, the later read of the company's system and the declared outcome,
  checkable by anyone with the company's public keys.
- **VXP Relationship**: an authorized agreement between a personal agent and a company, with allowed
  actions, limits, validity and revocation, inside which either side can start a request.

It also states operation requirements (O1 to O7) every implementation meets where a request becomes an
operation, such as executing only the approved revision and only once. How an implementation enforces
them inside is its own decision. VXP can be implemented with its native profile alone, without Poppy,
PACT or SOVRAS; the adapters for Poppy and PACT are optional.

## Repository layout

| Path | What it holds |
|---|---|
| [`spec/`](spec/) | The normative text: [`spec.tpl.html`](spec/spec.tpl.html), built into `site/spec/index.html` with `python spec/build.py`. |
| [`site/`](site/) | The published site, as built. |
| [`reference/`](reference/) | Reference implementation (Node.js, TypeScript run natively), with its tests. |
| [`verifier/`](verifier/) | Independent verifiers: two in Python and one in JavaScript for browser and Node, plus [`CHECKS.md`](verifier/CHECKS.md). |
| [`vectors/`](vectors/) | Conformance test vectors and the scripts that generate them. |

## Running the tests

Requirements: Node.js 22.18 or newer, Python 3 with the `cryptography` package
(`pip install cryptography`). The reference implementation has no npm dependencies.

```sh
cd reference
npm test                # tests in process, including the official Poppy validator and a native-only gateway
npm run test:network    # tests over TCP: gateway and agent in separate processes (ports 3610-3634)
```

Verifiers and vectors, from the repository root:

```sh
python verifier/verificar_paquete.py vectores vectors/vectores-0.1.json    # 92 checks, 0 failures
python verifier/verificar_paquete.py pact vectors/vectores-pact-0.1.json   # 16 checks, 0 failures
python verifier/verificar.py vectors/vectores-0.1.json
node verifier/tests/test-vxp-verify.mjs     # JavaScript verifier against the Python reference
node verifier/tests/fuzz-vxp-verify.mjs     # differential fuzz, default 3000 chains
```

A reproducible native-only run over the network, with persistent keys, the one published under
`site/downloads/`:

```sh
cd reference
VXP_RECORRIDO_DIR=<out> VXP_KEYS_DIR=<private dir> node --test scripts/recorrido-nativo.test.ts
```

The delegated PACT test (`reference/test-pact/`) runs inside a clone of the official
openpactprotocol repository; see [`reference/README.md`](reference/README.md).

## Notes

- All companies, people, addresses and phone numbers in the code, tests, vectors and signed
  examples are fictitious test data ("Ferretería Demo", "Hotel Demo", "Librería Demo",
  "Cliente de prueba A/B", "Calle Ejemplo 100"). Inventory, payments and the WhatsApp line are simulated.
- Every key in this repository is a test key. Keys whose private part appears (`d_TEST_ONLY` in the
  vectors) are derived from public phrases and must never be used for anything else.
- In the reference implementation, identifiers and customer-facing strings are in Spanish, as in the
  Chilean test companies; comments are in English.
- Protocol identifiers use `vxpprotocol.org`. Paths such as `/vxp/proof-jwks.json` or `/vxp/log/` are
  this implementation's own and are discovered through the issuer metadata (spec §8, Implementation
  paths). Until the evening revision of 22 October 2026 they were under `/sovras/`, still answered as an alias; files signed
  before that revision keep those names inside their signed content and are published exactly as signed.
- Proof keys: with `VXP_KEYS_DIR` the reference implementation keeps them across restarts and keeps
  earlier public keys published after a rotation (spec §10, Key rotation).

## License

Apache License 2.0, see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). The vendored Poppy kit keeps
its own Apache 2.0 license in [`reference/vendor/poppy-kit/`](reference/vendor/poppy-kit/).

Developed by SOVRAS, Santiago de Chile.
