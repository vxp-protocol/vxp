# VXP, Verifiable eXchange Protocol

**Status: draft 0.1. The native profile is experimental.** Adapters exist for Poppy draft 0.2 and PACT 1.0.

VXP is an open protocol for work that agents do for people inside companies. It comes from building
agents that change orders, deliveries and reservations in companies' own systems: after every one
of those operations someone asks who asked and for whom, which exact terms the person approved, and
what the company's system recorded afterwards. When the request comes from a person's own agent,
the company did not build that agent and cannot see its conversation, so those answers have to
travel with the operation. VXP decides what an agent may do, keeps an authorized relationship that
either side can start, and leaves a signed proof that is checked against the company's own system.

## Repository layout

| Path | What it holds |
|---|---|
| [`site/`](site/) | The published site, as built. The normative text is [`site/spec/index.html`](site/spec/index.html). |
| [`spec/`](spec/) | Pointer to the normative text. |
| [`reference/`](reference/) | Reference implementation (Node.js, TypeScript run natively), with its tests. |
| [`verifier/`](verifier/) | Independent verifiers: two in Python and one in JavaScript for browser and Node, plus [`CHECKS.md`](verifier/CHECKS.md). |
| [`vectors/`](vectors/) | Conformance test vectors and the scripts that generate them. |

## Running the tests

Requirements: Node.js 22.18 or newer, Python 3 with the `cryptography` package
(`pip install cryptography`). The reference implementation has no npm dependencies.

```sh
cd reference
npm test                # 141 tests in process, including the official Poppy validator
npm run test:network    # 3 tests over TCP: gateway and agent in separate processes (ports 3610-3634)
```

Verifiers and vectors, from the repository root:

```sh
python verifier/verificar_paquete.py vectores vectors/vectores-0.1.json    # 92 checks, 0 failures
python verifier/verificar_paquete.py pact vectors/vectores-pact-0.1.json   # 16 checks, 0 failures
python verifier/verificar.py vectors/vectores-0.1.json
node verifier/tests/test-vxp-verify.mjs     # JavaScript verifier against the Python reference
node verifier/tests/fuzz-vxp-verify.mjs     # differential fuzz, default 3000 chains
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
- Some URLs in examples and signed files name `sovras.io` hosts. They belong to SOVRAS acting as
  operator of the reference deployment; they are not protocol identifiers. Protocol identifiers use
  `vxpprotocol.org`.

## License

Apache License 2.0, see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). The vendored Poppy kit keeps
its own Apache 2.0 license in [`reference/vendor/poppy-kit/`](reference/vendor/poppy-kit/).

Developed by SOVRAS, Santiago de Chile.
