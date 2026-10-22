# VXP reference implementation

A company gateway that receives personal agents over Poppy draft 0.2, PACT 1.0 (A2A 1.0.1) and the
native VXP profile (experimental), on one operational core held in memory. It serves three
fictitious test companies: Ferretería Demo (store), Hotel Demo (on another host) and Librería Demo.
Inventory, payments, the company system and the WhatsApp line are simulated.
Identifiers and customer-facing strings are in Spanish, as in the Chilean test companies; comments
are in English.

Requirements: Node.js 22.18 or newer (TypeScript runs natively), Python 3 with `cryptography`
for the independent verifier (`../verifier/verificar_paquete.py`, called by several tests).

```sh
npm test                 # test/*.test.ts: 137 tests, in process
npm run test:network     # test-red/*.test.ts: 3 tests over TCP (ports 3610, 3614, 3630, 3632, 3634)
npm start                # local gateway on :3100 (PORT, PA_PORT, PUBLIC_ORIGIN, HOTEL_ORIGIN)
```

Directories:

- `src/`: the gateway. `puerta.ts` routes, `nucleo.ts` is the operational core, `poppy.ts`,
  `pact.ts` and `nativo.ts` are the three protocol faces, `prueba.ts` issues VXP Proof.
- `test/`, `test-red/`: in-process and over-the-network tests.
- `test-pact/`: the delegated PACT test. It needs the official client, so it runs inside a clone of
  the openpactprotocol repository (commit 838c6bd, with `pnpm install`) against a running gateway:
  `scripts/pact-e2e.sh <path to the clone>`. It reads a local agent key from
  `.prueba/pa-private.jwk` (a P-256 private JWK you generate; `.prueba/` is ignored by git) and the
  gateway log in `.prueba/server.log`.
- `scripts/`: mutation runs (`mutar-*.mjs`, `mutar-prueba.py`: switch one protection off and require
  a test to fail), verifier cross-checks and differential fuzz, live verification and browser
  walkthroughs (these need Playwright and write captures to `.prueba/`).
- `vendor/poppy-kit/`: the official Poppy company kit, unmodified, Apache 2.0 (see its README).

Mutation switches are read from the `SOVRAS_MUTAR` environment variable (`src/mutar.ts`); without
it no protection is switched off. The `x-sovras-*` header and the `/sovras/...` paths are the
operator's own surface in this implementation, not part of the protocol.
