VXP draft 0.1 · Downloads
=========================

Every file here backs a figure or a statement on vxpprotocol.org (Conformance, Examples,
Verify and Status pages). Some names and messages are in Spanish, because the reference
implementation by SOVRAS is written in Spanish.

This is not an independent certification. All runs were made by SOVRAS, on SOVRAS
machines, against the reference implementation and test companies configured in SOVRAS.

Test data. The signed files in native-run-2026-10-22/, pact-run-2026-10-22/ and vectors/
were produced on 22 Oct 2026 with neutral test data: "Ferreteria Demo", "Hotel Demo",
"Cliente de prueba A", "Calle Ejemplo 100". They are fictitious on purpose. Their inventory,
payments and WhatsApp line are simulated. Signed files are published exactly as signed.
In the logs, which carry no signature, the names of the earlier test companies are replaced
by "[test store]", "[test hotel]" and "[address masked]"; local paths of the machine that ran
them are shown with the layout of this repository (reference/, verifier/, vectors/), and one
test agent's name as "agente de prueba B". Nothing else in the logs changed. In vectors/vectores-0.1.json, the value of the
one unsigned disclosure of negative case N7 now reads "Calle Ejemplo 200, Concepción"; its
verdict is unchanged.

Environment: Windows 11, Node.js 22.20.0, Python 3.14.0 with cryptography 50.0.2.
Versions tested: Poppy draft 0.2 (official kit, commit 39b35bd), PACT 1.0 over A2A 1.0.1
(official openpactprotocol repository, commit 838c6bd).


1. runs-2026-10-22/  (logs of the 22 Oct 2026 runs)
---------------------------------------------------
Each log starts with "== <name> · <UTC time> · <command>" and ends with "exit <code>".

  01-npm-test.log             npm test: full suite, 137 tests, including the official Poppy
                              validator (draft 0.2, kit 39b35bd), three runs, each
                              {"pass":59,"skip":15}. It covers discovery and conversations;
                              the kit does not check sign-in or the Operations extension.
  02-red.log                  Three tests over the network (server and agent in separate
                              processes). 3 pass.
  03-mutar-vxp.log            21 mutations of VXP; each switches one protection off and the
                              matching test must fail. 21/21 detected.
  04-mutar-nativo.log         15 mutations of the native profile design. 15/15.
  05-mutar-exigencia.log      15 mutations of the store and hotel scenarios. 15/15.
  06-mutar-prueba.log         39 mutations of the proof chain. 39/39.
  07-vectores-verificar.log   verificar.py over vectors/vectores-0.1.json. 0 failures.
  08-vectores-paquete.log     verificar_paquete.py over vectors/vectores-0.1.json. 92 checks, 0 failures.
  09-vectores-pact.log        verificar_paquete.py over vectors/vectores-pact-0.1.json. 16 checks, 0 failures.
  10-cruce.log                Both Python verifiers on the same 49 cases. 0 discrepancies.
  11-fuzz.log                 20,000 random chains, valid and tampered, both verifiers. 0 discrepancies.
  13-pact-ferreteria.log      Local server with neutral data: official PACT Identity suite
                              (10 tests) and SOVRAS's own delegated test written with the
                              official PACT client (12 tests). 22 passed. The official PACT
                              delegated suite only runs against PACT's demo airline.
  14-pact-hotel-identity.log  Official PACT Identity suite against the test hotel. 10 passed.
  15-verificar-vivo.log       The Python verifier against the two proofs of run 13, fetching
                              public material from the live local server. 16 checks, 0 failures.
  16-verificador-web.log      The Verify page's JavaScript verifier under Node.js, compared with
                              the Python verifier on these vectors and these proofs, as signed
                              and tampered. 189 comparisons, 0 discrepancies.
  17-fuzz-web.log             Differential fuzz of the JavaScript verifier against Python.
  correr.sh                   The script that produced logs 01 to 11.

  The local server's start-up output is not published: it contains an internal test key.

2. native-run-2026-10-22/
-------------------------
  A full run of VXP's native profile captured from the reference implementation: discovery,
  identity, per-operation authority, proposal, acceptance, one execution, read-back, proof,
  and a request started by the company inside an approved relationship.
  paquete-op_*.json           The proof package (signed statements).
  material-op_*.json          The public material saved from the company's server, so the
                              proof can be verified offline (verificar_paquete.py material ...).
  operacion-op_*.json         The operation the agent saw.
  The issuer in these proofs is the local test server where they ran (localhost:3730).

3. pact-run-2026-10-22/
-----------------------
  The proofs left by run 13: pact-op_*.json (package), .recibo.json (PACT receipt),
  .op.json (operation the agent saw), .material.json (public material for offline checks;
  op_01NpsuOhdE3C is approved through the company's channel, company_channel).

4. vectors/
-----------
  vectores-0.1.json           Proof test vectors: chains, operation cases, log, negative cases
                              and discovery cases.
  vectores-pact-0.1.json      PACT anchoring and PACT receipt cross-check vectors.
  Both carry TEST-ONLY private keys (field "d_TEST_ONLY"), derived from public phrases so
  anyone can regenerate the signatures. Never use them outside tests.

5. verifier/
------------
  verificar_paquete.py        Reference verifier (Python, "cryptography" library; no code shared
                              with the TypeScript issuer).
  verificar.py                Second Python verifier, by the same team (logs 07 and 10).
  vxp-verify.js               The browser verifier used on the Verify page (ES module, WebCrypto).

  Offline check of a native-run proof:
    python verifier/verificar_paquete.py material \
      --material native-run-2026-10-22/material-op_<id>.json \
      --paquete  native-run-2026-10-22/paquete-op_<id>.json \
      --operacion native-run-2026-10-22/operacion-op_<id>.json

6. earlier-2026-10-21/
----------------------
  poppy-validator-tunnel.json The official Poppy validator run against the public tunnel of the
                              test store on 21 Oct 2026: 59 pass, 0 fail, 15 skipped.
