VXP draft 0.1 · Downloads
=========================

Every file here backs a figure or a statement on vxpprotocol.org (Conformance, Examples, Verify and
Status pages). Identifiers and customer-facing strings of the reference implementation are in Spanish,
as in its Chilean test companies; its comments are in English.

This is not an independent certification. All runs were made by SOVRAS, on SOVRAS machines, against
the reference implementation published in the same repository.

Test data. Every signed file here uses neutral test data: "Ferreteria Demo", "Hotel Demo", "Cliente de
prueba A", "Calle Ejemplo 100". They are fictitious on purpose; inventory, payments and the WhatsApp
approval line are simulated. Signed files are published exactly as signed. In the logs, which carry no
signature, local paths of the machine that ran them are shown with the repository layout.

Environment: Windows 11, Node.js 22.20.0, Python 3.14.0 with cryptography 50.0.2.
Versions tested: Poppy draft 0.2 with Operations v1 (official kit, commit 39b35bd), PACT 1.0 over
A2A 1.0.1 (official openpactprotocol repository, commit 838c6bd).


1. runs-2026-10-22-evening/  (the latest full run, against the repository)
--------------------------------------------------------------------------
Each log starts with "== <name> · <UTC time> · <command>" and ends with "exit <code>".
correr.sh is the script that produced them.

  01-npm-test.log             npm test: the reference suite, 149 tests, in process. It includes the
                              official Poppy validator (draft 0.2 kit), three runs, each
                              {"pass":59,"skip":15}: it covers discovery and conversations and skips
                              sign-in and Operations, so it is not full Poppy conformance. It also
                              includes the native-only gateway test and the key rotation tests.
  02-red.log                  Tests over the network (gateway and agent in separate processes). 3 pass.
  03-mutar-vxp.log            21 mutations: each switches one protection off and its test must fail. 21/21.
  04-mutar-nativo.log         15 mutations of the native profile. 15/15.
  05-mutar-exigencia.log      15 mutations of the store and hotel scenarios. 15/15.
  06-mutar-prueba.log         39 mutations of the proof chain. 39/39.
  07-vectores-verificar.log   verifier/verificar.py over the vectors. 0 failures.
  08-vectores-paquete.log     verifier/verificar_paquete.py over the vectors. 92 checks, 0 failures.
  09-vectores-pact.log        The same over the PACT vectors. 16 checks, 0 failures.
  10-cruce.log                Both Python verifiers on the same 49 cases. 0 discrepancies.
  11-fuzz.log                 20,000 random chains, valid and tampered, both verifiers. 0 discrepancies.
  12-recorrido-nativo.log     The native-only run over the network, with persistent keys (folder 2). 2 pass.
  13-pact-ferreteria.log      Official PACT Identity suite (10 tests) and SOVRAS's own delegated test
                              written with the official PACT client (12 tests), against the test store.
                              22 passed. The official PACT delegated suite runs only against PACT's demo
                              airline, so the delegated test here is SOVRAS's own, not the official one.
  14-pact-hotel-identity.log  Official PACT Identity suite against the test hotel. 10 passed.
  15-verificar-vivo.log       The Python verifier against the PACT run's proofs, fetching public material
                              from the live local gateway, with live negatives. 16 checks, 0 failures.
  16-verificador-web.log      The Verify page's JavaScript verifier under Node.js against the Python
                              verifier: vectors, every published proof, altered variants. 0 discrepancies.
  17-fuzz-web.log             Differential fuzz of the JavaScript verifier against Python. 0 discrepancies.

2. native-run-2026-10-22-evening/  (reproduced run: native profile only)
-----------------------------------------------------------------------
  The gateway ran with no adapter (no poppy.json, no Agent Card, no A2A) and persistent proof keys;
  the agent signed with node:crypto. Reproduce it from reference/ with
  scripts/recorrido-nativo.test.ts (see the repository README).
  paquete-op_*.json           The proof package (signed statements).
  material-op_*.json          The public material saved from the gateway: issuer metadata, key sets and
                              log checkpoint. It anchors the company by its issuer only.
  operacion-op_*.json         The operation the agent saw.
  http-log.json               Every HTTP exchange of the agent during the run. Tokens in it are test
                              tokens of a local gateway that no longer runs.
  The issuer in these proofs is the local gateway where they ran (localhost:3730).

  Offline check:
    python verifier/verificar_paquete.py material \
      --material native-run-2026-10-22-evening/material-op_<id>.json \
      --paquete  native-run-2026-10-22-evening/paquete-op_<id>.json \
      --operacion native-run-2026-10-22-evening/operacion-op_<id>.json

3. native-run-2026-10-22/  (reproduced run, early morning of the same day)
-------------------------------------------------------------------------
  The first native-profile capture (03:09 Chile time), before the evening revision: its proof
  material lived under /sovras/ paths, still inside its signed content, and its keys were in memory.
  Its material anchors by issuer and it still verifies with the files here.

4. pact-run-2026-10-22-evening/
-------------------------------
  The proofs left by run 13: pact-op_*.json (package), .recibo.json (PACT receipt of the turn that
  proposed), .op.json (operation the agent saw, when kept) and .material.json (public material,
  anchored by the company issuer). Approval in both is through the company's channel (company_channel).

5. vectors/
-----------
  vectores-0.1.json           Proof test vectors: chains, operation cases, log, negative cases, discovery.
  vectores-pact-0.1.json      PACT anchoring and PACT receipt cross-check vectors.
  Both carry TEST-ONLY private keys (field "d_TEST_ONLY"), derived from public phrases so anyone can
  regenerate the signatures. Example hosts use *.example. Never use these keys outside tests.

6. verifier/
------------
  verificar_paquete.py        Reference verifier (Python, "cryptography" library; no code shared with
                              the TypeScript issuer).
  verificar.py                Second Python verifier, by the same team.
  vxp-verify.js               The browser verifier of the Verify page (ES module, WebCrypto).

7. earlier-2026-10-21/
----------------------
  poppy-validator-tunnel.json The official Poppy validator run against the public tunnel of the test
                              store on 21 Oct 2026: 59 pass, 0 fail, 15 skipped.

Operations of 21 October 2026 with live agents are described on the Examples page. Their signed packages
carry the names of the earlier test companies and are not published here. One of them (OP-5) has been
re-verified by signature; the others can no longer be, because their keys lived in memory.
