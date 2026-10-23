---
title: Guide for verifiers
description: How anyone checks a VXP proof (an agent, a bank, an auditor, an arbitrator) and how to read what the verdict says and does not say.
---

## What you need

- The **package**: `{v, company, op, statements[], log}`, as the agent received it.
- An **anchor** you obtained independently: the company's domain or its issuer. Never a document handed
  over by whoever presents the package ([[issuer-anchoring|§10 anchoring]]).
- Optionally, the **operation the agent saw**: its revision, summary, terms, expiry and state. The verifier
  then also checks that what the agent was shown is what was signed ([[P8]]).

The repository has three verifiers that share no code with the issuer:
- `verifier/verificar_paquete.py`, the reference, in Python with `cryptography`;
- `verifier/verificar.py`, a second one in Python;
- `verifier/vxp-verify.js`, in JavaScript (WebCrypto), which runs in the browser and in Node.js.

All three return the same verdict on every vector.

## Verify offline, with saved material

Save the public material once (the issuer's metadata and the key sets and checkpoint it names) and
verify any time later, with no server:

```sh title="Offline"
python3 -m pip install cryptography
python3 verifier/verificar_paquete.py material \
  --material material.json --paquete paquete.json --operacion operacion.json
```

`material.json` is `{"anchor": {"issuer": "<issuer>"}, "docs": {"<url>": "<body>", …}}`, optionally with
`obtained_at`, the date it was fetched. The Python verifier's modes and flags are in Spanish: `vivo` is live,
`paquete` the package, `operacion` the operation and `vectores` the test vectors. The published runs in the
site's downloads include it, so you can try this right now.

## Verify live

```sh title="Live, fetching the material over HTTPS"
python3 verifier/verificar_paquete.py vivo --issuer https://agents.example.com/e/store \
  --paquete paquete.json --aud https://agent.example/agent.json
```

## In the browser or in Node.js

```js title="vxp-verify.js"
import { verifyPackage } from "./verifier/vxp-verify.js";
const verdict = await verifyPackage({ package: packageText, material: materialText, operation: operationText });
```

The [Verify](/verify/) page runs this module on published proofs, and lets you tamper with them to see each
rejection.

## Reading a verdict

A valid signature, the operator's testimony and an independent confirmation of a fact are three different
things ([[reading-a-verdict|§10 reading a verdict]]):

| Question | Where the verdict answers it |
|---|---|
| Integrity: has the chain changed, is it complete and ordered? | `valid`, and on failure `error` and `seq` |
| Provenance: who signed each link, anchored to whom? | `company`, `anchor`, `key_source` (`issuer_metadata_live` or `issuer_metadata_saved`) |
| Authority: what was approved, and how? | `revision`, `approval` (`agent_asserted` or `company_channel`) |
| Declared result | `final_state`: what the company asserts |
| Corroboration | `derived_assurance[]`, `single_root`, `custody_declared`, `logged` |

`derived_assurance` lists levels named by their real root of trust ([[P7]]):

| Level | Root of trust |
|---|---|
| `issuer_key_attested` | whoever controls the issuer's key |
| `operator_observed` | the operator |
| `operator_reported_read_back` | the operator, who says it read the system |
| `operator_reported_agent_approval` | the operator, who says the agent said the user approved |
| `operator_reported_channel_approval` | the operator, who says the answer came through the company's channel |

The specification also defines `logged`, `time_stamped`, `third_party_*` and `user_confirmed`; no verifier grants
them yet.

`single_root: operator` with `logged: false` means: intact and ordered, and not independent of the operator.

## Errors you will see

The first failing check decides the error and its `seq` ([[proof-chain-rules|§6 chain rules]]). The common
ones:
- `signature_invalid` or `unknown_key`: the signature fails, or the key is not published by the anchored
  issuer;
- `seq_error` or `chain_broken`: a link is missing, reordered or replaced;
- `aud_mismatch`: the package was issued to another agent;
- `approval_terms_mismatch`, `execution_terms_mismatch` or `outcome_terms_mismatch`: links that cite another
  revision;
- `succeeded_without_matching_read_back`: success without reading the system;
- `operation_terms_mismatch`: the agent was shown other terms;
- `issuer_not_anchored`: the material does not anchor to the issuer.

The full list, check by check, is in `verifier/CHECKS.md`.

## Old proofs and retired keys

Statements name their key by `kid`. A company that rotates keeps earlier public keys published. A key that
was retired verifies only against material saved while it was published. The verdict then says
`key_source: issuer_metadata_saved`, and your report should give the date of that material ([[key-rotation|§10 key rotation]]).
