---
title: Tests and conformance
description: How to check an implementation against VXP, with the validator, the conformance matrix and the checklist, and which tests are whose.
---

## The validator

`conformance/validate.ts` acts as a personal agent against a company's server and reports every check with
the rule it tests. It shares no code with the reference implementation: it signs with `node:crypto`, and it
checks the proof with the independent browser verifier, anchored by the issuer. Node.js 22.18+, no
dependencies.

```sh title="Against the reference implementation (native only)"
node conformance/reference/run.ts --report conformance-report.json
```

```sh title="Against your implementation"
node conformance/validate.ts my-config.json --report my-report.json
```

The config names your discovery domain, one write operation on a resource your test account owns, and how
the person approves (`"manual"`, or a command). Optionally, it adds a counter-proposal, a relationship and a
command that makes your company start a request. See `conformance/README.md`.

| Status | Meaning |
|---|---|
| `pass` | The requirement held |
| `fail` | It did not (exit code 1) |
| `optional` | An optional capability you do not offer, or did not configure |
| `manual` | It cannot be seen from outside: see the checklist |
| `skipped` | A step it depends on could not run |

What it checks, in order:
- discovery and metadata;
- session, DPoP and refusal without a proof;
- `Idempotency-Key`;
- authority held until the person approves, and the device authorization;
- the same request re-evaluated, the proposal and its commitment;
- isolation from another user, counter-proposal and `terms_changed`;
- one execution, success only after read-back, idempotent acceptance and events;
- the proof verified by issuer anchoring, cross-checked with the operation, and a tampered copy rejected;
- the relationship agreement and its signature;
- a company-initiated proposal and a closed question;
- revocation.

Against the reference implementation it reports 50 pass, 0 fail and 3 manual.

## The checklist

`conformance/CHECKLIST.md` lists what only a person can confirm:
- the consent screen's language ([[R3]]);
- account-linking evidence ([[ID1]], [[ID2]]);
- privacy;
- company review ([[O5]]);
- key custody and rotation.

## The matrix

`conformance/MATRIX.md` lists every normative rule with the reference tests, the validator checks and the
other evidence that cover it. It is generated from the specification, the tests and the validator, and the
build fails if a cited test does not exist.

## Three kinds of tests, never added together

| Kind | What | What it does not show |
|---|---|---|
| Official tools of other protocols | The Poppy validator (draft 0.2 kit) and the PACT Identity suite, unchanged | The Poppy validator skips sign-in and Operations; it is not full Poppy conformance. The official PACT delegated suite runs only against PACT's demo airline |
| Own adapter tests | Written by SOVRAS, including the delegated PACT flow with the official PACT client | That a third party agrees with them |
| VXP tests | The reference suite (in process and over the network), mutation runs, the native-only test, vectors, the three verifiers and the validator | Interoperability with an implementation written elsewhere |

## Running everything

```sh title="From the repository root"
cd reference && npm test && npm run test:network && cd ..
python verifier/verificar_paquete.py vectores vectors/vectores-0.1.json
python verifier/verificar_paquete.py pact vectors/vectores-pact-0.1.json
node verifier/tests/test-vxp-verify.mjs
node conformance/reference/run.ts
```

Continuous integration runs all of these on every push (`.github/workflows/ci.yml`).

## What this is not

A conformance report is the implementer's own evidence. It is not a certification, and passing the official
tools of Poppy or PACT on part of their scope is not conformance to those standards.
