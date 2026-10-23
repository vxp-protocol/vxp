---
title: Failures and how VXP behaves
description: What a company, an agent and a verifier do when authority is missing, a permission is revoked, terms change, a request repeats or a result is unknown. Every row is covered by a test in the repository.
---

Each row names the test that covers it. Tests in `reference/` run with `npm test` (and `npm run test:network`
for `test-red/`); tests in `agent/` with `npm test` in that folder; the conformance validator runs the same checks
against any implementation ([Conformance](conformance.md)). Error codes are those of [[errors|the specification]].

## Missing or wrong authority

| Situation | What happens | Covered by |
|---|---|---|
| An agent asks without authority | `202` with `state: authorization_required` and exactly the `authorization_details` to ask the person for; nothing runs ([[O2]]) | `reference/test/nativo.test.ts` 7 · validator Q2 |
| A grant for one resource is used for another | Refused, both to ask and to accept; a resource of another customer is not granted | `reference/test/vxp.test.ts` B2 · `reference/test/nativo.test.ts` 5 |
| An agent with read-only scope tries to change something | The company asks for the missing scope; nothing changes | `reference/test/poppy-flujo.test.ts` «con sólo lectura» |
| Another user of the same agent reads or accepts someone else's request | `404`: for that identity the request does not exist ([[ID3]]) | validator O3 · `reference/test/exigencia.test.ts` NH-I |
| The total is above what the person approved | `403 authorization_required` with the amount to authorize; the agent does not accept above the person's own cap and does not ask for more | `reference/test/vxp.test.ts` G3 · `agent/test/negatives.test.ts` «cap exceeded» |
| `approved_by: "standing_permission"` on a revision that requires the person | `403 user_approval_required` | `reference/test/exigencia.test.ts` NH-P · `reference/test/poppy-flujo.test.ts` «un permiso permanente no basta» |
| The person denies the exact terms | Nothing runs | `agent/test/negatives.test.ts` «person denies» |
| A token of one company at another | Not valid; nothing crosses between companies | `reference/test/poppy-flujo.test.ts` «nada cruza» · `reference/test/exigencia.test.ts` HO-A5 |

## Revocation and expiry

| Situation | What happens | Covered by |
|---|---|---|
| The person revokes between the proposal and the acceptance | Accepting no longer runs anything ([[O5]]) | `reference/test/vxp.test.ts` B4 · `reference/test/exigencia.test.ts` HO-A7 |
| The proposal, the device code or the session expires | `409 proposal_expired` or a refused token; nothing runs | `reference/test/nativo.test.ts` 2 · `reference/test/vxp.test.ts` F4 · `reference/test/exigencia.test.ts` HO-A7 |
| A relationship is revoked by the person, the company or the agent | The company cannot start anything (`relationship_revoked`); a pending proposal from it is no longer accepted; a late answer is refused ([[R6]], [[R9]], [[R10]]) | `reference/test/vxp.test.ts` E4, E5 · `reference/test/relacion-poppy.test.ts` RP3 · validator R11, R12 · `agent/test/negatives.test.ts` «relationship revoked…» |
| A relationship expires | `relationship_expired`; the agent's inbox and reply refuse it too | `reference/test/vxp.test.ts` E5 · `agent/test/negatives.test.ts` «relationship expired» |

## Changed or altered terms

| Situation | What happens | Covered by |
|---|---|---|
| The agent accepts a revision that a counter-proposal superseded | `409 terms_changed`; nothing runs ([[O4]]) | `reference/test/vxp.test.ts` B1 · validator N2 · `reference/test/poppy-flujo.test.ts` «si cambian los términos» |
| Too many revisions or acceptance attempts | `negotiation_limit_exceeded` or `attempt_limit_exceeded`; the request ends `failed` without effect | `reference/test/nativo.test.ts` 2 |
| A signed statement is changed without signing it again | The verifier answers `signature_invalid` | `reference/test/prueba-resultado.test.ts` «una prueba alterada» · validator V7 |
| The agent was shown other terms than the ones the company signed | `operation_terms_mismatch` ([[P8]]) | `reference/test/prueba-resultado.test.ts` «términos cambiados» · [Quickstart](quickstart.md) step 3 |
| The operator re-signs the execution on another revision | `execution_terms_mismatch` ([[P1]]) | `reference/test/prueba-resultado.test.ts` «el operador re-firma» |
| `succeeded` without a matching read of the company's system | `succeeded_without_matching_read_back` ([[O7]]) | `reference/test/prueba-resultado.test.ts` «resultado succeeded sin lectura» |
| A package or statement of another company, a replayed result, or another chain of the same size | Rejected by the verifier | `reference/test/prueba-resultado.test.ts` «otra empresa», «replay», «equivocación» |

## Duplicates and lost answers

| Situation | What happens | Covered by |
|---|---|---|
| A write without `Idempotency-Key` | `400 idempotency_key_required` | `reference/test/nativo.test.ts` 7 · validator Q1 |
| The same key with another body | `409 idempotency_key_reused`; the same key and body return the same request | `reference/test/nativo.test.ts` 7 · validator Q3 |
| The agent accepts twice | One execution; the second answer is the same result ([[O6]]) | `reference/test/vxp.test.ts` B3 · validator X3 |
| The connection drops while accepting and the agent retries | The retry sees the same state; one booking | `reference/test/exigencia.test.ts` HO-A6 · `reference/test-red/exigencia-red.test.ts` RX1 |
| The payment provider does not answer | The company reconciles by idempotency; never two charges | `reference/test/exigencia.test.ts` HO-C4 |
| The same order asked through Poppy, PACT and the native profile | Three operations, one execution; the others fail without effect | `reference/test/vxp.test.ts` A1 |

## Results nobody can confirm yet

| Situation | What happens | Covered by |
|---|---|---|
| The company's system does not answer after executing | The company signs `unknown`, does not retry; a later read adds a correction to `succeeded` citing it ([[P3]], [[P4]]) | `reference/test/prueba-resultado.test.ts` «timeout» · `reference/test/exigencia.test.ts` HO-C3 |
| The read of the system contradicts what was approved | `matches_terms: false`, the result stays `unknown`, the operation waits for a person ([[P5]]) | `reference/test/exigencia.test.ts` HO-A2 · `reference/test/ataques-ronda-3.test.ts` M1 |
| A capability that cannot read its result back | Never `succeeded`; at most `unknown` ([[P6]]) | `reference/test/vxp.test.ts` C3 |

## Inside a relationship

| Situation | What happens | Covered by |
|---|---|---|
| An action outside the relationship, another customer's resource, or over the daily limit | Rejected before signing or sending anything: `action_not_authorized`, `target_not_found`, `relationship_limit_exceeded` ([[R6]]) | `reference/test/vxp.test.ts` E3 · `reference/test/exigencia.test.ts` RE-A |
| An answer outside the question's options, or a second answer | `400 option_not_allowed`, `409 already_answered` ([[R17]]) | validator R8, R10 |
| A company message with a forged signature or a repeated `jti` | The agent's inbox rejects it ([[R7]]) | `agent/test/negatives.test.ts` «forged signature or a repeated jti» |
| A company returns identifiers with an unexpected shape, or the id of another company's request | The agent refuses them and keeps the other company's request intact | `agent/test/untrusted-ids.test.ts` |
| A company gives a URL outside its own base, or one not in canonical form (dot segments, backslashes, encoded separators, a look-alike host) | The agent sends no credential there | `agent/test/untrusted-ids.test.ts` |
| An approval given at one company is presented for the same proposal text at another | It does not count: approvals are bound to the company | `agent/test/untrusted-ids.test.ts` |
| A PACT Agent Card points the token endpoint or the interface at another server, or tries to rewrite a known company | The agent ignores the Card; tokens are only refreshed where they were issued | `agent/test/untrusted-ids.test.ts` |

The objects of every row match the [JSON Schemas](schemas.md); the conformance validator checks that with S1.
