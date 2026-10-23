---
title: Native profile and discovery
description: How an agent finds a company that speaks VXP, identifies itself, gets authority for one request, and drives an operation through the /v1 endpoints.
---

The native profile is VXP's own way to carry an operation. It needs neither Poppy nor PACT ([[native-only|§8, native-only gateway]]).
It is **experimental**, and `vxp.json` says so with `"status": "experimental"`.

## 1. Discover

The agent fetches `https://<company domain>/.well-known/vxp.json` ([[native-discovery|§8, discovery]]):

<!--json:discover.response title="GET /.well-known/vxp.json"-->

- `organization.domain` must be the host that served the document.
- `issuer` is the company's issuer; its RFC 8414 metadata lives at
  `/.well-known/oauth-authorization-server` + the issuer path, and its `issuer` must match character by
  character.
- `capabilities` lists only what the company offers to external agents. `access` is `public` or
  `delegated`; `admission` is `static` (the grant is enough) or `dynamic` (decided per request: owner,
  precondition, policy).
- `vxp.json` never carries keys. The verifier takes them from the issuer metadata (`vxp_proof`).

VXP has no global registry of companies. An agent starts from domains it already knows, or that the
person names.

## 2. Identify

The agent is an OAuth client identified by a Client ID Metadata Document at its own `client_id` URL, with
its JWKS. It authenticates with `private_key_jwt` and binds its token to a DPoP key (RFC 9449, ES256). The
user ID it holds for the person travels as an RFC 7523 assertion, and every native request carries
`resource` = the `endpoint` from `vxp.json` (RFC 8707) ([[native-authorization|§8, authorization]]).

<!--json:identify.form title="POST {issuer}/oauth/token · session"-->

## 3. Get authority for this request

Asking without authority is safe: the company holds the request and says exactly what is missing ([[O2]]).

<!--json:authority.response title="POST /v1/requests → 202 authorization_required"-->

The agent starts a device authorization (RFC 8628) with those `authorization_details` (RFC 9396). The person
approves on the company's own page, after linking their account through an authentication the company
controls ([[ID1]]). The token that follows carries exactly what was granted ([[O2]]).

## 4. Repeat the same request

The agent repeats the same request, with the same `Idempotency-Key`. It is the same request, re-evaluated
with the new authority ([[native-idempotency|§8, idempotency]]):

<!--json:context.response title="POST /v1/requests (same Idempotency-Key)"-->

- Same key and same body: the same request. Same key and another body: `409 idempotency_key_reused`.
- No key: `400 idempotency_key_required`.

## 5. Operate

The company answers with a proposal: a revision with exact terms, signed into the proof, and its commitment
([[commitment|§8, commitment]]).

<!--json:operate.proposal title="The proposal, revision 1"-->

The agent may counter (`POST /v1/proposals/{id}/counter`), which produces a new revision. Accepting a
superseded revision gets `409 terms_changed` and runs nothing ([[O4]]). Accepting the current one runs it
**once** ([[O6]]), and success is declared only after the company reads its system back ([[O7]]):

```http title="Accept the current revision"
POST /v1/proposals/{proposal_id}/accept
Authorization: DPoP <token>
DPoP: <proof>
Content-Type: application/json

{ "approved_by": "user" }
```

`approved_by: "user"` is the agent stating that the person approved: the proof records it as
`agent_asserted` ([[P2]]).

## 6. Prove, and keep the relationship

`GET /v1/requests/{id}/proof` returns the package (see [VXP Proof](proof.md)). If the person also approved a
relationship, the company can later start a request toward the agent (see [VXP Relationship](relationship.md)).

## Endpoints

| Method and path | What it does |
|---|---|
| `POST /v1/requests` | Create a request `{operation, target, parameters}`, with `Idempotency-Key` |
| `GET /v1/requests/{id}` | State, projections, proposal, effects, result, `proof_url` |
| `GET /v1/requests/{id}/events` | Transitions |
| `POST /v1/requests/{id}/cancel` | Ask to stop ([[cancellation|§8, cancellation]]) |
| `GET /v1/requests/{id}/proof` | The proof package |
| `POST /v1/proposals/{id}/accept` | Accept that revision |
| `POST /v1/proposals/{id}/counter` | Counter-proposal |
| `GET`, `DELETE /v1/relationships/{id}` | Read or revoke the agent's relationship |
| `POST /v1/relationships/{id}/replies` | Answer a closed question ([[R17]]) |

All of them take `Authorization: DPoP` and a DPoP proof. Full responses and errors:
[[native-endpoints|§8, endpoints]].

## States

Inside, a request moves through `received`, `authorization_required`, `proposed`, `accepted`,
`waiting_human`, `executing`, `pending_verification` and the final `succeeded`, `failed`, `cancelled` and
`expired` ([[E1]]). Each response also shows the projection onto Poppy's and A2A's enums ([[E2]]). A request
never moves to `failed` while it is unknown whether its effect happened.
