# Guide for personal agents

> How a personal agent finds companies that speak VXP, acts with its user's permission, keeps its state, verifies results and answers the company within an agreement.

A person tells their agent: «Book a hotel in Santiago for two nights, with breakfast; negotiate the best rate
and book it if it is under $250,000». This guide shows what the agent does with any company that speaks VXP,
with no integration per company. The `agent/` folder of the repository implements every step as a library you
can import or copy, with a command-line tool and an MCP server; the [Quickstart](https://vxpprotocol.org/docs/quickstart/) runs it.

## 1. Have an identity

Your agent is an OAuth client identified by a URL it controls: its Client ID Metadata Document, with its
public key set. Keep the private key in your agent's own storage. If you want companies to reach you later,
declare an inbox in that document (`extensions["vxpprotocol.org/relationship"].inbox_uri`), on the same origin
([R2](https://vxpprotocol.org/spec/#r2)).

## 2. Discover

Start from domains you know or the person names. VXP has no global registry. For each one, fetch
`/.well-known/vxp.json`, keep only companies whose `capabilities` offer what you need, and read the issuer's
RFC 8414 metadata ([§8 discovery](https://vxpprotocol.org/spec/#native-discovery)). Public capabilities, such as availability or catalog,
need no consent.

## 3. Open a session and ask

Get a session token with `private_key_jwt` and a DPoP proof, with `resource` = the company's endpoint. Then
`POST /v1/requests` with an `Idempotency-Key` you keep. If the answer is `authorization_required`, it lists
exactly what to ask the person for ([O2](https://vxpprotocol.org/spec/#o2)).

## 4. Get the person's permission

Start a device authorization (RFC 8628) with those `authorization_details`, and show the person the
verification link. They approve on the company's page, linking their account through the company's own
channel. If the person sets a limit in advance, for example «up to $250,000», ask for it as a limit in the
authorization details. Within it, the agent may accept without asking again. Above it, the company asks for
more authority and you go back to the person.

## 5. Negotiate, then accept exactly once

Repeat the request with the same key: it becomes `proposed`, with a proposal of exact terms. Compare
proposals across companies. Counter if the company allows it. Never accept a superseded revision: the company
answers `terms_changed` ([O4](https://vxpprotocol.org/spec/#o4)). Accept the revision the person approved, or one within the limit they gave.
Accepting again never runs it twice ([O6](https://vxpprotocol.org/spec/#o6)).

## 6. Keep your state

Persist the session, the `Idempotency-Key`, the request ID, the proposal you are on and any relationship. If
your process restarts, read the request (`GET /v1/requests/{id}`) and continue from its state. Repeating with
the same key never creates a second operation.

## 7. Get and verify the evidence

Fetch `GET /v1/requests/{id}/proof` and verify it yourself, anchored by the issuer you discovered, with the
operation you were shown ([P8](https://vxpprotocol.org/spec/#p8)). Keep the package and the public material with it, so the person can
prove later what was agreed. See the [verifier guide](https://vxpprotocol.org/docs/guides/verifier/).

## 8. Keep the relationship

If the person approved a relationship, the company may write to your inbox ([R7](https://vxpprotocol.org/spec/#r7)):
- **Verify** each message's signature with the relationship key anchored to the issuer, and reject a repeated
  `jti`.
- **A proposal** is a normal operation: accept it only with the person's approval or within their limit ([R8](https://vxpprotocol.org/spec/#r8)).
- **A closed question**, for example «hold or release the booking», is answered once, with one of the options,
  at `reply_url` ([R17](https://vxpprotocol.org/spec/#r17)).
- **Revoke** the relationship with `DELETE /v1/relationships/{id}` when the person asks ([R10](https://vxpprotocol.org/spec/#r10)).

## 9. Optionally, Poppy and PACT

If a company only offers Poppy or PACT, use those protocols as written: see
[Interoperability](https://vxpprotocol.org/docs/guides/interoperability/). The VXP proof still travels in their extension points. The library
in `agent/` has both, as `PoppyAdapter` and `PactAdapter`, with the same identity, state and person's rules as
the native profile; the native profile never imports them. Under Poppy the agent confirms within the person's
rules; under PACT the person approves each write on the company's own channel and the agent cannot.

## The same steps with `agent/`

| Step | Library (`VxpAgent`) | CLI (`vxp-agent`) | MCP tool |
|---|---|---|---|
| 1 Identity | `VxpAgent.open({ stateDir, publicOrigin })`, `startAgentServer` | `serve` | `mcp --port` |
| 2 Discover | `discover(domains)`, `read(company, operation, params)` | `discover`, `read` | `vxp_discover`, `vxp_read` |
| 3 Ask | `createRequest(company, operation, target, params)` | `request` | `vxp_request` |
| 4 Permission | `authorize(company, { forRequest, capClp, relationship })`, `pollAuthorization` | `authorize`, `wait-authorization` | `vxp_authorize`, `vxp_check_authorization` |
| 5 Negotiate, accept | `resubmit`, `counter`, `accept` | `resubmit`, `counter`, `accept` | `vxp_resubmit`, `vxp_counter`, `vxp_accept` |
| 6 State | everything persists in `stateDir` | `--state DIR` | the same directory |
| 7 Evidence | `proof(requestId)`, `verifySaved(requestId)` | `proof`, `verify` | `vxp_proof` |
| 8 Relationship | inbox in `startAgentServer`, `reply`, `revokeRelationship` | `inbox`, `reply`, `revoke-relationship` | `vxp_inbox`, `vxp_reply`, `vxp_revoke_relationship` |

The person's rules are set only by the person: `setMandate` (a cap) and `setReplyRule` (a standing answer), or
`mandate set` and `mandate reply` in the CLI. No MCP tool sets them. `accept` sends
`approved_by: "standing_permission"` only when a cap the person set covers the total **and** the company marks
the revision `user_approval_required: false`; otherwise the person confirms the exact revision. Over MCP, the
model receives the approval id, the summary, the amount and a link without any secret. The person decides in
the host's own confirmation dialog, on the agent's page with a code shown only in their terminal, or with
`vxp-agent approve`.

`agent/README.md` has the commands, the rule-by-rule correspondence and the limits. The tests in `agent/test/`
cover the hotel task, each step in a new process, the person's refusal, a cap exceeded, revoked and expired
relationships, forged and replayed company messages, and altered proofs.

## What you can rely on, and what you cannot

- You can rely on: one execution per accepted revision; success only after the company read its system; and a
  proof you can check without trusting the company's server.
- You cannot rely on: that the company told the truth about its own system. The proof names its root of trust;
  today that root is the operator ([P7](https://vxpprotocol.org/spec/#p7)).
