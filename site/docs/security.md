# Security, errors, recovery and versions

> The threats VXP addresses and the ones it does not, every error code, how operations recover from failures, and how keys and versions evolve.

## Threats

| Threat | How VXP covers it |
|---|---|
| Forgery by an outsider | Signatures, RFC 7638 `kid`, and keys anchored to the company's issuer ([§10 anchoring](https://vxpprotocol.org/spec/#issuer-anchoring)) |
| Terms changed after approval | The terms digest covers summary and terms; approval and execution must cite it ([P1](https://vxpprotocol.org/spec/#p1)) |
| Replay into another operation or to another agent | `op`, `seq`, `prev`, `aud` and `user` equal across the chain, verified |
| Two contradictory successes on one resource | One execution per resource ([O6](https://vxpprotocol.org/spec/#o6), [I2](https://vxpprotocol.org/spec/#i2)); across separate packages, only a log with witnesses |
| Another agent or user rewrites an operation | The full owner on every reuse ([ID3](https://vxpprotocol.org/spec/#id3)) |
| «The user approved», said by the agent | Labelled `agent_asserted`, with its real root ([P2](https://vxpprotocol.org/spec/#p2), [P7](https://vxpprotocol.org/spec/#p7)) |
| The company lies about its own system | No signature solves this. VXP relies on read-back, third-party evidence and an honest level label |
| The operator signs a whole alternative chain | Possible while the operator holds the keys and there are no witnesses: the verifier says `single_root: operator` |

Full table: [§9 security](https://vxpprotocol.org/spec/#security).

## Errors

| Where | Codes |
|---|---|
| Requests | `idempotency_key_required`, `invalid_request`, `target_not_found`, `idempotency_key_reused`, `request_exists`, `resource_busy`, `request_not_found`, `authorization_required` |
| Proposals | `terms_changed`, `proposal_expired`, `proposal_not_acceptable`, `attempt_limit_exceeded`, `counter_rejected`, `negotiation_limit_exceeded` |
| Authorization | `invalid_authorization_details`, and `invalid_target` on a native-only gateway |
| Relationship | `relationship_not_found`, `relationship_revoked`, `relationship_expired`, `action_not_authorized`, `relationship_limit_exceeded`, `target_not_found` |
| Closed questions | `alert_not_found`, `already_answered`, `alert_expired`, `option_not_allowed` |
| Verifier | The codes of the chain rules, plus `issuer_not_anchored` and the PACT receipt codes |

Someone else's resource and a missing one answer the same way, so an error never confirms that something
exists ([O3](https://vxpprotocol.org/spec/#o3)). Full table: [§9 errors](https://vxpprotocol.org/spec/#errors).

## Recovery

- **The response is lost.** Repeat the request with the same `Idempotency-Key`: you get the same request,
  never a second operation. Accepting a revision twice runs it once ([§8 idempotency](https://vxpprotocol.org/spec/#native-idempotency), [O6](https://vxpprotocol.org/spec/#o6)).
- **It is not known whether the effect happened.** The operation stays `pending_verification`, never `failed`.
  The company signs `unknown`. A later read reconciles without repeating the action, and a `correction`
  records what became known ([P3](https://vxpprotocol.org/spec/#p3), [P4](https://vxpprotocol.org/spec/#p4)).
- **The system contradicts the terms.** The read-back says so, the result stays `unknown`, the operation waits
  for a person, and nothing is retried ([P5](https://vxpprotocol.org/spec/#p5)).
- **Cancelling during execution** is a request to stop. It never claims a reversal that was not read back
  ([§8 cancellation](https://vxpprotocol.org/spec/#cancellation)).
- **The company's server restarts.** With persistent keys, earlier proofs still verify.

## Keys

- Persist proof keys. Rotate by publishing the new key and keeping the earlier one in the JWKS. Never reuse a
  retired key ([§10 key rotation](https://vxpprotocol.org/spec/#key-rotation)).
- The relationship key is distinct from the proof keys and from any Poppy or PACT key ([R5](https://vxpprotocol.org/spec/#r5)).
- The reference implementation keeps keys in `VXP_KEYS_DIR`. Without it, they live in memory and die with the
  process.

## Privacy

Personal data travels only as selective disclosures. `user` is a per-company pseudonym. Keys, issuers and log
tags are per company, and the log keeps no personal data ([§9 privacy](https://vxpprotocol.org/spec/#privacy)).

## Versions

Draft versions are incompatible with each other until 1.0, and a verifier rejects a `v` it does not know. See
[Specification and versions](https://vxpprotocol.org/docs/specification/) and the [changelog](https://vxpprotocol.org/docs/changelog/).

## Reporting a vulnerability

Privately, through the repository's Security tab. See `SECURITY.md`.
