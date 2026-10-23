---
title: JSON Schemas
description: JSON Schemas (2020-12) for every object of VXP 0.1, published under vxpprotocol.org/schemas/0.1/, checked against the reference implementation and usable to validate your own.
---

The schemas restate the specification as JSON Schema 2020-12, so a company or an agent can check its objects
mechanically. Where a schema and the [specification](/spec/) differ, the specification governs. They are
versioned with the protocol: `https://vxpprotocol.org/schemas/0.1/<name>.schema.json`, each with that URL as its
`$id`. `common.schema.json` holds the shared definitions (digests, states, authorization details, commitment).

## The schemas

| Schema | Object | Rules |
|---|---|---|
| `vxp.schema.json` | `GET /.well-known/vxp.json` | [[native-discovery]] |
| `issuer-metadata.schema.json` | `vxp_proof` and `vxp_relationship` in the issuer's RFC 8414 metadata | [[issuer-anchoring]], [[R1]], [[R5]] |
| `client-metadata.schema.json` | The agent's Client ID Metadata Document, with its inbox | [[native-authorization]], [[R2]] |
| `token-response.schema.json` | The token response: `authorization_details` granted and `relationships[]` | [[native-authorization]], [[R4]] |
| `request-body.schema.json` | `POST {endpoint}/requests` body | [[native-endpoints]] |
| `request.schema.json` | A request: state, projections, missing authority, proposal, effects, result | [[native-endpoints]], [[O2]], [[O4]] |
| `read-response.schema.json` | The answer to a read capability | [[native-endpoints]] |
| `accept-body.schema.json`, `counter-body.schema.json` | Accept and counter-proposal bodies | [[native-endpoints]] |
| `events.schema.json` | `GET {endpoint}/requests/{id}/events` | [[native-endpoints]], [[E1]] |
| `error.schema.json` | An error answer | [[errors]] |
| `proof-package.schema.json` | `GET {endpoint}/requests/{id}/proof` | [[proof]] |
| `statement-header.schema.json`, `statement.schema.json` | Each statement's header, and its payload by kind | [[proof]], [[P1]]–[[P6]] |
| `checkpoint.schema.json` | The log checkpoint | [[issuer-anchoring]] |
| `relationship.schema.json`, `relationship-agreement.schema.json` | A relationship and its signed agreement | [[R4]], [[R10]], [[R11]] |
| `company-request.schema.json`, `inbox-delivery.schema.json` | A company-initiated request and its delivery | [[R7]], [[R8]] |
| `reply-body.schema.json`, `reply-response.schema.json`, `reply-receipt.schema.json` | Answering a closed question and its receipt | [[R17]] |

A schema checks shape. Signatures, digests and the order of a chain are the verifier's job
([Guide for verifiers](guides/verifier.md)).

## How they are checked

- `node schemas/check.ts` validates the objects of a real native run, every proof package kept in the repository,
  every statement in the test vectors and the personal agent's run, and requires each object in
  `schemas/invalid.json` (one per broken rule) to be rejected. With `--run <dir>` it also validates a fresh run of
  `reference/scripts/recorrido-nativo.test.ts`. CI runs both.
- The conformance validator checks every object an implementation returns against the schemas, in check **S1**,
  including the messages that reach the validator's inbox. See [Conformance](conformance.md).

## Use them

```sh title="Validate one object with any JSON Schema 2020-12 validator, for example"
npx --yes ajv-cli@5 validate --spec=draft2020 -r "schemas/0.1/common.schema.json" \
  -s schemas/0.1/vxp.schema.json -d my-vxp.json
```

Or import them by URL once the site is published: every `$ref` is relative, so a validator that resolves `$id`
loads the rest by itself.
