# JSON Schemas

> JSON Schemas (2020-12) for every object of VXP 0.1, published under vxpprotocol.org/schemas/0.1/, checked against the reference implementation and usable to validate your own.

The schemas restate the specification as JSON Schema 2020-12, so a company or an agent can check its objects
mechanically. Where a schema and the [specification](https://vxpprotocol.org/spec/) differ, the specification governs. They are
versioned with the protocol: `https://vxpprotocol.org/schemas/0.1/<name>.schema.json`, each with that URL as its
`$id`. `common.schema.json` holds the shared definitions (digests, states, authorization details, commitment).

## The schemas

| Schema | Object | Rules |
|---|---|---|
| `vxp.schema.json` | `GET /.well-known/vxp.json` | [native-discovery](https://vxpprotocol.org/spec/#native-discovery) |
| `issuer-metadata.schema.json` | `vxp_proof` and `vxp_relationship` in the issuer's RFC 8414 metadata | [issuer-anchoring](https://vxpprotocol.org/spec/#issuer-anchoring), [R1](https://vxpprotocol.org/spec/#r1), [R5](https://vxpprotocol.org/spec/#r5) |
| `client-metadata.schema.json` | The agent's Client ID Metadata Document, with its inbox | [native-authorization](https://vxpprotocol.org/spec/#native-authorization), [R2](https://vxpprotocol.org/spec/#r2) |
| `token-response.schema.json` | The token response: `authorization_details` granted and `relationships[]` | [native-authorization](https://vxpprotocol.org/spec/#native-authorization), [R4](https://vxpprotocol.org/spec/#r4) |
| `request-body.schema.json` | `POST {endpoint}/requests` body | [native-endpoints](https://vxpprotocol.org/spec/#native-endpoints) |
| `request.schema.json` | A request: state, projections, missing authority, proposal, effects, result | [native-endpoints](https://vxpprotocol.org/spec/#native-endpoints), [O2](https://vxpprotocol.org/spec/#o2), [O4](https://vxpprotocol.org/spec/#o4) |
| `read-response.schema.json` | The answer to a read capability | [native-endpoints](https://vxpprotocol.org/spec/#native-endpoints) |
| `accept-body.schema.json`, `counter-body.schema.json` | Accept and counter-proposal bodies | [native-endpoints](https://vxpprotocol.org/spec/#native-endpoints) |
| `events.schema.json` | `GET {endpoint}/requests/{id}/events` | [native-endpoints](https://vxpprotocol.org/spec/#native-endpoints), [E1](https://vxpprotocol.org/spec/#e1) |
| `error.schema.json` | An error answer | [errors](https://vxpprotocol.org/spec/#errors) |
| `proof-package.schema.json` | `GET {endpoint}/requests/{id}/proof` | [proof](https://vxpprotocol.org/spec/#proof) |
| `statement-header.schema.json`, `statement.schema.json` | Each statement's header, and its payload by kind | [proof](https://vxpprotocol.org/spec/#proof), [P1](https://vxpprotocol.org/spec/#p1)–[P6](https://vxpprotocol.org/spec/#p6) |
| `checkpoint.schema.json` | The log checkpoint | [issuer-anchoring](https://vxpprotocol.org/spec/#issuer-anchoring) |
| `relationship.schema.json`, `relationship-agreement.schema.json` | A relationship and its signed agreement | [R4](https://vxpprotocol.org/spec/#r4), [R10](https://vxpprotocol.org/spec/#r10), [R11](https://vxpprotocol.org/spec/#r11) |
| `company-request.schema.json`, `inbox-delivery.schema.json` | A company-initiated request and its delivery | [R7](https://vxpprotocol.org/spec/#r7), [R8](https://vxpprotocol.org/spec/#r8) |
| `reply-body.schema.json`, `reply-response.schema.json`, `reply-receipt.schema.json` | Answering a closed question and its receipt | [R17](https://vxpprotocol.org/spec/#r17) |

A schema checks shape. Signatures, digests and the order of a chain are the verifier's job
([Guide for verifiers](https://vxpprotocol.org/docs/guides/verifier/)).

## How they are checked

- `node schemas/check.ts` validates the objects of a real native run, every proof package kept in the repository,
  every statement in the test vectors and the personal agent's run, and requires each object in
  `schemas/invalid.json` (one per broken rule) to be rejected. With `--run <dir>` it also validates a fresh run of
  `reference/scripts/recorrido-nativo.test.ts`. CI runs both.
- The conformance validator checks every object an implementation returns against the schemas, in check **S1**,
  including the messages that reach the validator's inbox. See [Conformance](https://vxpprotocol.org/docs/conformance/).

## Use them

```sh title="Validate one object with any JSON Schema 2020-12 validator, for example"
npx --yes ajv-cli@5 validate --spec=draft2020 -r "schemas/0.1/common.schema.json" \
  -s schemas/0.1/vxp.schema.json -d my-vxp.json
```

Or import them by URL once the site is published: every `$ref` is relative, so a validator that resolves `$id`
loads the rest by itself.
