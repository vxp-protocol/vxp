# Guide for companies

> How to make a company's existing systems speak VXP with the native profile, step by step, and how to prove it.

This guide adds the company side of VXP to systems you already run: an order system, a booking system, a
claims queue. You do not need SOVRAS, Poppy or PACT. Each step names the rules it implements; the
[specification](https://vxpprotocol.org/spec/) is the exact text.

## What you build

| Piece | What it does | Rules |
|---|---|---|
| Discovery | Publish `/.well-known/vxp.json` and your issuer's RFC 8414 metadata | [§8 discovery](https://vxpprotocol.org/spec/#native-discovery) |
| Authorization server | Clients with `private_key_jwt`, DPoP-bound tokens, device authorization with RAR | [§8 authorization](https://vxpprotocol.org/spec/#native-authorization), [ID1](https://vxpprotocol.org/spec/#id1)–[ID3](https://vxpprotocol.org/spec/#id3) |
| The `/v1` endpoints | Requests, proposals, acceptance, cancellation, events, proof | [§8 endpoints](https://vxpprotocol.org/spec/#native-endpoints) |
| Your controls | The operation requirements, enforced in front of your systems | [O1](https://vxpprotocol.org/spec/#o1)–[O7](https://vxpprotocol.org/spec/#o7) |
| VXP Proof issuer | Sign the chain, publish your keys, keep them persistent | [§6](https://vxpprotocol.org/spec/#proof), [§10 keys](https://vxpprotocol.org/spec/#key-rotation) |
| VXP Relationship (optional) | Agreements, signed outbound requests, answers | [§7](https://vxpprotocol.org/spec/#relationship) |

The reference implementation in `reference/` is one complete example, with every piece above. It is
reference code, not a product: copy what helps you, and keep your own systems as the source of truth.

## 1. Decide what you offer

List the operations an external agent may ask for. For each one, write down:
- what it reads or changes;
- whether a person must approve each revision;
- what you can read back afterwards to confirm it happened.

An operation you cannot read back can never be declared `succeeded` ([P6](https://vxpprotocol.org/spec/#p6)). Publish only those
operations in `vxp.json` `capabilities`, each with `access` (`public` or `delegated`) and `admission`
(`static` or `dynamic`).

## 2. Publish discovery

Serve `vxp.json` on your own domain. The `issuer` it names must serve RFC 8414 metadata with an identical
`issuer`. Put the proof trust members (`vxp_proof`: your key set, the operator's, the log and the custody)
**only** in that metadata, and list your discovery domain in `vxp_proof.domains`. A verifier anchors your
keys there, never in a document handed over with a package ([§10 anchoring](https://vxpprotocol.org/spec/#issuer-anchoring)).

## 3. Identify agents and link accounts

- Accept clients identified by a Client ID Metadata Document. Authenticate them with `private_key_jwt`, and
  issue DPoP-bound tokens.
- Link a customer account to an agent only through an authentication you control, for example a one-time
  code over a channel you already have for that customer, and keep the evidence. Never link by a matching
  name, email or phone number ([ID1](https://vxpprotocol.org/spec/#id1)). An identifier shared by two accounts links neither ([ID2](https://vxpprotocol.org/spec/#id2)).
- The owner of an operation is `(profile, client_id, sub, account)`. Nobody else sees it ([ID3](https://vxpprotocol.org/spec/#id3), [O1](https://vxpprotocol.org/spec/#o1)).

## 4. Hold requests until there is authority

When an agent asks without authority, answer `202 authorization_required` with exactly the
`authorization_details` that are missing ([O2](https://vxpprotocol.org/spec/#o2)). Your consent screen shows each item in business
language, and the person approves on your page ([R3](https://vxpprotocol.org/spec/#r3)). Re-evaluate the waiting request when the agent
repeats it with the same `Idempotency-Key` ([§8 idempotency](https://vxpprotocol.org/spec/#native-idempotency)).

## 5. Propose exact terms

Turn the request into a revision with exact terms, a fresh `vxp_salt`, an expiry and a commitment:
- `firm`, when only your systems are involved;
- `conditional`, listing what depends on a third party ([§8 commitment](https://vxpprotocol.org/spec/#commitment)).

Sign it into the proof ([P1](https://vxpprotocol.org/spec/#p1), [O4](https://vxpprotocol.org/spec/#o4)). A change of terms is a new revision. Accepting an older one gets
`409 terms_changed`.

## 6. Execute once, then read back

On acceptance:
1. Re-check authority, the policy and the precondition.
2. Execute **once** per resource, even if the same request arrives by several paths ([O6](https://vxpprotocol.org/spec/#o6), [I2](https://vxpprotocol.org/spec/#i2)).
3. Read your system back.
4. Only if what you read matches the terms, sign `succeeded` ([O7](https://vxpprotocol.org/spec/#o7)).

If you cannot tell whether it happened, sign `unknown` and correct it later ([P3](https://vxpprotocol.org/spec/#p3), [P4](https://vxpprotocol.org/spec/#p4)). If what you read
contradicts the terms, sign that, keep `unknown` and send it to a person ([P5](https://vxpprotocol.org/spec/#p5)). When your rule requires it,
a person at the company decides on the same digest before execution ([O5](https://vxpprotocol.org/spec/#o5)).

## 7. Keep your keys

Generate proof keys once and keep them; publish earlier public keys after a rotation; never reuse a
retired key ([§10 key rotation](https://vxpprotocol.org/spec/#key-rotation)). Proofs signed with keys you lose can no longer be checked by
anyone.

## 8. Optionally, a relationship

If you want to reach agents later, publish `vxp_relationship` (its own key set and your
`company_initiated_actions`), accept the relationship RAR in the same consent, and follow [R1](https://vxpprotocol.org/spec/#r1)–[R17](https://vxpprotocol.org/spec/#r17). See
[VXP Relationship](https://vxpprotocol.org/docs/relationship/).

## 9. Prove it

Run the conformance validator against your deployment. It acts as a personal agent and reports every check
with the rule it tests:

```sh title="Validate your implementation"
node conformance/validate.ts my-config.json --report my-report.json
```

Then go through `conformance/CHECKLIST.md` for what no tool can see from outside. See
[Tests and conformance](https://vxpprotocol.org/docs/conformance/).

## Running the reference implementation as your starting point

```sh title="The reference company, native profile only"
cd reference
VXP_ADAPTERS=none VXP_KEYS_DIR=./.keys VXP_SHOW_CHANNEL=1 npm start
```

It serves three fictitious test companies on `http://localhost:3100`. The store's discovery is at
`/.well-known/vxp.json`. `VXP_SHOW_CHANNEL=1` prints to the console what the company would send through its
channel, such as the account-linking code, because that channel is simulated.
