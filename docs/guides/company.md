---
title: Guide for companies
description: How to make a company's existing systems speak VXP with the native profile, step by step, and how to prove it.
---

This guide adds the company side of VXP to systems you already run: an order system, a booking system, a
claims queue. You do not need SOVRAS, Poppy or PACT. Each step names the rules it implements; the
[specification](/spec/) is the exact text.

## What you build

| Piece | What it does | Rules |
|---|---|---|
| Discovery | Publish `/.well-known/vxp.json` and your issuer's RFC 8414 metadata | [[native-discovery|§8 discovery]] |
| Authorization server | Clients with `private_key_jwt`, DPoP-bound tokens, device authorization with RAR | [[native-authorization|§8 authorization]], [[ID1]]–[[ID3]] |
| The `/v1` endpoints | Requests, proposals, acceptance, cancellation, events, proof | [[native-endpoints|§8 endpoints]] |
| Your controls | The operation requirements, enforced in front of your systems | [[O1]]–[[O7]] |
| VXP Proof issuer | Sign the chain, publish your keys, keep them persistent | [[proof|§6]], [[key-rotation|§10 keys]] |
| VXP Relationship (optional) | Agreements, signed outbound requests, answers | [[relationship|§7]] |

The reference implementation in `reference/` is one complete example, with every piece above. It is
reference code, not a product: copy what helps you, and keep your own systems as the source of truth.

## 1. Decide what you offer

List the operations an external agent may ask for. For each one, write down:
- what it reads or changes;
- whether a person must approve each revision;
- what you can read back afterwards to confirm it happened.

An operation you cannot read back can never be declared `succeeded` ([[P6]]). Publish only those
operations in `vxp.json` `capabilities`, each with `access` (`public` or `delegated`) and `admission`
(`static` or `dynamic`).

## 2. Publish discovery

Serve `vxp.json` on your own domain. The `issuer` it names must serve RFC 8414 metadata with an identical
`issuer`. Put the proof trust members (`vxp_proof`: your key set, the operator's, the log and the custody)
**only** in that metadata, and list your discovery domain in `vxp_proof.domains`. A verifier anchors your
keys there, never in a document handed over with a package ([[issuer-anchoring|§10 anchoring]]).

## 3. Identify agents and link accounts

- Accept clients identified by a Client ID Metadata Document. Authenticate them with `private_key_jwt`, and
  issue DPoP-bound tokens.
- Link a customer account to an agent only through an authentication you control, for example a one-time
  code over a channel you already have for that customer, and keep the evidence. Never link by a matching
  name, email or phone number ([[ID1]]). An identifier shared by two accounts links neither ([[ID2]]).
- The owner of an operation is `(profile, client_id, sub, account)`. Nobody else sees it ([[ID3]], [[O1]]).

## 4. Hold requests until there is authority

When an agent asks without authority, answer `202 authorization_required` with exactly the
`authorization_details` that are missing ([[O2]]). Your consent screen shows each item in business
language, and the person approves on your page ([[R3]]). Re-evaluate the waiting request when the agent
repeats it with the same `Idempotency-Key` ([[native-idempotency|§8 idempotency]]).

## 5. Propose exact terms

Turn the request into a revision with exact terms, a fresh `vxp_salt`, an expiry and a commitment:
- `firm`, when only your systems are involved;
- `conditional`, listing what depends on a third party ([[commitment|§8 commitment]]).

Sign it into the proof ([[P1]], [[O4]]). A change of terms is a new revision. Accepting an older one gets
`409 terms_changed`.

## 6. Execute once, then read back

On acceptance:
1. Re-check authority, the policy and the precondition.
2. Execute each accepted revision **once**; if competing requests for the same resource arrive by several paths, only the
   first that passes the precondition takes effect ([[O6]], [[I2]]).
3. Read your system back.
4. Only if what you read matches the terms, sign `succeeded` ([[O7]]).

If you cannot tell whether it happened, sign `unknown` and correct it later ([[P3]], [[P4]]). If what you read
contradicts the terms, sign that, keep `unknown` and send it to a person ([[P5]]). When your rule requires it,
a person at the company decides on the same digest before execution ([[O5]]).

## 7. Keep your keys

Generate proof keys once and keep them; publish earlier public keys after a rotation; never reuse a
retired key ([[key-rotation|§10 key rotation]]). Losing a private key only stops new signatures. Losing a public
key that nobody saved while it was published leaves the proofs it signed impossible to check.

## 8. Optionally, a relationship

If you want to reach agents later, publish `vxp_relationship` (its own key set and your
`company_initiated_actions`), accept the relationship RAR in the same consent, and follow [[R1]]–[[R17]]. See
[VXP Relationship](../relationship.md).

## 9. Prove it

Run the conformance validator against your deployment. It acts as a personal agent and reports every check
with the rule it tests:

```sh title="Validate your implementation"
node conformance/validate.ts my-config.json --report my-report.json
```

Then go through `conformance/CHECKLIST.md` for what no tool can see from outside. See
[Tests and conformance](../conformance.md).

## Running the reference implementation as your starting point

```sh title="The reference company, native profile only"
cd reference
VXP_ADAPTERS=none VXP_KEYS_DIR=/tmp/vxp-keys VXP_SHOW_CHANNEL=1 npm start
```

It serves three fictitious test companies on `http://localhost:3100`. The store's discovery is at
`/.well-known/vxp.json`. `VXP_SHOW_CHANNEL=1` prints to the console what the company would send through its
channel, such as the account-linking code, because that channel is simulated.
