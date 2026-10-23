---
title: VXP Relationship
description: The authorized agreement within which a company can start a request toward a person's agent, and how it is born, used, limited and revoked.
---

## Why it exists

Some work cannot wait for the person's agent to ask. A guest has not arrived and the hotel must decide
whether to hold the room; a delivery has to move; a suspicious order needs a yes or a no. VXP Relationship
lets the company reach the person's agent for that, and only within an agreement the person approved first.

## How it is born

The agent asks for the relationship in the same consent it asks for authority, with an
`authorization_details` entry of type `https://vxpprotocol.org/rar/relationship` ([[r1|R1]]):

```json title="authorization_details · relationship"
{ "type": "https://vxpprotocol.org/rar/relationship",
  "actions": ["despacho.proponer_cambio"],
  "identifier": "relationship",
  "limits": { "max_per_day": 2, "duration_seconds": 3600 } }
```

- The actions must be among those the company publishes in `vxp_relationship.company_initiated_actions`.
  The company caps the limits at its own maximums ([[R1]]).
- The agent declares an inbox in its Client ID Metadata Document, on the same origin as its `client_id` ([[R2]]).
- The consent screen shows the relationship in business language, with its own checkbox. Unchecked, no
  relationship is created ([[R3]]).
- On approval, the token response carries `relationships[]` and a signed agreement
  (`vxp-relationship+jwt`), with the company's relationship key anchored to its issuer ([[R4]], [[R5]]).

<!--json:relate.relationship title="The relationship, as granted"-->

## How the company uses it

Before it signs or sends anything, the company checks that ([[R6]]):
- the relationship and the delegation that created it are still in force;
- the action is in the agreement;
- the daily limit is not exceeded;
- the resource belongs to the same customer.

The message is a `vxp-company-request+jwt` delivered to the agent's inbox ([[R7]]). There are two kinds:
- **A proposal** ([[R8]]): it creates a normal operation, with terms signed by the company and its own
  VXP Proof chain. Proposing never executes. The agent accepts with the person's approval, and the company
  checks the relationship again at that moment ([[R9]]).
- **A closed question** ([[R17]]): for example «hold or release the booking». The agent answers once, with
  one of the options, before it expires, and gets a signed receipt (`vxp-reply-receipt+jwt`).

<!--json:relate.outbox title="A company-initiated request, as delivered"-->

## Limits and revocation

- The person, the company or the agent can revoke. Revoking the delegation revokes the relationship. Once it
  is revoked or expired, nothing goes through ([[R10]]).
- The agent reads or revokes its relationship with `GET` and `DELETE /v1/relationships/{id}` ([[R11]]). A
  late answer to a question does not count after revocation.
- The relationship never replaces the company's authorization: inside an agreement, each request still
  passes the company's own rules and the operation requirements ([[O1]]–[[O7]]).

## Agents without an inbox

An agent that only speaks Poppy and has no HTTP inbox can still hold a relationship. It is asked for,
received and answered inside its Poppy conversation, without changing the Poppy contract ([[R12]]–[[R16]]).
See [Interoperability](guides/interoperability.md).

## Status

Experimental. The HTTP inbox has been tested with agents written by SOVRAS. The relationship over a Poppy
conversation was used once by a live agent, on 21 October 2026. No third-party agent exposes an inbox yet.
