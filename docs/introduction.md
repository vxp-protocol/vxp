---
title: Introduction
description: What VXP is, the work it comes from, its two public components, and what it does not do.
---

## The work it comes from

Every day, companies take bookings, sell, change deliveries, handle claims and answer incidents in their
own systems. More and more of those requests come from a person's own agent: an assistant the company did
not build and whose conversation it cannot see. After each operation the same questions come back:

1. Who asked, and on whose behalf?
2. Which exact terms did the person approve, and how?
3. What ran, and how many times?
4. What did the company's system record afterwards?

And sometimes the company needs to come back to the agent: the guest has not arrived, the order needs a
decision, the delivery date has to move. It may only do so within something the person authorized.

VXP writes the answers to those questions into contracts that any company and any agent can implement.

## Two public components

| Component | What it gives you |
|---|---|
| [VXP Proof](proof.md) | Signed evidence that anyone can verify. By digest it binds the request, the exact terms of each revision, the approval given on them, the single execution, the later read of the company's system, the declared outcome and any correction. See [[proof|specification §6]]. |
| [VXP Relationship](relationship.md) | An authorized agreement between a personal agent and a company: the actions allowed in each direction, limits, validity and revocation. Within it, the company can start a request toward the agent, and the agent answers. See [[relationship|specification §7]]. |

VXP also states seven **operation requirements**, [[O1]] to [[O7]], that every implementation meets where an
external request becomes an operation on a company's system. Among them: execute only the exact revision
that was approved, execute it once, and declare success only after reading the system back. They are
requirements, not a third component: VXP defines no interface for them, VXP Proof is how anyone can check
them afterwards, and how an implementation enforces them internally is its own decision. See
[[operation-requirements|specification §9]].

## How the parts fit

```text title="The parts"
Personal agent ──► discovery (vxp.json) ──► identity (private_key_jwt + DPoP)
                ──► authority for this request (RFC 8628 + RFC 9396)
                ──► request ──► proposal with exact terms ──► acceptance
Company system  ◄── one execution ──► read of the system ──► outcome
                         │
                VXP Proof: the signed chain of all of the above
                VXP Relationship: the agreement within which the company can start the next request
```

The **native profile** is VXP's own way to carry all of this: `/.well-known/vxp.json` and a small set of
`/v1` endpoints. It is experimental and works on its own. A company may also offer the **optional
adapters** for Poppy draft 0.2 and PACT 1.0, for agents that already speak those protocols. See
[Native profile](native-profile.md) and [Interoperability](guides/interoperability.md).

## Three parties, kept apart

| Party | In VXP |
|---|---|
| The person | Approves authority, terms and agreements, through the company's own pages and channel. |
| The personal agent | Identifies itself with its own key, asks, negotiates, accepts within what the person approved, keeps the evidence, and answers the company inside an agreement. |
| The company | Publishes what it offers, signs its exact terms, executes once, reads its own system, signs the result, and starts requests only within an agreement. |

An **operator** may run the company's VXP endpoints for it. The evidence names who signed each link, so a
verifier knows whether it is reading the company's word or the operator's ([[P7]]).

## What VXP does not do

- It does not build the personal agent, and it does not connect an agent to every company. Both sides need
  a compatible implementation and a system that can carry out what is offered.
- It does not require SOVRAS, Poppy or PACT. Anyone can implement it from the specification.
- It does not define payments, disputes or the person's civil identity.
- A valid proof does not by itself prove that what the company asserts is true: it proves who asserted
  what, over which exact terms and in which order, with its root of trust named ([[P7]],
  [[reading-a-verdict|§10, reading a verdict]]).

This is the behaviour the standard targets. Today no commercial personal agent supports VXP natively, and
the native profile is experimental.

## Status

Draft 0.1. The specification, the reference implementation, the verifiers, the vectors, the conformance
validator and the agent tools are published together, under Apache 2.0. See [Changelog](changelog.md).
