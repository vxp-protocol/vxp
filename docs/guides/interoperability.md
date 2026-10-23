---
title: Interoperability with Poppy and PACT
description: The optional adapters that let agents already speaking Poppy draft 0.2 or PACT 1.0 work with a VXP company, and what each one carries.
---

VXP works on its own with the native profile. A company **may** also offer adapters for agents that already
speak another protocol. Adapters are optional and never required to implement VXP ([[native-only|§8 native-only]]).

## The rule for every adapter

An adapter speaks the other protocol exactly as written: its discovery, authorization, operations,
states and errors. VXP adds only what fits in that protocol's extension points, and none of its own items
leak into the other protocol's catalog ([[I1]], [[I4]], [[I5]]). Whatever the entry, of several operations
competing for one resource only the first that passes the precondition takes effect ([[I2]]).

## Poppy draft 0.2 (with Operations v1)

| | |
|---|---|
| Discovery and identity | `poppy.json`, Poppy sign-in, sessions and conversations, as Poppy defines them |
| Operations | Poppy's Operations extension v1: revisions, confirmation, single execution |
| What VXP adds | The extension `vxpprotocol.org/proof` in `poppy.json` and in the agent's client metadata; a domain-named member in each operation with effect, only for an agent that lists the extension |
| VXP Relationship | Over the Poppy conversation, for agents without an inbox ([[R12]]–[[R16]]); experimental, company side only. Accepting a change the company proposes ([[R8]]) uses the native profile |

## PACT 1.0 over A2A 1.0.1

| | |
|---|---|
| Discovery and identity | The Agent Card, PACT agent identity and delegated authority, as PACT defines them |
| What VXP adds | `capabilities.extensions[]` with `https://vxpprotocol.org/ext/proof/v0.1` (`required: false`), and the proof in `message.metadata` next to `pact.receipt`, which is not touched |
| VXP Relationship | Not specified yet |

## The agent side

The personal agent in `agent/` speaks both adapters as written, as a library: `PoppyAdapter` (discovery by
`poppy.json`, Device Sign-In, the conversation and Operations `confirm`) and `PactAdapter` (the Agent Card,
the personal-agent JWT, delegated authority and `message:send`). Each verifies the VXP proof with its own anchor:
the Poppy domain, or the PACT authorization server with the PACT receipt cross-checked. They are tested against
the reference with `VXP_ADAPTERS=poppy` and `VXP_ADAPTERS=pact`, and a test checks that the native modules
import neither (`agent/test/native-only.test.ts`). VXP Relationship over a Poppy conversation ([[R12]]–[[R16]])
is implemented by the company side only.

## States across protocols

One internal state model, projected onto each protocol's own enum ([[E1]], [[E2]], [[state-projection|§4 projection]]):
Poppy sees `proposed`, `in_progress`, `succeeded`… and A2A sees `TASK_STATE_*`. A value outside a protocol's
enum is never used.

## How the adapters are tested

- **Official tools of those protocols, unchanged.** The Poppy validator (draft 0.2 kit) covers discovery and
  conversations, and skips sign-in and Operations, so passing it is not full Poppy conformance. The PACT
  Identity suite covers identity.
- **Tests written by SOVRAS** for the delegated PACT flow (with the official PACT client) and for Operations.
  They are not the official suites.

See [Tests and conformance](../conformance.md).

## Running the reference with or without adapters

```sh title="Adapters on (default) or off"
cd reference
npm start                         # native profile + Poppy + PACT
VXP_ADAPTERS=none npm start       # native profile only
VXP_ADAPTERS=poppy npm start      # native profile + Poppy
```
