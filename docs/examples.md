---
title: Examples and messages
description: One complete operation with every message, as the reference implementation produced it in a native-only run, and where to find more.
---

Every object on this page was captured from the reference implementation running as a native-only gateway
(no Poppy, no PACT) with persistent keys, against a fictitious test store, in the evening run of 22 October
2026. Hosts are shown as `store.example` and `agent.example`, and long tokens are shortened. The signed
files, their public material and every HTTP exchange of that run are in the site's downloads
(`native-run-2026-10-22-evening/`). You can reproduce the run with `reference/scripts/recorrido-nativo.test.ts`.

## 1. Discovery

<!--json:discover.response title="GET /.well-known/vxp.json"-->

## 2. Session

<!--json:identify.form title="POST {issuer}/oauth/token · form fields"-->
<!--json:identify.response title="Token response · session"-->

## 3. Asking without authority

<!--json:authority.body title="POST /v1/requests · body (Idempotency-Key set)"-->
<!--json:authority.response title="202 authorization_required"-->

The person approved on the store's page; the device authorization asked for exactly this, plus a
relationship:

<!--json:authority.device title="Device authorization · authorization_details"-->
<!--json:authority.token title="Token response after approval"-->

## 4. The same request, re-evaluated

<!--json:context.response title="POST /v1/requests (same Idempotency-Key) · 201"-->

## 5. The proposal and its acceptance

<!--json:operate.proposal title="Proposal, revision 1"-->
<!--json:operate.body title="POST /v1/proposals/{id}/accept · body"-->

## 6. The result and its proof

<!--json:prove.response title="Result"-->
<!--json:prove.chain title="The chain (payload bodies)"-->
<!--json:prove.verdict title="Verdict of the independent verifier"-->

## 7. The relationship

<!--json:relate.relationship title="Relationship, as granted"-->
<!--json:relate.outbox title="The company starts a request: delivered to the agent's inbox"-->
<!--json:relate.accepted title="The agent accepts the company's proposal"-->

## More examples

- **Failures, on purpose:** the conformance validator's run against the reference shows each refusal it
  checks: a missing `Idempotency-Key`, a reused key, `terms_changed`, a tampered outcome, an answer outside
  the options, a second answer, and a request after revocation (`node conformance/reference/run.ts`).
- **Tampered proofs:** the [Verify](/verify/) page alters a published proof in five ways and shows each
  rejection.
- **Test vectors:** `vectors/vectores-0.1.json` holds valid chains and negative cases, each with the verdict
  and error a conforming verifier must return.
- **Operations with live agents** (21 October 2026) are described on the [Examples](/examples/) page, with
  what can and cannot be verified about each.
