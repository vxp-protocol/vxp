# Changelog

> Every notable change to the specification and the repository, by version.

All notable changes to the VXP specification and to this repository. Draft versions are incompatible
with each other until 1.0.

## 0.1.0-rc.3 · 23 October 2026

### Repository
- `agent/`: a URL a company gives is accepted only in canonical form, so no server can resolve it differently
  from the agent; under PACT, the interface that receives the delegation must be on the authorization server's
  origin. Tests in `agent/test/untrusted-ids.test.ts`.

## 0.1.0-rc.2 · 23 October 2026

### Specification
- Two public components, VXP Proof and VXP Relationship. Operation requirements O1–O7 replace the
  earlier presentation of a third component; the rules themselves did not change.
- Native-only gateway (§8): a company can implement VXP with the native profile alone.
- Implementation paths (§8): only the well-known locations and the native endpoints are fixed; key sets,
  log and proof bundle are discovered through the issuer metadata.
- Reading a verdict, key rotation and historical verification (§10).
- WhatsApp no longer named in normative rules: «a channel the company has linked to the customer».
- Native endpoints (§8): read capabilities answer at once with `{operation, effect: "read", result}` and
  create no request; `approved_by` is `user`, or `standing_permission` only for a revision with
  `user_approval_required: false` (otherwise `403 user_approval_required`); `user_approval` statements may
  carry `basis: "standing_permission"`.
- JSON Schemas (§12, informative) for every object of the draft.

### Repository
- `docs/`: documentation in Markdown, built into the site, with `llms.txt`; a page of failures with the test
  that covers each one.
- `schemas/0.1/`: JSON Schemas (2020-12), published at `vxpprotocol.org/schemas/0.1/`; `schemas/check.ts`
  validates real runs, proof packages, vectors and the agent's run against them and requires a set of invalid
  objects to be rejected; the conformance validator checks every object an implementation returns (S1).
- `conformance/`: a validator that acts as an agent against any native-profile implementation and
  reports every check with its rule; a conformance matrix and a checklist of what only a person can check.
- `agent/`: client library, CLI, MCP server and example personal agent; optional Poppy draft 0.2 and PACT 1.0
  adapters in the library, which the native profile does not import.
- `reference/`: optional adapters (`VXP_ADAPTERS=none`), persistent and rotating proof keys
  (`VXP_KEYS_DIR`), proof material under `/vxp/` (`/sovras/` kept as an alias), the simulated company
  channel printed to the console (`VXP_SHOW_CHANNEL=1`).
- `reference/`, company side for a personal agent: public reads in the native profile (`effect: "read"`,
  `access: "public" | "delegated"` in `vxp.json`), a cap the person approves beforehand
  (`user_approval_required: false` and `approved_by: "standing_permission"` within it), the hotel's
  late-arrival question started by the company every minute, and a relationship key that persists with
  `VXP_KEYS_DIR`.
- Network tests no longer block the event loop while the Python verifier runs (an idle keep-alive socket
  closed meanwhile caused `ECONNRESET`).
- `site/`: the home page starts from the work inside companies; Proof and Relationship have their own
  interactive views; Docs and Demos in every page; the native walkthrough states that the code linked the
  account and granted authority, while the terms were `agent_asserted`.
- Vectors use `*.example` hosts. Continuous integration runs the suites on every push.

## 0.1.0-rc.1 · 22 October 2026

First complete draft: specification, reference implementation with the native profile and the Poppy
draft 0.2 and PACT 1.0 adapters, three verifiers (two in Python, one in JavaScript for the browser),
test vectors, and the site.
