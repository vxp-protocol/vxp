# Changelog

All notable changes to the VXP specification and to this repository. Draft versions are incompatible
with each other until 1.0.

## 0.1.0-rc.4 · 23 October 2026

Editorial review of the site, the documentation and the specification against the code. No rule changes
what an implementation that passed rc.3 does.

### Specification
- I2 and O6 state the scope of “one execution”: each accepted revision executes at most once, and of several
  operations competing for one resource only the first that passes the precondition takes effect. A later
  request on the same resource is a new operation.
- `resource` (RFC 8707) goes in the native profile's device authorization and token requests, and is how an
  authorization server shared with the Poppy adapter tells the two apart.
- Approving a revision needs no grant of its own: the sentence about a `vxpprotocol.org/operation` grant
  type, which no implementation had, is removed.
- Relationship over a Poppy conversation: the `relationship` and `reply_error` messages, and that accepting a
  change the company proposes (R8) uses the native profile.
- Errors: the codes a native client meets (`customer_not_linked`, `not_authorized`, `sign_in_required`,
  `invalid_target`), `404 request_not_found` on `/v1/requests/{id}/proof`.
- Key rotation: what losing a key means, and how a verdict states that it used saved material.
- Conformance by role: an issuer that offers VXP Relationship meets R1 to R17.
- The design draft that VXP Proof comes from is named as unpublished; prior art cites the Internet-Drafts
  by name.

### Repository
- `verifier/`: `key_source` is `issuer_metadata_saved` when the keys come from saved material, and
  `issuer_metadata_live` when they are fetched for the check.
- `site/` and `docs/`: wording, dates and status brought up to date; the Quickstart runs as written;
  Demos in the menu; adding a demo is described in CONTRIBUTING.md.

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
