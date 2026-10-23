# AGENTS.md

This repository is the VXP protocol: the specification, the documentation, a reference company
implementation, personal-agent tools, three verifiers, test vectors and a conformance validator.

## If you are integrating another codebase

- **Making a company speak VXP:** follow `docs/guides/company.md`. The rules are in
  `spec/spec.tpl.html` (published at https://vxpprotocol.org/spec/). Prove your implementation with
  `node conformance/validate.ts <config>` (see `conformance/README.md`), then go through
  `conformance/CHECKLIST.md`.
- **Making a personal agent speak VXP:** follow `docs/guides/agent.md` and use the library in `agent/`
  (import or copy it). It has no dependencies.
- **Verifying a proof someone gave you:** `docs/guides/verifier.md`; the verifiers are in `verifier/`.
- **Exact rules and wire formats:** `spec/spec.tpl.html` is the only normative text. The guides restate it
  and link to its rule identifiers (`#r6`, `#p5`, `#o6`).

## If you are changing this repository

- Requirements: Node.js 22.18+ and Python 3 with `cryptography`. No npm dependencies anywhere.
- Checks: `cd reference && npm test && npm run test:network`, `node conformance/reference/run.ts`,
  `cd agent && npm test`, and the verifier and vector commands in `README.md`.
- Changing normative text: edit `spec/spec.tpl.html` and rebuild with `python spec/build.py`. In the same
  change, update the guides that restate it, add or adjust a test or vector, and regenerate
  `conformance/MATRIX.md` with `node conformance/matrix.ts`.
- Documentation lives in `docs/` and is built into `site/docs/` with `node docs/build.ts`. Never edit
  generated files under `site/docs/` or `site/spec/` by hand.
- The Capability Gate is SOVRAS's internal mechanism. Do not describe it as part of VXP.
