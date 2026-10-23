# Security policy

## Reporting a vulnerability

Report security problems in the specification, the reference implementation, the verifiers, the
conformance validator or the agent tools privately, through GitHub's private vulnerability reporting:
the **Security** tab of this repository, then **Report a vulnerability**. Do not open a public issue,
pull request or discussion.

Include what you found, the affected rule (for example `P5` or `R6`) or file, and how to reproduce it.
We acknowledge reports within five working days and will agree a disclosure date with you.

## Scope and supported versions

VXP is a draft (0.1). The reference implementation, the agent tools and the validator are reference
code for testing and study, not production services: they keep operation state in memory, simulate the
company's systems, payments and channel, and expose test-only routes under `/interno/` protected by a key
printed at start-up. Report problems in them anyway: they are the code others will read and copy.

Only the latest commit on `main` is supported.

## Known limits, stated in the specification

- A proof is an attestation signed by the operator: there are no external witnesses, and in the reference
  deployment the operator holds the company's key (`single_root: operator`, `logged: false`). See §10.
- Approval in the native profile is `agent_asserted`: the operator records that the agent said the user
  approved. See P2.
- Keys generated in memory are lost when a process stops; set `VXP_KEYS_DIR` to keep them. See §10.
