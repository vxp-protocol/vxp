---
title: Specification and versions
description: Where the normative text lives, how its rules are identified, and how versions work.
---

## The normative text

The [specification](/spec/) is the only normative text of VXP. Its source is `spec/spec.tpl.html` in the
repository. Current version: **draft 0.1**, revised on 23 October 2026 (repository release 0.1.0-rc.4).

| Section | What it defines |
|---|---|
| §1–§3 | What VXP is, why it exists, principles and scope |
| §4 | Architecture, interoperability rules [[I1]]–[[I5]], states [[E1]]–[[E3]] |
| §5 | Identity model [[ID1]]–[[ID3]] |
| §6 | VXP Proof: format, statement kinds, chain rules, [[P1]]–[[P8]] |
| §7 | VXP Relationship: [[R1]]–[[R17]] |
| §8 | Native profile and optional adapters |
| §9 | Operation requirements [[O1]]–[[O7]], security, privacy, errors |
| §10 | Independent verification, reading a verdict, key rotation |
| §11–§13 | Examples, conformance, versions and status |

## Stable identifiers

Every requirement has an identifier you can link to: `https://vxpprotocol.org/spec/#r6`, `#p5`, `#o6`,
`#id1`. The docs, the conformance matrix and the validator's report all use them. Section anchors such as
`#native-only` or `#key-rotation` are stable too.

The key words MUST, MUST NOT, SHOULD and MAY follow BCP 14 (RFC 2119 and RFC 8174).

## Versions

- One version, the same in three places: the trust block's `version`, the A2A extension URI
  (`https://vxpprotocol.org/ext/proof/v0.1`) and the `v` of every statement and package.
- While VXP is a 0.x draft, every new draft is treated as incompatible with the previous one. A verifier
  rejects a `v` it does not know ([[versioning|§13 versioning]]).
- Each change to the specification is recorded in the [changelog](changelog.md).

## Changing it

A normative change cites the identifiers it touches and comes with a test or a vector. See `CONTRIBUTING.md`.
